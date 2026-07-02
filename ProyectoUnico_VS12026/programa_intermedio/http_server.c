/*
 * http_server.c - Servidor HTTP del daemon EDR Híbrido
 * 
 * Este módulo implementa un servidor HTTP básico desde cero usando sockets.
 * Se encarga de recibir las peticiones del frontend (dashboard web)
 * y responder con los datos apropiados en formato JSON.
 * 
 * RUTAS DISPONIBLES (API REST):
 * 
 *   GET  /api/metrics        → Métricas del sistema (memoria, swap, page faults)
 *   GET  /api/login           → Autenticación de usuarios con PAM
 *   GET  /api/processes       → Lista paginada de procesos del sistema
 *   GET  /api/top_processes   → Top 20 procesos por consumo de memoria
 *   GET  /api/process_info    → Información de un proceso por PID (syscall 464)
 *   GET  /api/alerts          → Lista de alertas de seguridad
 *   GET  /api/files           → Lista de archivos escaneados
 *   GET  /api/kill            → Matar un proceso por PID
 *   GET  /api/quarantine      → Poner un archivo en cuarentena (chmod 0000)
 *   GET  /api/quarantine_list → Lista de archivos en cuarentena
 *   GET  /api/toggle_scan     → Activar/desactivar escaneo de archivos
 *   GET  /api/toggle_metrics  → Activar/desactivar monitoreo de métricas
 *   GET  /api/status          → Estado actual de los toggles
 *   POST /api/update_blacklist→ Actualizar la base de datos de hashes malignos
 *   POST /api/create_user     → Crear un nuevo usuario del sistema (solo admin)
 * 
 * NOTA: Usamos CORS (Access-Control-Allow-Origin: *) para permitir
 * que el frontend (que corre en un puerto diferente) pueda hacer
 * peticiones a nuestro servidor.
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#define _GNU_SOURCE /* Necesario para strcasestr() en Linux */
#include "http_server.h"
#include "globals.h"
#include "alerts.h"
#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>        /* Para read(), write(), close() */
#include <sys/socket.h>    /* Para socket(), bind(), listen(), accept() */
#include <netinet/in.h>    /* Para struct sockaddr_in (direcciones IPv4) */
#include <arpa/inet.h>     /* Para INADDR_ANY */
#include <signal.h>        /* Para SIGKILL (señal para matar procesos) */
#include <sys/stat.h>      /* Para chmod() */
#include <sys/syscall.h>   /* Para syscall() - llamar syscalls personalizadas */

/* Header CORS que se agrega a todas las respuestas HTTP.
 * CORS es necesario porque el frontend corre en localhost:5173
 * y el backend en localhost:8080 (diferente puerto = diferente origen). */
#define RESPONSE_HEADERS "Access-Control-Allow-Origin: *\r\n"

/* ============================================================
 * FUNCIONES UTILITARIAS DE HTTP
 * ============================================================ */

/*
 * send_response - Envía una respuesta HTTP completa al cliente
 * 
 * Construye el header HTTP con el status, content-type y content-length,
 * y luego envía el body. Esto es lo que el navegador o axios recibe.
 * 
 * Ejemplo de respuesta HTTP que genera:
 *   HTTP/1.1 200 OK
 *   Content-Type: application/json
 *   Access-Control-Allow-Origin: *
 *   Content-Length: 42
 *   
 *   {"status":"success","role":"admin_user"}
 */
static void send_response(int socket, const char *status, const char *content_type, const char *body) {
    char header[512];
    snprintf(header, sizeof(header), 
             "HTTP/1.1 %s\r\n"
             "Content-Type: %s\r\n"
             RESPONSE_HEADERS
             "Content-Length: %zu\r\n"
             "\r\n", 
             status, content_type, strlen(body));
             
    write(socket, header, strlen(header)); /* Enviamos el header */
    write(socket, body, strlen(body));     /* Enviamos el body */
}

/*
 * send_long_response - Envía una respuesta HTTP con body potencialmente grande
 * 
 * Similar a send_response pero envía el body en chunks de 4KB.
 * Esto es necesario porque write() puede no enviar todo el contenido
 * de una sola vez si es muy grande (limitación del kernel/socket).
 */
static void send_long_response(int socket, const char *status, const char *content_type, const char *body, size_t body_len) {
    char header[512];
    snprintf(header, sizeof(header),
             "HTTP/1.1 %s\r\n"
             "Content-Type: %s\r\n"
             RESPONSE_HEADERS
             "Content-Length: %zu\r\n"
             "\r\n",
             status, content_type, body_len);
    write(socket, header, strlen(header));

    /* Enviamos el body en bloques de 4KB para mayor confiabilidad */
    size_t sent = 0;
    while (sent < body_len) {
        size_t chunk = body_len - sent;
        if (chunk > 4096) chunk = 4096;
        ssize_t w = write(socket, body + sent, chunk);
        if (w <= 0) break; /* Error o conexión cerrada */
        sent += w;
    }
}

/*
 * cmp_process_by_memory_desc - Comparador para ordenar procesos
 * 
 * Se usa con qsort() para ordenar procesos de mayor a menor
 * consumo de memoria. qsort() es la implementación de QuickSort
 * de la librería estándar de C.
 */
static int cmp_process_by_memory_desc(const void *a, const void *b) {
    const struct process_info *pa = (const struct process_info *)a;
    const struct process_info *pb = (const struct process_info *)b;
    if (pb->memory_usage > pa->memory_usage) return 1;
    if (pb->memory_usage < pa->memory_usage) return -1;
    return 0;
}

/* ============================================================
 * HANDLERS DE RUTAS HTTP
 * Cada función maneja una ruta específica del API.
 * ============================================================ */

/*
 * GET /api/metrics
 * Retorna las métricas actuales del sistema en formato JSON.
 * Los datos los genera el hilo de monitoreo (metrics.c).
 */
static void handle_metrics_route(int socket) {
    char body[16384];
    /* Leemos el JSON de métricas con mutex (otro hilo podría estar escribiéndolo) */
    pthread_mutex_lock(&metrics_mutex);
    strncpy(body, global_metrics_json, sizeof(body)-1);
    body[sizeof(body)-1] = '\0';
    pthread_mutex_unlock(&metrics_mutex);
    
    send_response(socket, "200 OK", "application/json", body);
}

/*
 * GET /api/login?user=X&pass=Y
 * Autentica al usuario contra PAM y retorna su rol.
 * 
 * Flujo:
 *   1. Extraemos user y pass de los query params
 *   2. Llamamos a authenticate_user() (usa PAM)
 *   3. Si es válido, obtenemos su rol con get_user_role()
 *   4. Retornamos el rol: admin_user, common_user, o error
 */
static void handle_login_route(int socket, const char *request) {
    char user[50] = {0};
    char pass[50] = {0};
    
    /* 
     * sscanf() extrae los valores de user y pass del query string.
     * %49[^&] = lee hasta 49 caracteres que NO sean '&'
     * %49[^ ] = lee hasta 49 caracteres que NO sean espacio
     */
    if (sscanf(request, "GET /api/login?user=%49[^&]&pass=%49[^ ]", user, pass) == 2) {
        /* Intentamos autenticar al usuario con PAM */
        if (authenticate_user(user, pass)) {
            /* Login exitoso -> generamos alerta LOW */
            add_alert("sesion", "Inicio de sesion exitoso", "LOW");
            int role = get_user_role(user);
            
            if (role == 2) {
                /* El usuario pertenece al grupo admin_user */
                send_response(socket, "200 OK", "application/json", "{\"status\":\"success\", \"role\":\"admin_user\"}");
            } else if (role == 1) {
                /* El usuario pertenece al grupo common_user */
                send_response(socket, "200 OK", "application/json", "{\"status\":\"success\", \"role\":\"common_user\"}");
            } else {
                /* El usuario existe pero no pertenece a ningún grupo válido */
                send_response(socket, "403 Forbidden", "application/json", "{\"status\":\"error\", \"message\":\"Usuario sin grupo asignado\"}");
            }
        } else {
            /* Contraseña incorrecta o usuario no existe -> alerta MEDIUM */
            add_alert("sesion", "Inicio de sesion fallido", "MEDIUM");
            send_response(socket, "401 Unauthorized", "application/json", "{\"status\":\"error\", \"message\":\"Credenciales invalidas\"}");
        }
    } else {
        /* Faltan parámetros en la URL */
        send_response(socket, "400 Bad Request", "application/json", "{\"status\":\"error\", \"message\":\"Parametros faltantes\"}");
    }
}

/*
 * GET /api/alerts
 * Retorna todas las alertas almacenadas en formato JSON.
 * Las alertas están ordenadas por las más recientes primero.
 */
static void handle_alerts_route(int socket) {
    char *alerts_str = get_alerts_json();
    if (alerts_str) {
        send_long_response(socket, "200 OK", "application/json", alerts_str, strlen(alerts_str));
        free(alerts_str); /* Liberamos la memoria que get_alerts_json() reservó */
    } else {
        send_response(socket, "500 Internal Server Error", "application/json", "[]");
    }
}

/*
 * GET /api/kill?pid=X
 * Termina (mata) un proceso del sistema usando SIGKILL.
 * 
 * SIGKILL (señal 9) es la señal más fuerte de Linux:
 * el proceso se termina inmediatamente sin oportunidad de limpieza.
 * Por eso se muestra un mensaje de confirmación en el frontend.
 */
static void handle_kill_route(int socket, const char *request) {
    int pid_to_kill;
    if (sscanf(request, "GET /api/kill?pid=%d", &pid_to_kill) == 1) {
        /* 
         * kill() es una función del sistema que envía una señal a un proceso.
         * Retorna 0 si fue exitoso, o -1 si hubo error.
         */
        if (kill(pid_to_kill, SIGKILL) == 0) {
            char desc[128];
            snprintf(desc, sizeof(desc), "Proceso %d terminado por el administrador", pid_to_kill);
            add_alert("sistema", desc, "MEDIUM");
            send_response(socket, "200 OK", "application/json", "{\"status\":\"success\"}");
        } else {
            send_response(socket, "500 Error", "application/json", "{\"status\":\"error\", \"message\":\"Fallo al matar proceso\"}");
        }
    } else {
        send_response(socket, "400 Bad Request", "application/json", "{\"status\":\"error\", \"message\":\"PID invalido\"}");
    }
}

/*
 * GET /api/quarantine?file=X
 * Pone un archivo en cuarentena cambiando sus permisos a 0000.
 * 
 * chmod 0000 revoca TODOS los permisos (lectura, escritura, ejecución)
 * para todos los usuarios, incluyendo el propietario.
 * El archivo queda completamente inaccesible hasta que un admin
 * lo restaure manualmente con chmod.
 */
static void handle_quarantine_route(int socket, const char *request) {
    char filename[256] = {0};
    if (sscanf(request, "GET /api/quarantine?file=%255[^ &]", filename) == 1) {
        /* Construimos la ruta completa al archivo */
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s%s", MONITOR_DIR, filename);
        
        /* chmod() cambia los permisos del archivo. 0000 = sin permisos */
        if (chmod(full_path, 0000) == 0) {
            /* Registramos el archivo en la lista de cuarentena */
            pthread_mutex_lock(&files_mutex);
            if (quarantined_count < MAX_QUARANTINED) {
                strncpy(quarantined_files[quarantined_count].filename, filename,
                        sizeof(quarantined_files[quarantined_count].filename) - 1);
                /* Registramos la fecha y hora de la cuarentena */
                time_t t = time(NULL);
                struct tm tm = *localtime(&t);
                snprintf(quarantined_files[quarantined_count].timestamp,
                         sizeof(quarantined_files[quarantined_count].timestamp),
                         "%d-%02d-%02d %02d:%02d:%02d",
                         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                         tm.tm_hour, tm.tm_min, tm.tm_sec);
                quarantined_count++;
            }
            pthread_mutex_unlock(&files_mutex);

            /* Generamos alerta HIGH (archivo en cuarentena es un evento crítico) */
            char desc[320];
            snprintf(desc, sizeof(desc), "Archivo '%s' puesto en cuarentena (chmod 0000)", filename);
            add_alert("archivos", desc, "HIGH");
            send_response(socket, "200 OK", "application/json", "{\"status\":\"success\"}");
        } else {
            send_response(socket, "500 Error", "application/json", "{\"status\":\"error\", \"message\":\"No se pudo cambiar permisos\"}");
        }
    } else {
        send_response(socket, "400 Bad Request", "application/json", "{\"status\":\"error\", \"message\":\"Nombre de archivo invalido\"}");
    }
}

/*
 * GET /api/quarantine_list
 * Retorna la lista de todos los archivos que están en cuarentena.
 */
static void handle_quarantine_list_route(int socket) {
    json_t *arr = json_array();

    /* Leemos la lista de archivos escaneados para ver cuáles están en cuarentena (permisos 0000) */
    pthread_mutex_lock(&files_mutex);
    for (int i = 0; i < scanned_files_count; i++) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "/home/sopes/monitor/%s", scanned_files[i].filename);
        
        struct stat st;
        if (stat(full_path, &st) == 0) {
            /* Si no tiene permisos de lectura, escritura o ejecución para nadie, está en cuarentena */
            if ((st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == 0) {
                json_t *obj = json_object();
                json_object_set_new(obj, "filename", json_string(scanned_files[i].filename));
                json_object_set_new(obj, "timestamp", json_string(scanned_files[i].timestamp));
                json_array_append_new(arr, obj);
            }
        }
    }
    pthread_mutex_unlock(&files_mutex);

    char *json_str = json_dumps(arr, JSON_COMPACT);
    json_decref(arr);
    if (json_str) {
        send_long_response(socket, "200 OK", "application/json", json_str, strlen(json_str));
        free(json_str);
    } else {
        send_response(socket, "200 OK", "application/json", "[]");
    }
}

/*
 * GET /api/processes?page=X&search=Y
 * Retorna una lista PAGINADA de procesos del sistema.
 * 
 * Parámetros opcionales:
 *   page   = Número de página (por defecto 1)
 *   search = Filtro por nombre o PID
 * 
 * Usa la syscall 463 (sys_get_process_list) para obtener los procesos.
 */
static void handle_processes_route(int socket, const char *request) {
    int page = 1;
    char search[100] = {0};
    
    /* Extraemos los parámetros de la URL */
    const char *page_ptr = strstr(request, "page=");
    if (page_ptr) sscanf(page_ptr, "page=%d", &page);
    
    const char *search_ptr = strstr(request, "search=");
    if (search_ptr) sscanf(search_ptr, "search=%99[^ &]", search);
    
    if (page < 1) page = 1;
    int limit = 15; /* Mostramos 15 procesos por página */
    
    /* 
     * Llamamos a la syscall 463 para obtener la lista de procesos.
     * Le pasamos un array de hasta 1024 procesos y el tamaño del array.
     * La syscall retorna el número de procesos que llenó.
     */
    struct process_info procs[1024];
    long int status2 = syscall(463, procs, 1024);
    
    if (status2 < 0) {
        send_response(socket, "500 Internal Server Error", "application/json", "{\"status\":\"error\"}");
        return;
    }
    
    int total_processes = status2;

    /* 
     * Filtramos los procesos según el término de búsqueda.
     * Comparamos contra el nombre del proceso y su PID.
     * strcasestr() busca sin importar mayúsculas/minúsculas.
     */
    struct process_info filtered[1024];
    int filtered_count = 0;
    
    for (int i = 0; i < total_processes; i++) {
        if (strlen(search) > 0) {
            char pid_str[32];
            snprintf(pid_str, sizeof(pid_str), "%d", procs[i].pid);
            if (strcasestr(procs[i].name, search) != NULL || strstr(pid_str, search) != NULL) {
                filtered[filtered_count++] = procs[i];
            }
        } else {
            /* Sin filtro: incluimos todos los procesos */
            filtered[filtered_count++] = procs[i];
        }
    }
    
    /* Calculamos la paginación */
    int total_pages = (filtered_count + limit - 1) / limit;
    if (total_pages == 0) total_pages = 1;
    if (page > total_pages) page = total_pages;
    
    int start_idx = (page - 1) * limit;
    int end_idx = start_idx + limit;
    if (end_idx > filtered_count) end_idx = filtered_count;
    
    /* Construimos el JSON de respuesta con los procesos de la página actual */
    json_t *root = json_object();
    json_t *json_procs = json_array();
    
    for (int i = start_idx; i < end_idx; i++) {
        json_t *proc_obj = json_object();
        json_object_set_new(proc_obj, "pid", json_integer(filtered[i].pid));
        json_object_set_new(proc_obj, "name", json_string(filtered[i].name));
        json_object_set_new(proc_obj, "memory_usage", json_integer(filtered[i].memory_usage));
        json_array_append_new(json_procs, proc_obj);
    }
    
    /* Incluimos metadata de paginación para que el frontend sepa cuántas páginas hay */
    json_object_set_new(root, "data", json_procs);
    json_object_set_new(root, "total_pages", json_integer(total_pages));
    json_object_set_new(root, "current_page", json_integer(page));
    json_object_set_new(root, "total_records", json_integer(filtered_count));
    
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (json_str) {
        send_long_response(socket, "200 OK", "application/json", json_str, strlen(json_str));
        free(json_str);
    } else {
        send_response(socket, "500 Internal Server Error", "application/json", "{\"status\":\"error\"}");
    }
    json_decref(root);
}

/*
 * GET /api/top_processes
 * Retorna los 20 procesos con mayor consumo de memoria.
 * 
 * Obtiene todos los procesos con syscall 463 y luego los ordena
 * de mayor a menor consumo usando qsort() (QuickSort).
 */
static void handle_top_processes_route(int socket) {
    struct process_info procs[1024];
    long int count = syscall(463, procs, 1024);

    if (count < 0) {
        send_response(socket, "500 Internal Server Error", "application/json", "{\"status\":\"error\"}");
        return;
    }

    /* Ordenamos los procesos por consumo de memoria (de mayor a menor) */
    qsort(procs, count, sizeof(struct process_info), cmp_process_by_memory_desc);

    /* Tomamos solo los top 20 (o menos si hay menos procesos) */
    int top = count < 20 ? count : 20;
    json_t *arr = json_array();
    for (int i = 0; i < top; i++) {
        json_t *obj = json_object();
        json_object_set_new(obj, "pid", json_integer(procs[i].pid));
        json_object_set_new(obj, "name", json_string(procs[i].name));
        json_object_set_new(obj, "memory_usage", json_integer(procs[i].memory_usage));
        json_array_append_new(arr, obj);
    }

    char *json_str = json_dumps(arr, JSON_COMPACT);
    json_decref(arr);
    if (json_str) {
        send_long_response(socket, "200 OK", "application/json", json_str, strlen(json_str));
        free(json_str);
    } else {
        send_response(socket, "200 OK", "application/json", "[]");
    }
}

/*
 * GET /api/process_info?pid=X
 * Obtiene información detallada de un proceso específico usando
 * la syscall 464 (sys_get_process_info).
 * 
 * A diferencia de la syscall 463 que obtiene TODOS los procesos,
 * esta syscall recibe un PID y retorna solo la información de ese proceso.
 */
static void handle_process_info_route(int socket, const char *request) {
    int pid;
    if (sscanf(request, "GET /api/process_info?pid=%d", &pid) != 1) {
        send_response(socket, "400 Bad Request", "application/json", "{\"status\":\"error\", \"message\":\"PID invalido\"}");
        return;
    }

    struct process_info info;
    /* Llamamos a la syscall 464 con el PID específico */
    long int ret = syscall(464, pid, &info);

    if (ret < 0) {
        /* El proceso no existe o hubo un error */
        send_response(socket, "404 Not Found", "application/json", "{\"status\":\"error\", \"message\":\"Proceso no encontrado\"}");
        return;
    }

    /* Construimos el JSON con la información del proceso */
    json_t *obj = json_object();
    json_object_set_new(obj, "pid", json_integer(info.pid));
    json_object_set_new(obj, "name", json_string(info.name));
    json_object_set_new(obj, "memory_usage", json_integer(info.memory_usage));

    char *json_str = json_dumps(obj, JSON_COMPACT);
    json_decref(obj);
    if (json_str) {
        send_response(socket, "200 OK", "application/json", json_str);
        free(json_str);
    } else {
        send_response(socket, "500 Internal Server Error", "application/json", "{\"status\":\"error\"}");
    }
}

/*
 * GET /api/files
 * Retorna la lista de todos los archivos que han sido escaneados,
 * incluyendo su hash SHA-256, si es malicioso o benigno, etc.
 */
static void handle_files_route(int socket) {
    json_t *arr = json_array();

    /* Leemos la lista de archivos escaneados con protección de mutex */
    pthread_mutex_lock(&files_mutex);
    for (int i = 0; i < scanned_files_count; i++) {
        json_t *obj = json_object();
        json_object_set_new(obj, "filename", json_string(scanned_files[i].filename));
        json_object_set_new(obj, "hash", json_string(scanned_files[i].hash));
        json_object_set_new(obj, "is_malicious", json_boolean(scanned_files[i].is_malicious));
        json_object_set_new(obj, "threat_name", json_string(scanned_files[i].threat_name));
        json_object_set_new(obj, "description", json_string(scanned_files[i].description));
        json_object_set_new(obj, "timestamp", json_string(scanned_files[i].timestamp));

        /* Verificar si está en cuarentena (permisos 000) */
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "/home/sopes/monitor/%s", scanned_files[i].filename);
        struct stat st;
        int is_quarantined = 0;
        if (stat(full_path, &st) == 0) {
            /* Si no tiene permisos de lectura, escritura o ejecución para nadie, está en cuarentena */
            if ((st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == 0) {
                is_quarantined = 1;
            }
        }
        json_object_set_new(obj, "is_quarantined", json_boolean(is_quarantined));

        json_array_append_new(arr, obj);
    }
    pthread_mutex_unlock(&files_mutex);

    char *json_str = json_dumps(arr, JSON_COMPACT);
    json_decref(arr);
    if (json_str) {
        send_long_response(socket, "200 OK", "application/json", json_str, strlen(json_str));
        free(json_str);
    } else {
        send_response(socket, "200 OK", "application/json", "[]");
    }
}

/*
 * GET /api/toggle_scan
 * Activa o desactiva el escaneo de archivos.
 * Genera alertas LOW (activar) o MEDIUM (desactivar).
 */
static void handle_toggle_scan_route(int socket) {
    /* Invertimos el estado actual (toggle) */
    scan_enabled = !scan_enabled;
    if (scan_enabled) {
        add_alert("sistema", "Monitoreo del sistema activado", "LOW");
    } else {
        add_alert("sistema", "Monitoreo del sistema desactivado", "MEDIUM");
    }

    char body[128];
    snprintf(body, sizeof(body), "{\"status\":\"success\", \"scan_enabled\":%s}", scan_enabled ? "true" : "false");
    send_response(socket, "200 OK", "application/json", body);
}

/*
 * GET /api/toggle_metrics
 * Activa o desactiva el monitoreo de métricas del sistema.
 * Genera alertas LOW (activar) o MEDIUM (desactivar).
 */
static void handle_toggle_metrics_route(int socket) {
    metrics_enabled = !metrics_enabled;
    if (metrics_enabled) {
        add_alert("sistema", "Monitoreo de metricas activado", "LOW");
    } else {
        add_alert("sistema", "Monitoreo de metricas desactivado", "MEDIUM");
    }

    char body[128];
    snprintf(body, sizeof(body), "{\"status\":\"success\", \"metrics_enabled\":%s}", metrics_enabled ? "true" : "false");
    send_response(socket, "200 OK", "application/json", body);
}

/*
 * GET /api/status
 * Retorna el estado actual de los toggles (escaneo y métricas).
 * El frontend lo consulta al inicio para sincronizar los botones.
 */
static void handle_status_route(int socket) {
    char body[128];
    snprintf(body, sizeof(body), "{\"scan_enabled\":%s, \"metrics_enabled\":%s}",
             scan_enabled ? "true" : "false", metrics_enabled ? "true" : "false");
    send_response(socket, "200 OK", "application/json", body);
}

/*
 * GET /api/download_blacklist
 * Retorna el contenido actual de blacklist.json para descarga.
 */
static void handle_download_blacklist_route(int socket) {
    json_error_t error;
    json_t *root = json_load_file(JSON_FILE, 0, &error);
    if (!root) {
        send_response(socket, "500 Error", "application/json", "{\"status\":\"error\", \"message\":\"No se pudo leer blacklist.json\"}");
        return;
    }
    char *json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (json_str) {
        /* Encabezados para forzar descarga si fuera necesario, o simplemente retornar JSON */
        send_long_response(socket, "200 OK", "application/json", json_str, strlen(json_str));
        free(json_str);
    } else {
        send_response(socket, "500 Error", "application/json", "{\"status\":\"error\"}");
    }
}

/*
 * POST /api/add_blacklist
 * Añade nuevas entradas a la base de datos de hashes malignos (blacklist.json)
 * sin borrar las existentes.
 */
static void handle_add_blacklist_route(int socket, const char *request) {
    const char *body = strstr(request, "\r\n\r\n");
    if (!body) {
        send_response(socket, "400 Bad Request", "application/json", "{\"status\":\"error\", \"message\":\"Body vacio\"}");
        return;
    }
    body += 4;

    json_error_t error;
    json_t *new_entries = json_loads(body, 0, &error);
    if (!new_entries) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "{\"status\":\"error\", \"message\":\"JSON invalido: %s\"}", error.text);
        send_response(socket, "400 Bad Request", "application/json", err_msg);
        return;
    }

    const char *key;
    json_t *value;
    json_object_foreach(new_entries, key, value) {
        json_t *hash_j = json_object_get(value, "hash");
        json_t *desc_j = json_object_get(value, "descripcion");
        if (!json_is_string(hash_j) || !json_is_string(desc_j)) {
            json_decref(new_entries);
            send_response(socket, "400 Bad Request", "application/json",
                         "{\"status\":\"error\", \"message\":\"Formato invalido: cada entrada necesita 'hash' y 'descripcion'\"}");
            return;
        }
    }

    /* Cargamos la blacklist existente */
    json_t *existing_root = json_load_file(JSON_FILE, 0, &error);
    if (!existing_root) {
        existing_root = json_object(); /* Si no existe, creamos una nueva */
    }

    /* Fusionamos las nuevas entradas en la existente */
    json_object_update(existing_root, new_entries);

    /* Guardamos el resultado */
    if (json_dump_file(existing_root, JSON_FILE, JSON_INDENT(2)) != 0) {
        json_decref(new_entries);
        json_decref(existing_root);
        send_response(socket, "500 Error", "application/json", "{\"status\":\"error\", \"message\":\"Error al escribir archivo\"}");
        return;
    }

    json_decref(new_entries);
    json_decref(existing_root);
    
    add_alert("sistema", "Nuevas amenazas agregadas a la base de datos local", "MEDIUM");
    send_response(socket, "200 OK", "application/json", "{\"status\":\"success\", \"message\":\"Amenazas agregadas a la blacklist\"}");
}

/*
 * POST /api/update_blacklist
 * Actualiza la base de datos de hashes malignos (blacklist.json).
 * 
 * El body del POST debe contener un JSON válido con el formato:
 * {
 *   "NombreAmenaza": {
 *     "hash": "sha256_hex",
 *     "descripcion": "Texto descriptivo"
 *   }
 * }
 * 
 * El sistema valida la estructura antes de guardar el archivo.
 */
static void handle_update_blacklist_route(int socket, const char *request) {
    /* 
     * Buscamos el body del POST.
     * En HTTP, el body va después de dos saltos de línea (\r\n\r\n).
     * Todo lo que está antes son los headers.
     */
    const char *body = strstr(request, "\r\n\r\n");
    if (!body) {
        send_response(socket, "400 Bad Request", "application/json", "{\"status\":\"error\", \"message\":\"Body vacio\"}");
        return;
    }
    body += 4; /* Saltamos los 4 caracteres de \r\n\r\n */

    /* Parseamos el JSON del body */
    json_error_t error;
    json_t *root = json_loads(body, 0, &error);
    if (!root) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "{\"status\":\"error\", \"message\":\"JSON invalido: %s\"}", error.text);
        send_response(socket, "400 Bad Request", "application/json", err_msg);
        return;
    }

    /* 
     * Validamos que cada entrada del JSON tenga los campos requeridos.
     * json_object_foreach() itera sobre cada par clave-valor del objeto.
     */
    const char *key;
    json_t *value;
    json_object_foreach(root, key, value) {
        json_t *hash_j = json_object_get(value, "hash");
        json_t *desc_j = json_object_get(value, "descripcion");
        if (!json_is_string(hash_j) || !json_is_string(desc_j)) {
            json_decref(root);
            send_response(socket, "400 Bad Request", "application/json",
                         "{\"status\":\"error\", \"message\":\"Formato invalido: cada entrada necesita 'hash' y 'descripcion'\"}");
            return;
        }
    }

    /* Guardamos el JSON validado en el archivo blacklist.json */
    if (json_dump_file(root, JSON_FILE, JSON_INDENT(2)) != 0) {
        json_decref(root);
        send_response(socket, "500 Error", "application/json", "{\"status\":\"error\", \"message\":\"Error al escribir archivo\"}");
        return;
    }

    json_decref(root);
    /* Generamos alerta MEDIUM porque se actualizó la BD de firmas */
    add_alert("sistema", "Actualizacion base de datos local de hashes malignos", "MEDIUM");
    send_response(socket, "200 OK", "application/json", "{\"status\":\"success\", \"message\":\"Blacklist actualizada\"}");
}

/*
 * POST /api/create_user
 * Crea un nuevo usuario del sistema Linux desde el panel de administración.
 * 
 * El body del POST debe contener un JSON con:
 * {
 *   "username": "nombre_usuario",
 *   "password": "contraseña",
 *   "role": "admin_user" | "common_user"
 * }
 * 
 * Esta ruta solo debería ser accesible por administradores.
 * El nuevo usuario se crea en el sistema Linux con useradd,
 * se le asigna la contraseña y se agrega al grupo correspondiente.
 */
static void handle_create_user_route(int socket, const char *request) {
    /* Buscamos el body del POST */
    const char *body = strstr(request, "\r\n\r\n");
    if (!body) {
        send_response(socket, "400 Bad Request", "application/json", "{\"status\":\"error\", \"message\":\"Body vacio\"}");
        return;
    }
    body += 4;

    /* Parseamos el JSON del body */
    json_error_t error;
    json_t *root = json_loads(body, 0, &error);
    if (!root) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "{\"status\":\"error\", \"message\":\"JSON invalido: %s\"}", error.text);
        send_response(socket, "400 Bad Request", "application/json", err_msg);
        return;
    }

    /* Extraemos los campos del JSON */
    json_t *j_user = json_object_get(root, "username");
    json_t *j_pass = json_object_get(root, "password");
    json_t *j_role = json_object_get(root, "role");

    /* Validamos que todos los campos estén presentes y sean strings */
    if (!json_is_string(j_user) || !json_is_string(j_pass) || !json_is_string(j_role)) {
        json_decref(root);
        send_response(socket, "400 Bad Request", "application/json",
                     "{\"status\":\"error\", \"message\":\"Se requieren los campos 'username', 'password' y 'role'\"}");
        return;
    }

    const char *username = json_string_value(j_user);
    const char *password = json_string_value(j_pass);
    const char *role = json_string_value(j_role);

    /* Validamos que el rol sea uno de los dos válidos */
    if (strcmp(role, "admin_user") != 0 && strcmp(role, "common_user") != 0) {
        json_decref(root);
        send_response(socket, "400 Bad Request", "application/json",
                     "{\"status\":\"error\", \"message\":\"El rol debe ser 'admin_user' o 'common_user'\"}");
        return;
    }

    /* Validamos que el nombre de usuario no esté vacío y tenga una longitud razonable */
    if (strlen(username) < 1 || strlen(username) > 32) {
        json_decref(root);
        send_response(socket, "400 Bad Request", "application/json",
                     "{\"status\":\"error\", \"message\":\"El nombre de usuario debe tener entre 1 y 32 caracteres\"}");
        return;
    }

    /* Llamamos a la función que crea el usuario en el sistema Linux */
    int result = create_system_user(username, password, role);

    json_decref(root);

    /* Respondemos según el resultado */
    switch (result) {
        case 0:
            /* Éxito: usuario creado correctamente */
            {
                char desc[256];
                snprintf(desc, sizeof(desc), "Nuevo usuario '%s' creado con rol '%s'", username, role);
                add_alert("sistema", desc, "LOW");
            }
            send_response(socket, "200 OK", "application/json",
                         "{\"status\":\"success\", \"message\":\"Usuario creado exitosamente\"}");
            break;
        case 1:
            /* El usuario ya existe */
            send_response(socket, "409 Conflict", "application/json",
                         "{\"status\":\"error\", \"message\":\"El usuario ya existe en el sistema\"}");
            break;
        case -1:
            send_response(socket, "500 Error", "application/json",
                         "{\"status\":\"error\", \"message\":\"Error al crear el usuario (useradd fallo)\"}");
            break;
        case -2:
            send_response(socket, "500 Error", "application/json",
                         "{\"status\":\"error\", \"message\":\"Error al asignar la contrasena (chpasswd fallo)\"}");
            break;
        case -3:
            send_response(socket, "500 Error", "application/json",
                         "{\"status\":\"error\", \"message\":\"Error al agregar el usuario al grupo (usermod fallo)\"}");
            break;
        default:
            send_response(socket, "500 Error", "application/json",
                         "{\"status\":\"error\", \"message\":\"Error desconocido\"}");
            break;
    }
}

/* ============================================================
 * HILO DEL SERVIDOR HTTP
 * 
 * Esta función crea un servidor TCP que escucha en el puerto 8080.
 * Cuando llega una conexión, lee la petición HTTP, identifica la ruta
 * y llama al handler correspondiente.
 * 
 * CONCEPTOS IMPORTANTES DE SOCKETS:
 *   socket() → Crea un "punto final" de comunicación
 *   bind()   → Asocia el socket con una dirección IP y puerto
 *   listen() → Marca el socket como pasivo (listo para recibir conexiones)
 *   accept() → Espera y acepta una conexión entrante
 *   read()   → Lee datos del cliente
 *   write()  → Envía datos al cliente
 *   close()  → Cierra la conexión
 * ============================================================ */
void *thread_servidor_http(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    /* Paso 1: Crear el socket TCP */
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Fallo en socket"); exit(EXIT_FAILURE);
    }
    
    /* 
     * SO_REUSEADDR | SO_REUSEPORT permite reutilizar el puerto inmediatamente
     * después de cerrar el programa. Sin esto, habría que esperar unos minutos
     * antes de poder volver a usar el puerto 8080.
     */
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    /* Configuramos la dirección: IPv4, todas las interfaces, puerto 8080 */
    address.sin_family = AF_INET;          /* IPv4 */
    address.sin_addr.s_addr = INADDR_ANY;  /* Escuchar en todas las interfaces de red */
    address.sin_port = htons(PORT);        /* Puerto 8080 (htons convierte a network byte order) */

    /* Paso 2: Asociar el socket con la dirección configurada */
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Fallo en bind"); exit(EXIT_FAILURE);
    }
    
    /* Paso 3: Marcar el socket como pasivo (puede aceptar conexiones) */
    if (listen(server_fd, 10) < 0) {
        perror("Fallo en listen"); exit(EXIT_FAILURE);
    }

    printf("[Servidor HTTP] Escuchando en http://0.0.0.0:%d\n", PORT);

    /* Paso 4: Bucle principal - aceptar y procesar conexiones */
    while(1) {
        /* 
         * accept() bloquea hasta que un cliente se conecte.
         * Retorna un NUEVO socket específico para esa conexión.
         */
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            continue; /* Si falla, ignoramos y esperamos la siguiente conexión */
        }
        
        /* Leemos la petición HTTP del cliente (buffer grande para soportar POST con body) */
        char buffer[65536] = {0};
        read(new_socket, buffer, sizeof(buffer)-1);

        /* ============================================================
         * RUTEO: Determinamos qué handler llamar según la ruta de la petición.
         * 
         * strncmp() compara los primeros N caracteres de dos strings.
         * Si coinciden, retorna 0 (por eso usamos == 0).
         * 
         * El orden importa: rutas más específicas van primero.
         * Por ejemplo, /api/quarantine_list debe ir ANTES de /api/quarantine
         * para que no se confundan.
         * ============================================================ */
        if (strncmp(buffer, "GET /api/metrics", 16) == 0) {
            handle_metrics_route(new_socket);
        } else if (strncmp(buffer, "GET /api/top_processes", 22) == 0) {
            handle_top_processes_route(new_socket);
        } else if (strncmp(buffer, "GET /api/process_info", 21) == 0) {
            handle_process_info_route(new_socket, buffer);
        } else if (strncmp(buffer, "GET /api/processes", 18) == 0) {
            handle_processes_route(new_socket, buffer);
        } else if (strncmp(buffer, "GET /api/login", 14) == 0) {
            handle_login_route(new_socket, buffer);
        } else if (strncmp(buffer, "GET /api/alerts", 15) == 0) {
            handle_alerts_route(new_socket);
        } else if (strncmp(buffer, "GET /api/kill", 13) == 0) {
            handle_kill_route(new_socket, buffer);
        } else if (strncmp(buffer, "GET /api/quarantine_list", 24) == 0) {
            handle_quarantine_list_route(new_socket);
        } else if (strncmp(buffer, "GET /api/quarantine", 19) == 0) {
            handle_quarantine_route(new_socket, buffer);
        } else if (strncmp(buffer, "GET /api/files", 14) == 0) {
            handle_files_route(new_socket);
        } else if (strncmp(buffer, "GET /api/toggle_scan", 20) == 0) {
            handle_toggle_scan_route(new_socket);
        } else if (strncmp(buffer, "GET /api/toggle_metrics", 23) == 0) {
            handle_toggle_metrics_route(new_socket);
        } else if (strncmp(buffer, "GET /api/status", 15) == 0) {
            handle_status_route(new_socket);
        } else if (strncmp(buffer, "GET /api/download_blacklist", 27) == 0) {
            handle_download_blacklist_route(new_socket);
        } else if (strncmp(buffer, "POST /api/add_blacklist", 23) == 0) {
            handle_add_blacklist_route(new_socket, buffer);
        } else if (strncmp(buffer, "POST /api/update_blacklist", 26) == 0) {
            handle_update_blacklist_route(new_socket, buffer);
        } else if (strncmp(buffer, "POST /api/create_user", 21) == 0) {
            handle_create_user_route(new_socket, buffer);
        } else if (strncmp(buffer, "OPTIONS", 7) == 0) {
            /* 
             * OPTIONS es una petición "preflight" que el navegador envía
             * antes de hacer una petición POST con CORS.
             * Debemos responder con los headers de CORS permitidos.
             */
            char *resp = "HTTP/1.1 204 No Content\r\n"
                         "Access-Control-Allow-Origin: *\r\n"
                         "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                         "Access-Control-Allow-Headers: *\r\n"
                         "Access-Control-Max-Age: 86400\r\n"
                         "\r\n";
            write(new_socket, resp, strlen(resp));
        } else {
            /* Ruta no encontrada */
            send_response(new_socket, "404 Not Found", "text/plain", "Not Found");
        }

        /* Cerramos la conexión con este cliente */
        close(new_socket);
    }
    return NULL;
}
