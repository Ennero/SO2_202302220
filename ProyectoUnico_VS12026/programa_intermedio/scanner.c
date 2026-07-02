/*
 * scanner.c - Módulo de escaneo de archivos y detección de amenazas
 * 
 * Este módulo implementa el hilo encargado de escanear archivos
 * en busca de amenazas. El flujo de detección funciona así:
 * 
 *   1. El LKM (módulo del kernel) detecta que se escribió un archivo
 *      en el directorio /home/sopes/monitor/
 *   2. El LKM escribe el nombre del archivo en /proc/edr_alerts
 *   3. Este hilo lee /proc/edr_alerts cada 2 segundos
 *   4. Si hay un nombre de archivo, calcula su hash SHA-256
 *   5. Compara el hash contra la blacklist.json (base de firmas)
 *   6. Si coincide: genera alerta HIGH (amenaza detectada)
 *   7. Si no coincide: genera alerta LOW (archivo limpio)
 * 
 * Funciones importantes:
 *   - calculate_sha256():      Calcula el hash SHA-256 de un archivo
 *   - check_blacklist():       Busca un hash en la base de datos de amenazas
 *   - register_scanned_file(): Registra el resultado del escaneo
 *   - process_alert():         Orquesta todo el proceso de escaneo
 *   - thread_archivos():       Función principal del hilo
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#include "scanner.h"
#include "globals.h"
#include "alerts.h"
#include <stdio.h>        /* Para printf, fopen, fclose, fread, fgets */
#include <stdlib.h>       /* Para funciones generales */
#include <string.h>       /* Para strcmp, strncpy, memcpy, etc. */
#include <strings.h>      /* Para strcasecmp (comparación case-insensitive) */
#include <unistd.h>       /* Para sleep() */
#include <openssl/evp.h>  /* API moderna de OpenSSL para criptografía (SHA-256) */
#include <time.h>         /* Para time() y localtime() */
#include <jansson.h>      /* Para parsear/crear JSON */

/* ============================================================
 * DEFINICIÓN DE VARIABLES GLOBALES
 * Estas variables están declaradas como "extern" en globals.h
 * pero se definen aquí (aquí se reserva la memoria real).
 * ============================================================ */

/* Mutex para proteger las listas de archivos cuando se leen/escriben */
pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Array donde almacenamos los archivos que hemos escaneado */
scanned_file_t scanned_files[MAX_SCANNED_FILES];
int scanned_files_count = 0; /* Cantidad de archivos actualmente en el array */

/* Array donde almacenamos los archivos que están en cuarentena */
quarantined_file_t quarantined_files[MAX_QUARANTINED];
int quarantined_count = 0; /* Cantidad de archivos en cuarentena */

/* ============================================================
 * PERSISTENCIA DE ARCHIVOS ESCANEADOS
 * ============================================================ */
static void save_scanned_files() {
    json_t *arr = json_array();
    for (int i = 0; i < scanned_files_count; i++) {
        json_t *obj = json_object();
        json_object_set_new(obj, "filename", json_string(scanned_files[i].filename));
        json_object_set_new(obj, "hash", json_string(scanned_files[i].hash));
        json_object_set_new(obj, "is_malicious", json_integer(scanned_files[i].is_malicious));
        json_object_set_new(obj, "threat_name", json_string(scanned_files[i].threat_name));
        json_object_set_new(obj, "description", json_string(scanned_files[i].description));
        json_object_set_new(obj, "timestamp", json_string(scanned_files[i].timestamp));
        json_array_append_new(arr, obj);
    }
    json_dump_file(arr, "archivos_analizados.json", JSON_INDENT(4));
    json_decref(arr);
}

void init_scanner_db() {
    json_error_t error;
    json_t *arr = json_load_file("archivos_analizados.json", 0, &error);
    if (arr && json_is_array(arr)) {
        size_t index;
        json_t *obj;
        scanned_files_count = 0;
        json_array_foreach(arr, index, obj) {
            if (scanned_files_count >= MAX_SCANNED_FILES) break;
            strncpy(scanned_files[scanned_files_count].filename, json_string_value(json_object_get(obj, "filename")), 255);
            strncpy(scanned_files[scanned_files_count].hash, json_string_value(json_object_get(obj, "hash")), 64);
            scanned_files[scanned_files_count].is_malicious = json_integer_value(json_object_get(obj, "is_malicious"));
            strncpy(scanned_files[scanned_files_count].threat_name, json_string_value(json_object_get(obj, "threat_name")), 127);
            strncpy(scanned_files[scanned_files_count].description, json_string_value(json_object_get(obj, "description")), 255);
            strncpy(scanned_files[scanned_files_count].timestamp, json_string_value(json_object_get(obj, "timestamp")), 31);
            scanned_files_count++;
        }
        json_decref(arr);
    }
}

/* ============================================================
 * calculate_sha256 - Calcula el hash SHA-256 de un archivo
 * 
 * SHA-256 es un algoritmo criptográfico que genera un "resumen"
 * único de 256 bits (64 caracteres hexadecimales) para cualquier archivo.
 * Si el archivo cambia aunque sea un byte, el hash cambia completamente.
 * Esto nos permite identificar archivos maliciosos por su "firma" (hash).
 * 
 * Parámetros:
 *   filepath       - Ruta completa al archivo a hashear
 *   output_buffer  - Buffer donde se escribirá el hash (mínimo 65 bytes)
 * 
 * Retorna:
 *   1 si se calculó exitosamente
 *   0 si hubo un error (archivo no encontrado, etc.)
 * 
 * Usamos la API EVP de OpenSSL (la moderna y recomendada),
 * en lugar de las funciones SHA256() directas que están deprecadas.
 * ============================================================ */
static int calculate_sha256(const char *filepath, char *output_buffer) {
    /* Abrimos el archivo en modo binario ("rb" = read binary) */
    FILE *file = fopen(filepath, "rb");
    if (!file) return 0; /* El archivo no existe o no tenemos permisos */
    
    /* 
     * Creamos un "contexto" de digest (resumen).
     * EVP_MD_CTX es la estructura que OpenSSL usa para llevar el estado
     * del cálculo del hash a medida que vamos leyendo el archivo.
     */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { fclose(file); return 0; }
    
    const EVP_MD *md = EVP_sha256(); /* Seleccionamos el algoritmo SHA-256 */
    unsigned char hash[EVP_MAX_MD_SIZE]; /* Buffer para el hash resultante (en bytes) */
    unsigned int md_len; /* Longitud del hash en bytes (para SHA-256 será 32) */
    unsigned char buffer[8192]; /* Buffer de lectura (leemos el archivo en bloques de 8KB) */
    size_t bytes_read;
    
    /* Inicializamos el contexto con el algoritmo SHA-256 */
    EVP_DigestInit_ex(mdctx, md, NULL);

    /* 
     * Leemos el archivo en bloques de 8KB y vamos "alimentando"
     * el algoritmo de hash con cada bloque.
     * Esto permite hashear archivos enormes sin cargarlos completos en memoria.
     */
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }
    fclose(file); /* Ya terminamos de leer el archivo */

    /* Finalizamos el cálculo del hash y obtenemos el resultado */
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx); /* Liberamos el contexto */
    
    /* 
     * Convertimos el hash de bytes a una cadena hexadecimal.
     * Ejemplo: byte 0xAB -> "ab" (2 caracteres por cada byte)
     * El hash SHA-256 tiene 32 bytes -> 64 caracteres hex.
     */
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(output_buffer + (i * 2), "%02x", hash[i]);
    }
    output_buffer[64] = '\0'; /* Terminamos la cadena con null */
    return 1; /* Éxito */
}

/* ============================================================
 * check_blacklist - Busca un hash en la base de datos de amenazas
 * 
 * Lee el archivo blacklist.json y compara el hash calculado
 * contra cada entrada de la base de datos.
 * 
 * El formato de blacklist.json es:
 * {
 *   "NombreAmenaza": {
 *     "hash": "abc123...",
 *     "descripcion": "Descripción de la amenaza"
 *   }
 * }
 * 
 * Parámetros:
 *   hash_calculado  - El hash SHA-256 del archivo escaneado
 *   threat_name_out - Buffer donde se escribirá el nombre de la amenaza
 *   desc_out        - Buffer donde se escribirá la descripción
 * 
 * Retorna:
 *   1 si el hash fue encontrado en la blacklist (¡archivo malicioso!)
 *   0 si no fue encontrado (archivo limpio)
 * ============================================================ */
static int check_blacklist(const char *hash_calculado, char *threat_name_out, char *desc_out) {
    /* Cargamos el archivo JSON de la blacklist */
    json_error_t error;
    json_t *root = json_load_file(JSON_FILE, 0, &error);
    if (!root) return 0; /* Si no se puede leer el archivo, asumimos limpio */
    
    const char *key;   /* Nombre de la amenaza (la key del JSON) */
    json_t *value;     /* Objeto con hash y descripción */
    int found = 0;

    /* 
     * json_object_foreach es una macro de jansson que itera
     * sobre cada par clave-valor del objeto JSON.
     * Es el equivalente a un for...of en JavaScript.
     */
    json_object_foreach(root, key, value) {
        json_t *hash_json = json_object_get(value, "hash");
        json_t *desc_json = json_object_get(value, "descripcion");

        if (json_is_string(hash_json)) {
            const char *hash_str = json_string_value(hash_json);
            /* 
             * Comparamos los hashes de forma case-insensitive
             * porque los hashes pueden estar en mayúsculas o minúsculas.
             * strcasecmp() retorna 0 si las cadenas son iguales (ignorando caso).
             */
            if (strcasecmp(hash_str, hash_calculado) == 0) {
                found = 1;

                /* Copiamos el nombre de la amenaza (la key del JSON) */
                strncpy(threat_name_out, key, 127);
                threat_name_out[127] = '\0';

                /* Copiamos la descripción si existe */
                if (json_is_string(desc_json)) {
                    strncpy(desc_out, json_string_value(desc_json), 255);
                    desc_out[255] = '\0';
                } else {
                    strcpy(desc_out, "Amenaza identificada");
                }
                break; /* Ya encontramos el hash, no necesitamos seguir buscando */
            }
        }
    }

    json_decref(root); /* Liberamos la memoria del JSON cargado */
    return found;
}

/* ============================================================
 * write_security_log - Escribe una alerta en el archivo de log
 * 
 * Además de las alertas en memoria (que se envían al frontend),
 * también guardamos un registro en un archivo de texto plano
 * para tener un historial persistente de las amenazas detectadas.
 * ============================================================ */
static void write_security_log(const char *filename, const char *hash_str, const char *threat_desc) {
    /* Abrimos el archivo en modo "append" (agregar al final) */
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;
    
    /* Obtenemos la fecha y hora actual */
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    fprintf(log, "[%d-%02d-%02d %02d:%02d:%02d] ALERTA: %s | Archivo: %s | Hash: %s\n", 
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, 
            tm.tm_hour, tm.tm_min, tm.tm_sec, threat_desc, filename, hash_str);
    fclose(log);
}

/* ============================================================
 * get_current_timestamp - Obtiene la fecha y hora actual como string
 * 
 * Formato: "2026-06-16 10:30:45"
 * Se usa para registrar cuándo fue escaneado cada archivo.
 * ============================================================ */
static void get_current_timestamp(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    snprintf(buf, len, "%d-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* ============================================================
 * register_scanned_file - Registra un archivo escaneado en la lista global
 * 
 * Guarda la información del archivo escaneado para que el frontend
 * pueda mostrarla en la tabla de "Archivos Analizados".
 * 
 * Si el archivo ya fue escaneado antes, actualiza su información
 * en lugar de crear una entrada duplicada.
 * ============================================================ */
static void register_scanned_file(const char *filename, const char *hash,
                                   int is_malicious, const char *threat_name,
                                   const char *description) {
    /* Protegemos el acceso a la lista con mutex */
    pthread_mutex_lock(&files_mutex);

    /* Buscamos si este archivo ya está en nuestra lista */
    int idx = -1;
    for (int i = 0; i < scanned_files_count; i++) {
        if (strcmp(scanned_files[i].filename, filename) == 0) {
            idx = i; /* Ya existe, vamos a actualizarlo */
            break;
        }
    }

    /* Si no existe, lo agregamos como nuevo */
    if (idx == -1) {
        if (scanned_files_count >= MAX_SCANNED_FILES) {
            /* 
             * Si llegamos al límite, eliminamos el más antiguo (FIFO).
             * memmove() mueve la memoria desplazando todo el array
             * una posición hacia atrás, liberando la posición 0.
             */
            memmove(&scanned_files[0], &scanned_files[1],
                    sizeof(scanned_file_t) * (MAX_SCANNED_FILES - 1));
            scanned_files_count = MAX_SCANNED_FILES - 1;
        }
        idx = scanned_files_count++; /* Usamos el siguiente slot disponible */
    }

    /* Copiamos toda la información del archivo al slot correspondiente */
    strncpy(scanned_files[idx].filename, filename, sizeof(scanned_files[idx].filename) - 1);
    strncpy(scanned_files[idx].hash, hash, sizeof(scanned_files[idx].hash) - 1);
    scanned_files[idx].is_malicious = is_malicious;
    strncpy(scanned_files[idx].threat_name, threat_name, sizeof(scanned_files[idx].threat_name) - 1);
    strncpy(scanned_files[idx].description, description, sizeof(scanned_files[idx].description) - 1);
    get_current_timestamp(scanned_files[idx].timestamp, sizeof(scanned_files[idx].timestamp));

    /* Guardamos la persistencia en formato binario */
    save_scanned_files();

    /* También lo escribimos en el log legible de texto plano */
    FILE *log = fopen("archivos_analizados.log", "a");
    if (log) {
        fprintf(log, "[%s] Archivo: %s | Estado: %s | Hash: %s\n",
                scanned_files[idx].timestamp, filename, 
                is_malicious ? "INFECTADO" : "Limpio", hash);
        fclose(log);
    }

    pthread_mutex_unlock(&files_mutex);
}

/* ============================================================
 * process_alert - Procesa un archivo detectado por el LKM
 * 
 * Esta es la función "orquestadora" que ejecuta todo el pipeline
 * de detección para un archivo:
 *   1. Construye la ruta completa al archivo
 *   2. Calcula su hash SHA-256
 *   3. Lo compara contra la blacklist
 *   4. Genera las alertas correspondientes
 *   5. Registra el resultado
 * ============================================================ */
static void process_alert(const char *filename) {
    char full_path[512];
    char hash_str[65];
    char threat_name[128] = {0};
    char threat_desc[256] = {0};

    /* Construimos la ruta completa: /home/sopes/monitor/ + nombre_archivo */
    snprintf(full_path, sizeof(full_path), "%s%s", MONITOR_DIR, filename);

    /* Calculamos el hash SHA-256 del archivo */
    if (calculate_sha256(full_path, hash_str)) {
        /* Buscamos el hash en nuestra blacklist */
        if (check_blacklist(hash_str, threat_name, threat_desc)) {
            /* ¡AMENAZA DETECTADA! El hash coincide con una entrada de la blacklist */
            write_security_log(filename, hash_str, threat_desc);
            printf("[Hilo EDR] AMENAZA DETECTADA! -> %s | %s | %s\n", filename, threat_name, threat_desc);
            
            /* Generamos una alerta HIGH con detalles de la amenaza */
            char alert_desc[512];
            snprintf(alert_desc, sizeof(alert_desc),
                     "Hash malicioso detectado en '%s' — Firma: %s", filename, threat_name);
            add_alert("archivos", alert_desc, "HIGH");
            
            /* Registramos el archivo como malicioso (is_malicious = 1) */
            register_scanned_file(filename, hash_str, 1, threat_name, threat_desc);
        } else {
            /* El hash no está en la blacklist -> archivo limpio */
            printf("[Hilo EDR] Archivo %s escaneado. Hash limpio.\n", filename);
            add_alert("archivos", "Archivo creado/modificado", "LOW");
            
            /* Registramos el archivo como benigno (is_malicious = 0) */
            register_scanned_file(filename, hash_str, 0, "", "Archivo limpio");
        }
    }
}

/* ============================================================
 * thread_archivos - Función principal del hilo de escaneo
 * 
 * Este hilo corre en un bucle infinito que cada 2 segundos:
 *   1. Verifica si el escaneo está habilitado (toggle del admin)
 *   2. Lee /proc/edr_alerts para ver si el LKM detectó un archivo nuevo
 *   3. Si hay un nombre de archivo, lo procesa (calcula hash, compara, etc.)
 * 
 * La comunicación con el LKM es a través de /proc/edr_alerts:
 *   - El LKM ESCRIBE el nombre del archivo cuando detecta una escritura
 *   - Este hilo LEE el nombre del archivo y lo procesa
 *   - Una vez leído, el LKM marca la alerta como "consumida"
 * ============================================================ */
void *thread_archivos(void *arg) {
    char buffer[256]; /* Buffer para leer el nombre del archivo desde /proc */

    /* Cargamos la base de datos de archivos analizados al arrancar */
    pthread_mutex_lock(&files_mutex);
    init_scanner_db();
    pthread_mutex_unlock(&files_mutex);

    while(1) {
        /* 
         * Verificamos si el escaneo está habilitado.
         * El administrador puede desactivarlo desde el dashboard.
         */
        if (!scan_enabled) {
            sleep(1);
            continue;
        }

        /* 
         * Intentamos leer de /proc/edr_alerts.
         * Si el LKM detectó un archivo nuevo, aquí leeremos su nombre.
         * Si no hay archivo nuevo, fgets() retorna NULL y no hacemos nada.
         */
        FILE *f = fopen(PROC_FILE, "r");
        if (f) {
            if (fgets(buffer, sizeof(buffer), f) != NULL) {
                /* Eliminamos el salto de línea final si existe */
                buffer[strcspn(buffer, "\n")] = 0; 
                if (strlen(buffer) > 0) {
                    /* Si leímos un nombre de archivo, lo procesamos */
                    process_alert(buffer);
                }
            }
            fclose(f);
        }

        /* Esperamos 2 segundos antes de volver a verificar */
        sleep(1);
    }
    return NULL;
}
