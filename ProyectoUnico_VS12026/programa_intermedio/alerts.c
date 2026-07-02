/*
 * alerts.c - Sistema de alertas de seguridad
 * 
 * Este módulo maneja todo lo relacionado con las alertas del sistema EDR.
 * Las alertas se clasifican en 3 niveles de severidad:
 *   - LOW:    Informativo (archivo creado, login exitoso, monitoreo activado)
 *   - MEDIUM: Advertencia (login fallido, proceso matado, BD actualizada)
 *   - HIGH:   Crítico (hash malicioso detectado, archivo en cuarentena)
 * 
 * Las alertas se almacenan en un array JSON en memoria y se envían
 * al frontend cuando este solicita GET /api/alerts.
 * 
 * NOTA IMPORTANTE SOBRE CONCURRENCIA:
 * Este módulo es accedido por múltiples hilos al mismo tiempo
 * (el hilo de monitoreo, el de escaneo y el del servidor HTTP),
 * por lo que usamos mutexes para proteger los datos compartidos.
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#include "alerts.h"
#include "globals.h"
#include <stdlib.h>   /* Para funciones generales (malloc, free, etc.) */
#include <stdio.h>    /* Para printf y snprintf */
#include <time.h>     /* Para time() y localtime() - obtener fecha y hora */
#include <string.h>   /* Para strdup() - duplicar strings */

/* ============================================================
 * DEFINICIÓN DE VARIABLES GLOBALES
 * 
 * Estas variables están declaradas como "extern" en globals.h,
 * pero se DEFINEN aquí (es decir, aquí es donde realmente
 * se reserva la memoria para ellas).
 * 
 * PTHREAD_MUTEX_INITIALIZER es una macro que inicializa un mutex
 * de forma estática (sin necesidad de llamar a pthread_mutex_init).
 * ============================================================ */

/* Mutex para proteger el JSON de métricas cuando se lee/escribe */
pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex para proteger el array de alertas cuando se lee/escribe */
pthread_mutex_t alerts_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Buffer global donde se guarda el JSON de métricas más reciente.
 * Se inicializa con un JSON vacío para evitar errores si el frontend
 * hace una petición antes de que el hilo de métricas haya corrido. */
char global_metrics_json[16384] = "{}";

/* Array JSON donde se almacenan todas las alertas del sistema */
json_t *global_alerts_array = NULL;

/* Variables de control (toggle) para activar/desactivar funciones.
 * Están habilitadas por defecto (1 = activo). */
volatile int scan_enabled = 1;     /* Controla el escaneo de archivos */
volatile int metrics_enabled = 1;  /* Controla el monitoreo de métricas */

/* ============================================================
 * FUNCIONES DE INICIALIZACIÓN Y LIMPIEZA
 * ============================================================ */

/*
 * init_alerts - Inicializa el sistema de alertas
 * 
 * Intenta cargar el historial desde alertas_db.json, si no existe
 * crea un array JSON vacío.
 */
void init_alerts() {
    pthread_mutex_lock(&alerts_mutex);
    if (!global_alerts_array) {
        json_error_t error;
        global_alerts_array = json_load_file("alertas_db.json", 0, &error);
        if (!global_alerts_array) {
            global_alerts_array = json_array();
        }
    }
    pthread_mutex_unlock(&alerts_mutex);
}

/*
 * save_alerts_db - Guarda el array de alertas en un archivo JSON
 * Se debe llamar cada vez que el array se modifique.
 */
static void save_alerts_db() {
    if (global_alerts_array) {
        json_dump_file(global_alerts_array, "alertas_db.json", JSON_INDENT(2));
    }
}

/*
 * cleanup_alerts - Libera la memoria del sistema de alertas
 * 
 * Se llama al finalizar el programa para evitar memory leaks.
 * json_decref() disminuye el contador de referencias del objeto JSON;
 * cuando llega a 0, jansson libera la memoria automáticamente.
 */
void cleanup_alerts() {
    pthread_mutex_lock(&alerts_mutex);
    if (global_alerts_array) {
        json_decref(global_alerts_array);
        global_alerts_array = NULL;
    }
    pthread_mutex_unlock(&alerts_mutex);
}

/* ============================================================
 * FUNCIONES PRINCIPALES
 * ============================================================ */

/*
 * add_alert - Agrega una nueva alerta al sistema
 * 
 * Parámetros:
 *   type     - Tipo del evento: "archivos", "sistema", o "sesion"
 *   desc     - Descripción detallada de lo que ocurrió
 *   severity - Nivel de severidad: "LOW", "MEDIUM", o "HIGH"
 * 
 * Esta función es llamada desde diferentes partes del código:
 *   - Desde scanner.c cuando se detecta un hash malicioso
 *   - Desde http_server.c cuando se mata un proceso o se hace login
 *   - Desde http_server.c cuando se activa/desactiva el monitoreo
 */
void add_alert(const char *type, const char *desc, const char *severity) {
    /* Creamos un objeto JSON para esta alerta individual */
    json_t *alert = json_object();
    json_object_set_new(alert, "tipo", json_string(type));
    json_object_set_new(alert, "descripcion", json_string(desc));
    json_object_set_new(alert, "severidad", json_string(severity));
    
    /* 
     * Obtenemos la fecha y hora actual del sistema.
     * time() retorna los segundos desde el 1 de enero de 1970 (epoch).
     * localtime() convierte esos segundos a una estructura legible
     * con año, mes, día, hora, minuto y segundo.
     */
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%d-%02d-%02d %02d:%02d:%02d", 
             tm.tm_year + 1900,  /* tm_year cuenta desde 1900, por eso sumamos */
             tm.tm_mon + 1,      /* tm_mon va de 0 a 11, por eso sumamos 1 */
             tm.tm_mday, 
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    json_object_set_new(alert, "fecha", json_string(time_str));

    /* 
     * Insertamos la alerta en el array global.
     * Usamos mutex porque otros hilos podrían estar leyendo el array
     * al mismo tiempo (por ejemplo, el servidor HTTP respondiendo a /api/alerts).
     */
    pthread_mutex_lock(&alerts_mutex);

    /* Si el array no existe por alguna razón, lo creamos */
    if (!global_alerts_array) {
        global_alerts_array = json_array();
    }

    /* 
     * Insertamos la alerta en la posición 0 (al inicio del array).
     * Esto hace que las alertas más recientes aparezcan primero
     * en el dashboard, que es lo que pide el enunciado.
     */
    json_array_insert_new(global_alerts_array, 0, alert);
    
    /* 
     * Limitamos el array a un máximo de 100 alertas en memoria.
     * Si hay más de 100, eliminamos la más antigua (la última del array).
     */
    if (json_array_size(global_alerts_array) > 100) {
        json_array_remove(global_alerts_array, 100);
    }

    /* Guardamos el historial en el archivo JSON */
    save_alerts_db();

    pthread_mutex_unlock(&alerts_mutex);

    /* Escribimos en el log legible (fuera del mutex del array) */
    FILE *log = fopen("alertas_seguridad.log", "a");
    if (log) {
        fprintf(log, "[%s] ALERTA [%s]: %s | Origen: %s\n", time_str, severity, desc, type);
        fclose(log);
    }
}

/*
 * get_alerts_json - Obtiene todas las alertas en formato JSON string
 * 
 * Retorna:
 *   Un string con el array JSON de alertas (el caller debe hacer free()).
 *   Si no hay alertas, retorna "[]".
 * 
 * Esta función es llamada por el servidor HTTP cuando el frontend
 * solicita GET /api/alerts.
 */
char* get_alerts_json() {
    pthread_mutex_lock(&alerts_mutex);

    char *alerts_str = NULL;
    if (global_alerts_array) {
        /* json_dumps() convierte el array JSON a un string */
        alerts_str = json_dumps(global_alerts_array, JSON_COMPACT);
    } else {
        /* Si no hay array, retornamos un array vacío */
        alerts_str = strdup("[]");
    }

    pthread_mutex_unlock(&alerts_mutex);
    return alerts_str; /* IMPORTANTE: El que llame a esta función debe hacer free() del resultado */
}
