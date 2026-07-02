/*
 * globals.h - Archivo de cabecera principal del proyecto
 * 
 * Este archivo contiene todas las definiciones globales que se comparten
 * entre los diferentes módulos del programa (main, metrics, scanner, etc).
 * 
 * Aquí definimos:
 *   - Las constantes del sistema (puertos, rutas, tamaños máximos)
 *   - Las estructuras que usamos para comunicarnos con el kernel (syscalls)
 *   - Las estructuras para almacenar archivos escaneados y en cuarentena
 *   - Las variables globales que se comparten entre hilos (con extern)
 * 
 * IMPORTANTE: Usamos "extern" para declarar variables que están definidas
 * en otros archivos .c, así evitamos tener múltiples copias de la misma
 * variable en memoria.
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#ifndef GLOBALS_H
#define GLOBALS_H

/* Incluimos las librerías necesarias para nuestras estructuras */
#include <pthread.h>    /* Para pthread_mutex_t (control de concurrencia entre hilos) */
#include <jansson.h>    /* Para json_t (manejo de JSON en C) */
#include <sys/types.h>  /* Para pid_t (tipo de dato para PIDs de procesos) */

/* ============================================================
 * CONSTANTES DEL SISTEMA
 * Estas definen las rutas y configuraciones que usa el daemon
 * ============================================================ */
#define PROC_FILE "/proc/edr_alerts"      /* Ruta del archivo /proc que crea nuestro LKM (módulo del kernel) */
#define MONITOR_DIR "/home/sopes/monitor/" /* Directorio que vigila el LKM para detectar cambios en archivos */
#define JSON_FILE "blacklist.json"         /* Archivo con los hashes de amenazas conocidas (nuestra "base de datos") */
#define LOG_FILE "alertas_seguridad.log"   /* Archivo donde se registran las alertas de seguridad */
#define PORT 8080                          /* Puerto donde escucha nuestro servidor HTTP */
#define MAX_SCANNED_FILES 256              /* Máximo de archivos escaneados que almacenamos en memoria */
#define MAX_QUARANTINED 128                /* Máximo de archivos en cuarentena que recordamos */

/* ============================================================
 * ESTRUCTURAS DEL KERNEL
 * 
 * Estas estructuras deben ser IDÉNTICAS a las que definimos
 * dentro del código del kernel (en sys.c). Si no coinciden,
 * la comunicación entre el kernel y el espacio de usuario falla.
 * 
 * Las usamos cuando llamamos a las syscalls con la función syscall().
 * ============================================================ */

/* Estructura para la syscall 462 (sys_get_system_monitor)
 * Contiene las métricas del sistema que nos devuelve el kernel */
struct system_metrics {
    unsigned long memoria_usada;       /* RAM utilizada en bytes */
    unsigned long memoria_libre;       /* RAM disponible en bytes */
    unsigned long memoria_cache;       /* Memoria usada como caché de archivos */
    unsigned long swap_usada;          /* Espacio swap utilizado en bytes */
    unsigned long fallos_menores;      /* Page faults menores (la página estaba en RAM) */
    unsigned long fallos_mayores;      /* Page faults mayores (la página tuvo que leerse del disco) */
    unsigned long paginas_activas;     /* Páginas de memoria usadas recientemente */
    unsigned long paginas_inactivas;   /* Páginas de memoria que no se han usado recientemente */
};

/* Estructura para las syscalls 463 y 464 (lista de procesos / info de un proceso)
 * Contiene la información básica de un proceso del sistema */
struct process_info {
    pid_t pid;                         /* El identificador único del proceso */
    char name[16];                     /* Nombre del proceso (máximo 15 caracteres + null) */
    unsigned long memory_usage;        /* Uso de memoria en páginas (se convierte a MB en el frontend) */
};

/* ============================================================
 * ESTRUCTURA PARA ARCHIVOS ESCANEADOS
 * 
 * Cuando el LKM detecta que se creó o modificó un archivo
 * en el directorio monitoreado, calculamos su hash SHA-256
 * y lo comparamos con la blacklist. El resultado se guarda aquí.
 * ============================================================ */
typedef struct {
    char filename[256];       /* Nombre del archivo escaneado */
    char hash[65];            /* Hash SHA-256 del archivo (64 caracteres hex + null) */
    int is_malicious;         /* 0 = archivo limpio (benigno), 1 = archivo infectado */
    char threat_name[128];    /* Nombre de la amenaza si fue detectada (ej: "Simulated.Ransomware") */
    char description[256];    /* Descripción de la amenaza encontrada */
    char timestamp[64];       /* Fecha y hora en que se escaneó el archivo */
} scanned_file_t;

/* ============================================================
 * ESTRUCTURA PARA ARCHIVOS EN CUARENTENA
 * 
 * Cuando el administrador pone un archivo en cuarentena,
 * le quitamos todos los permisos (chmod 0000) y lo registramos aquí.
 * ============================================================ */
typedef struct {
    char filename[256];       /* Nombre del archivo en cuarentena */
    char timestamp[64];       /* Fecha y hora en que se puso en cuarentena */
} quarantined_file_t;

/* ============================================================
 * VARIABLES GLOBALES COMPARTIDAS ENTRE HILOS
 * 
 * Usamos "extern" porque las variables reales están definidas
 * en otros archivos .c (alerts.c y scanner.c). Aquí solo las
 * declaramos para que todos los módulos puedan acceder a ellas.
 * 
 * Los mutexes son necesarios para proteger estas variables
 * cuando múltiples hilos intentan leer/escribir al mismo tiempo.
 * Sin mutexes tendríamos condiciones de carrera (race conditions).
 * ============================================================ */

/* Mutexes para sincronización entre hilos */
extern pthread_mutex_t metrics_mutex;  /* Protege el JSON de métricas */
extern pthread_mutex_t alerts_mutex;   /* Protege el array de alertas */
extern pthread_mutex_t files_mutex;    /* Protege las listas de archivos escaneados/cuarentena */

/* Buffer global donde se almacena el JSON de métricas más reciente */
extern char global_metrics_json[16384];

/* Array de alertas en formato JSON (las que se envían al frontend) */
extern json_t *global_alerts_array;

/* Arrays globales de archivos escaneados y en cuarentena */
extern scanned_file_t scanned_files[MAX_SCANNED_FILES];
extern int scanned_files_count;

extern quarantined_file_t quarantined_files[MAX_QUARANTINED];
extern int quarantined_count;

/* Variables de control (toggle) para activar/desactivar funciones
 * Usamos "volatile" porque estas variables pueden ser modificadas
 * desde diferentes hilos y necesitamos que el compilador NO las optimice
 * (es decir, que siempre lea el valor actual de la memoria). */
extern volatile int scan_enabled;     /* 1 = escaneo de archivos activo, 0 = pausado */
extern volatile int metrics_enabled;  /* 1 = monitoreo de métricas activo, 0 = pausado */

#endif /* GLOBALS_H */
