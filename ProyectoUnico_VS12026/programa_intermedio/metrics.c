/*
 * metrics.c - Hilo de monitoreo de métricas del sistema
 * 
 * Este módulo contiene el hilo que se encarga de obtener las métricas
 * del sistema operativo en tiempo real usando nuestra syscall personalizada
 * (número 462: sys_get_system_monitor).
 * 
 * Cada 2 segundos, este hilo:
 *   1. Llama a la syscall 462 para obtener las métricas del kernel
 *   2. Convierte los datos a formato JSON usando la librería jansson
 *   3. Guarda el JSON en la variable global "global_metrics_json"
 *      (protegida con mutex para evitar problemas de concurrencia)
 * 
 * El servidor HTTP luego lee esa variable global cuando el frontend
 * solicita GET /api/metrics.
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#include "metrics.h"
#include "globals.h"
#include <unistd.h>      /* Para sleep() */
#include <string.h>      /* Para strncpy() */
#include <stdio.h>       /* Para printf() */
#include <sys/syscall.h> /* Para syscall() - nos permite llamar a nuestras syscalls personalizadas */

/*
 * thread_monitoreo - Función principal del hilo de monitoreo
 * 
 * Esta función se ejecuta como un hilo independiente (creado en main.c).
 * Tiene un bucle infinito que cada 2 segundos obtiene las métricas
 * del kernel y las convierte a JSON para que el frontend las consuma.
 * 
 * El parámetro "arg" no se usa pero es requerido por la interfaz
 * de pthread_create (que espera una función void* -> void*).
 */
void *thread_monitoreo(void *arg) {
    /* 
     * Declaramos la estructura donde el kernel depositará las métricas.
     * Esta estructura debe coincidir exactamente con la que definimos
     * en el código del kernel (sys.c) y en globals.h.
     */
    struct system_metrics metrics;

    /* Bucle infinito: el hilo corre hasta que se termine el programa */
    while(1) {
        /* 
         * Verificamos si el monitoreo de métricas está activado.
         * El administrador puede desactivarlo desde el dashboard
         * usando el toggle de métricas (GET /api/toggle_metrics).
         * Si está desactivado, simplemente dormimos y no consumimos
         * recursos del kernel con llamadas a la syscall.
         */
        if (!metrics_enabled) {
            sleep(1);
            continue; /* Volvemos al inicio del while sin hacer nada */
        }

        /* 
         * Llamamos a nuestra syscall personalizada número 462.
         * La función syscall() es la forma de invocar syscalls
         * directamente desde espacio de usuario.
         * 
         * Parámetros:
         *   462       - Número de la syscall (el que registramos en syscall_64.tbl)
         *   &metrics  - Puntero a la estructura donde el kernel escribirá los datos
         * 
         * Retorna 0 si fue exitoso, o un número negativo si hubo error.
         */
        long int status1 = syscall(462, &metrics);
        
        /* Solo procesamos los datos si la syscall fue exitosa */
        if (status1 == 0) {
            /* 
             * Creamos un objeto JSON con la librería jansson.
             * json_object() crea un JSON vacío: {}
             * json_object_set_new() agrega un campo al objeto JSON.
             * json_integer() crea un valor numérico JSON.
             * 
             * El resultado será algo como:
             * {
             *   "memoria_usada": 1234567890,
             *   "memoria_libre": 987654321,
             *   ...
             * }
             */
            json_t *root = json_object();
            json_object_set_new(root, "memoria_usada", json_integer(metrics.memoria_usada));
            json_object_set_new(root, "memoria_libre", json_integer(metrics.memoria_libre));
            json_object_set_new(root, "memoria_cache", json_integer(metrics.memoria_cache));
            json_object_set_new(root, "swap_usada", json_integer(metrics.swap_usada));
            json_object_set_new(root, "fallos_menores", json_integer(metrics.fallos_menores));
            json_object_set_new(root, "fallos_mayores", json_integer(metrics.fallos_mayores));
            json_object_set_new(root, "paginas_activas", json_integer(metrics.paginas_activas));
            json_object_set_new(root, "paginas_inactivas", json_integer(metrics.paginas_inactivas));

            /* 
             * json_dumps() convierte el objeto JSON a un string.
             * JSON_COMPACT hace que no tenga espacios ni saltos de línea
             * (más eficiente para enviar por red).
             */
            char *json_str = json_dumps(root, JSON_COMPACT);
            
            if (json_str) {
                /* 
                 * Aquí protegemos la escritura de la variable global con un mutex.
                 * 
                 * ¿Por qué? Porque el hilo del servidor HTTP podría estar LEYENDO
                 * global_metrics_json al mismo tiempo que nosotros estamos ESCRIBIENDO.
                 * Sin el mutex, el servidor podría leer un JSON a medias (corrupto).
                 * 
                 * pthread_mutex_lock()   -> Bloquea: "soy el único que puede acceder"
                 * ... operaciones con la variable compartida ...
                 * pthread_mutex_unlock() -> Libera: "ya terminé, los demás pueden acceder"
                 */
                pthread_mutex_lock(&metrics_mutex);
                strncpy(global_metrics_json, json_str, sizeof(global_metrics_json) - 1);
                global_metrics_json[sizeof(global_metrics_json) - 1] = '\0'; /* Aseguramos terminación nula */
                pthread_mutex_unlock(&metrics_mutex);

                free(json_str); /* Liberamos la memoria que json_dumps() reservó */
            }

            /* Liberamos el objeto JSON (jansson maneja su propia memoria) */
            json_decref(root);
        }

        /* 
         * Dormimos 2 segundos antes de la siguiente lectura.
         * Esto evita que bombardeemos al kernel con syscalls
         * y le da tiempo al frontend de procesar los datos.
         */
        sleep(1); 
    }

    return NULL; /* Nunca se alcanza, pero es buena práctica retornar */
}
