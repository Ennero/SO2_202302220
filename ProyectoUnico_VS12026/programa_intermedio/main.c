/*
 * main.c - Punto de entrada del daemon EDR Híbrido
 * 
 * Este es el archivo principal del programa intermedio.
 * Su función es inicializar el sistema de alertas y crear
 * los 3 hilos que conforman la arquitectura concurrente del daemon:
 * 
 *   Hilo 1 (thread_monitoreo):    Lee métricas del kernel usando syscalls
 *   Hilo 2 (thread_archivos):     Escanea archivos detectados por el LKM
 *   Hilo 3 (thread_servidor_http): Sirve los datos al frontend via HTTP
 * 
 * NOTA: Este programa DEBE ejecutarse con sudo porque:
 *   - PAM necesita permisos de root para autenticar usuarios
 *   - Las syscalls personalizadas requieren acceso al kernel
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#include "globals.h"        /* Constantes, estructuras y variables globales */
#include "alerts.h"         /* Funciones del sistema de alertas */
#include "metrics.h"        /* Hilo de monitoreo de métricas del sistema */
#include "scanner.h"        /* Hilo de escaneo de archivos */
#include "http_server.h"    /* Hilo del servidor HTTP */
#include <stdio.h>          /* Para printf */
#include <stdlib.h>         /* Para funciones de uso general */

int main() {
    /* 
     * Declaramos las variables para almacenar los identificadores de los hilos.
     * pthread_t es el tipo de dato que POSIX usa para identificar un hilo.
     * Necesitamos estos IDs para poder hacer pthread_join() después.
     */
    pthread_t tid1, tid2, tid3;
    
    /* 
     * Inicializamos el sistema de alertas antes de crear los hilos.
     * Esto crea el array JSON donde se almacenarán las alertas
     * y prepara los mutexes necesarios.
     */
    init_alerts();

    printf("Iniciando Daemon EDR Híbrido...\n");

    /* 
     * Creamos los 3 hilos del daemon usando pthread_create.
     * 
     * Parámetros de pthread_create:
     *   1. &tid  - Puntero donde se guardará el ID del hilo creado
     *   2. NULL  - Usamos los atributos por defecto del hilo
     *   3. func  - Función que ejecutará el hilo (debe recibir void* y retornar void*)
     *   4. NULL  - Argumento que se le pasa a la función (no necesitamos ninguno)
     * 
     * Cada hilo se ejecuta de forma independiente y concurrente.
     * Todos comparten el mismo espacio de memoria del proceso,
     * por eso necesitamos mutexes para proteger las variables globales.
     */
    pthread_create(&tid1, NULL, thread_monitoreo, NULL);       /* Hilo 1: Métricas del kernel */
    pthread_create(&tid2, NULL, thread_archivos, NULL);        /* Hilo 2: Escaneo de archivos */
    pthread_create(&tid3, NULL, thread_servidor_http, NULL);   /* Hilo 3: Servidor HTTP */

    /* 
     * pthread_join() bloquea el hilo principal (main) hasta que
     * el hilo indicado termine su ejecución.
     * 
     * Como nuestros hilos tienen bucles infinitos (while(1)),
     * en la práctica main nunca termina. Esto mantiene el daemon
     * ejecutándose continuamente hasta que el usuario presione Ctrl+C.
     */
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    pthread_join(tid3, NULL);

    /* 
     * Si llegáramos aquí (lo cual no sucede normalmente),
     * liberaríamos los recursos del sistema de alertas.
     */
    cleanup_alerts();
    return 0;
}
