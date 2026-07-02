/*
 * scanner.h - Cabecera del módulo de escaneo de archivos
 * Declara la función del hilo que escanea archivos del directorio monitoreado.
 */
#ifndef SCANNER_H
#define SCANNER_H

/* Función del hilo de escaneo (se pasa a pthread_create en main.c) */
void *thread_archivos(void *arg);

#endif /* SCANNER_H */
