/*
 * http_server.h - Cabecera del módulo del servidor HTTP
 * Declara la función del hilo que escucha peticiones HTTP del frontend.
 */
#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

/* Función del hilo del servidor HTTP (se pasa a pthread_create en main.c) */
void *thread_servidor_http(void *arg);

#endif /* HTTP_SERVER_H */
