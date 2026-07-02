/*
 * metrics.h - Cabecera del módulo de monitoreo de métricas
 * Declara la función del hilo que obtiene métricas del kernel via syscalls.
 */
#ifndef METRICS_H
#define METRICS_H

/* Función del hilo de monitoreo (se pasa a pthread_create en main.c) */
void *thread_monitoreo(void *arg);

#endif /* METRICS_H */
