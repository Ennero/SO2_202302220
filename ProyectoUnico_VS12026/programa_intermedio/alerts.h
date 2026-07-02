/*
 * alerts.h - Cabecera del módulo de alertas de seguridad
 * Declara las funciones para inicializar, agregar y consultar alertas.
 */
#ifndef ALERTS_H
#define ALERTS_H

/* Inicializa el array JSON de alertas (llamar una vez al inicio) */
void init_alerts();

/* Libera la memoria del array de alertas (llamar al finalizar) */
void cleanup_alerts();

/* Agrega una nueva alerta. type="archivos|sistema|sesion", severity="LOW|MEDIUM|HIGH" */
void add_alert(const char *type, const char *desc, const char *severity);

/* Retorna un string JSON con todas las alertas (el caller debe hacer free) */
char* get_alerts_json();

#endif /* ALERTS_H */
