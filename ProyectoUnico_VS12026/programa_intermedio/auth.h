/*
 * auth.h - Cabecera del módulo de autenticación PAM
 * 
 * Declara las funciones de autenticación y gestión de usuarios
 * que son utilizadas por el servidor HTTP para verificar credenciales
 * y crear nuevos usuarios desde el panel de administración.
 */

#ifndef AUTH_H
#define AUTH_H

/* Autentica un usuario contra PAM. Retorna 1 si es válido, 0 si no. */
int authenticate_user(const char *username, const char *password);

/* Obtiene el rol del usuario: 2=admin, 1=common, 0=sin grupo */
int get_user_role(const char *username);

/* Crea un nuevo usuario en el sistema. Retorna 0 si fue exitoso. */
int create_system_user(const char *username, const char *password, const char *role);

#endif /* AUTH_H */
