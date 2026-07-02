/*
 * auth.c - Módulo de autenticación con PAM (Pluggable Authentication Modules)
 * 
 * Este módulo se encarga de autenticar a los usuarios del sistema
 * usando PAM, que es el sistema de autenticación estándar de Linux.
 * 
 * Funciones principales:
 *   - authenticate_user(): Verifica si el usuario/contraseña son válidos
 *   - get_user_role():     Determina si el usuario es admin o usuario común
 *   - create_system_user(): Crea un nuevo usuario en el sistema Linux
 * 
 * ¿Qué es PAM?
 * PAM es un conjunto de librerías que Linux usa para verificar credenciales.
 * En lugar de que cada programa implemente su propia verificación de contraseñas,
 * PAM centraliza esto. Así, nuestro programa puede verificar si un usuario
 * existe y si su contraseña es correcta usando las mismas credenciales
 * que se usan para hacer login en la terminal.
 * 
 * IMPORTANTE: El programa debe ejecutarse con sudo porque PAM
 * necesita permisos de root para leer /etc/shadow (donde se guardan
 * las contraseñas hasheadas del sistema).
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#include "auth.h"
#include <security/pam_appl.h>  /* Librería de PAM para autenticación */
#include <stdlib.h>             /* Para calloc(), free() */
#include <string.h>             /* Para strdup(), strstr() */
#include <stdio.h>              /* Para printf(), snprintf(), popen(), pclose(), fgets() */

/* ============================================================
 * FUNCIÓN DE CONVERSACIÓN PAM (callback)
 * 
 * PAM funciona con un patrón de "conversación": cuando PAM necesita
 * la contraseña del usuario, llama a esta función callback.
 * 
 * Es como si PAM nos "preguntara": "Dame la contraseña" y nosotros
 * respondemos con la contraseña que el usuario ingresó en el frontend.
 * 
 * Parámetros:
 *   num_msg      - Número de mensajes que PAM nos envía
 *   msg          - Array de mensajes de PAM (preguntas)
 *   resp         - Array de respuestas que debemos llenar
 *   appdata_ptr  - Datos de la aplicación (aquí pasamos la contraseña)
 * ============================================================ */
static int pam_conversation(int num_msg, const struct pam_message **msg, 
                            struct pam_response **resp, void *appdata_ptr) {
    /* Obtenemos la contraseña que guardamos cuando creamos la conversación */
    const char *password = (const char *)appdata_ptr;
    
    /* 
     * Reservamos memoria para las respuestas.
     * calloc() es como malloc() pero inicializa la memoria a cero.
     * Necesitamos una respuesta por cada mensaje que PAM nos envíe.
     */
    struct pam_response *reply = calloc(num_msg, sizeof(struct pam_response));
    if (!reply) return PAM_BUF_ERR; /* Error si no hay memoria */

    /* Respondemos a cada mensaje de PAM */
    for (int i = 0; i < num_msg; i++) {
        /* PAM_PROMPT_ECHO_OFF = "Dame la contraseña (sin mostrarla)"
         * PAM_PROMPT_ECHO_ON  = "Dame el usuario (mostrándolo)" */
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || 
            msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            /* strdup() crea una copia de la contraseña en memoria nueva.
             * PAM se encargará de liberar esta memoria después. */
            reply[i].resp = strdup(password);
            reply[i].resp_retcode = 0;
        }
    }
    *resp = reply;
    return PAM_SUCCESS;
}

/* ============================================================
 * authenticate_user - Verifica las credenciales de un usuario
 * 
 * Parámetros:
 *   username - Nombre de usuario del sistema Linux
 *   password - Contraseña del usuario
 * 
 * Retorna:
 *   1 si la autenticación fue exitosa
 *   0 si falló (usuario no existe o contraseña incorrecta)
 * 
 * Ejemplo de uso:
 *   if (authenticate_user("sopes", "mipassword")) {
 *       printf("Login exitoso!\n");
 *   }
 * ============================================================ */
int authenticate_user(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;  /* Handle de la sesión PAM */
    int retval;

    /* 
     * Creamos la estructura de conversación que PAM usará
     * para pedirnos la contraseña. Le pasamos la contraseña
     * como appdata_ptr para que nuestra función callback la use.
     */
    struct pam_conv conv = { pam_conversation, (void *)password };

    /* 
     * pam_start() inicia una sesión PAM.
     * "su" es el servicio PAM que usamos (el mismo que usa el comando 'su').
     * Podríamos usar "login" u otro servicio, pero "su" funciona bien.
     */
    retval = pam_start("su", username, &conv, &pamh);

    /* Si pam_start fue exitoso, intentamos autenticar */
    if (retval == PAM_SUCCESS) {
        /* 
         * pam_authenticate() es la función que realmente verifica
         * si la contraseña es correcta. Internamente, PAM:
         * 1. Busca al usuario en /etc/passwd
         * 2. Lee el hash de su contraseña de /etc/shadow
         * 3. Hashea la contraseña que proporcionamos
         * 4. Compara ambos hashes
         */
        retval = pam_authenticate(pamh, 0);
    }

    /* Cerramos la sesión PAM y liberamos recursos */
    pam_end(pamh, retval);

    /* Retornamos 1 si fue exitoso, 0 si falló */
    return (retval == PAM_SUCCESS);
}

/* ============================================================
 * get_user_role - Determina el rol del usuario según sus grupos
 * 
 * Parámetros:
 *   username - Nombre del usuario del sistema Linux
 * 
 * Retorna:
 *   2 si pertenece al grupo "admin_user"  (administrador)
 *   1 si pertenece al grupo "common_user" (usuario estándar)
 *   0 si no pertenece a ninguno de los dos grupos
 * 
 * NOTA: Si un usuario pertenece a ambos grupos, se le asigna
 * el rol de administrador (se verifica admin_user primero).
 * ============================================================ */
int get_user_role(const char *username) {
    char cmd[256];
    char output[512];

    /* 
     * Usamos el comando "id -nG" para obtener los nombres de todos
     * los grupos a los que pertenece el usuario.
     * 
     * Ejemplo de salida: "sopes adm cdrom sudo admin_user"
     * 
     * popen() ejecuta un comando del sistema y nos devuelve un
     * FILE* para leer su salida, como si fuera un archivo.
     */
    snprintf(cmd, sizeof(cmd), "id -nG %s 2>/dev/null", username);
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0; /* Si falla, retornamos 0 (sin grupo) */
    
    int role = 0;
    /* Leemos la salida del comando */
    if (fgets(output, sizeof(output), fp) != NULL) {
        /* strstr() busca una subcadena dentro de otra.
         * Si encuentra "admin_user" en la lista de grupos -> admin */
        if (strstr(output, "admin_user")) role = 2; 
        /* Si no es admin, verificamos si es common_user */
        else if (strstr(output, "common_user")) role = 1;
    }
    pclose(fp); /* Cerramos el proceso del comando */
    return role; 
}

/* ============================================================
 * create_system_user - Crea un nuevo usuario en el sistema Linux
 * 
 * Parámetros:
 *   username - Nombre para el nuevo usuario
 *   password - Contraseña para el nuevo usuario
 *   role     - "admin_user" o "common_user"
 * 
 * Retorna:
 *   0 si se creó exitosamente
 *   1 si el usuario ya existe
 *  -1 si hubo un error al crear el usuario
 *  -2 si hubo un error al asignar la contraseña
 *  -3 si hubo un error al agregar el usuario al grupo
 * 
 * NOTA: Esta función requiere que el daemon se ejecute con sudo.
 * Internamente ejecuta los comandos: useradd, chpasswd y usermod.
 * ============================================================ */
int create_system_user(const char *username, const char *password, const char *role) {
    char cmd[512];
    int ret;

    /* 
     * Paso 1: Verificar si el usuario ya existe.
     * Usamos "id" para consultar si el usuario existe en el sistema.
     * Si "id" retorna 0, el usuario ya existe.
     */
    snprintf(cmd, sizeof(cmd), "id %s >/dev/null 2>&1", username);
    if (system(cmd) == 0) {
        return 1; /* El usuario ya existe */
    }

    /* 
     * Paso 2: Crear el usuario con useradd.
     * -m  = Crea el directorio home del usuario (/home/username)
     * -s  = Asigna /bin/bash como shell por defecto
     */
    snprintf(cmd, sizeof(cmd), "useradd -m -s /bin/bash %s 2>/dev/null", username);
    ret = system(cmd);
    if (ret != 0) {
        return -1; /* Error al crear el usuario */
    }

    /* 
     * Paso 3: Asignar la contraseña usando chpasswd.
     * chpasswd lee pares "usuario:contraseña" desde stdin.
     * Usamos echo y pipe (|) para pasarle los datos.
     */
    snprintf(cmd, sizeof(cmd), "echo '%s:%s' | chpasswd 2>/dev/null", username, password);
    ret = system(cmd);
    if (ret != 0) {
        return -2; /* Error al asignar la contraseña */
    }

    /* 
     * Paso 4: Agregar al usuario al grupo correspondiente.
     * usermod -aG agrega al usuario a un grupo sin quitarlo de los que ya tiene.
     * El grupo ("admin_user" o "common_user") debe existir previamente.
     */
    snprintf(cmd, sizeof(cmd), "usermod -aG %s %s 2>/dev/null", role, username);
    ret = system(cmd);
    if (ret != 0) {
        return -3; /* Error al agregar al grupo */
    }

    return 0; /* Éxito: el usuario fue creado correctamente */
}
