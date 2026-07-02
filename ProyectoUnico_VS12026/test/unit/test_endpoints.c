#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <jansson.h>

#define BASE_HOST "127.0.0.1"
#define BASE_PORT 8080

// Función para enviar solicitud HTTP cruda a través de sockets TCP
char* send_http_request(const char *method, const char *path, const char *payload, int *status_code) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(BASE_PORT);
    inet_pton(AF_INET, BASE_HOST, &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(sock);
        return NULL;
    }

    char request[4096];
    if (strcmp(method, "POST") == 0 && payload != NULL) {
        snprintf(request, sizeof(request),
                 "POST %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n\r\n"
                 "%s", path, BASE_HOST, strlen(payload), payload);
    } else {
        snprintf(request, sizeof(request),
                 "GET %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Connection: close\r\n\r\n", path, BASE_HOST);
    }

    send(sock, request, strlen(request), 0);

    // Leer respuesta completa
    char *response = malloc(32768);
    if (!response) {
        close(sock);
        return NULL;
    }
    memset(response, 0, 32768);

    int total_read = 0;
    int bytes;
    while ((bytes = read(sock, response + total_read, 32768 - total_read - 1)) > 0) {
        total_read += bytes;
    }
    close(sock);

    // Extraer código de estado HTTP (ej: "HTTP/1.1 200 OK")
    if (sscanf(response, "HTTP/1.1 %d", status_code) != 1) {
        *status_code = 0;
    }

    // Encontrar inicio del cuerpo (body) de la respuesta HTTP
    char *body_start = strstr(response, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        char *body_copy = strdup(body_start);
        free(response);
        return body_copy;
    }

    free(response);
    return NULL;
}

void test_get(const char *path, const char *description) {
    int status;
    char *body = send_http_request("GET", path, NULL, &status);
    
    if (body && status == 200) {
        json_error_t error;
        json_t *root = json_loads(body, 0, &error);
        if (root) {
            printf("- [x] **%s** (`GET %s`): ✅ EXITO (Status: %d, JSON Valido)\n", description, path, status);
            json_decref(root);
        } else {
            printf("- [ ] **%s** (`GET %s`): ❌ FALLO (Status: %d, No es JSON)\n", description, path, status);
        }
    } else if (status == 404 && strstr(path, "999999") != NULL) {
        // Excepción para el caso de prueba negativo esperado (proceso inexistente)
        printf("- [x] **%s** (`GET %s`): ✅ EXITO (Status: %d - Comportamiento esperado)\n", description, path, status);
    } else {
        printf("- [ ] **%s** (`GET %s`): ❌ FALLO (Status: %d)\n", description, path, status);
    }
    
    if (body) free(body);
}

void test_post(const char *path, const char *payload, const char *description) {
    int status;
    char *body = send_http_request("POST", path, payload, &status);
    
    if (status == 200) {
        printf("- [x] **%s** (`POST %s`): ✅ EXITO (Status: %d)\n", description, path, status);
    } else if (status == 400 && strstr(body, "ya existe") != NULL) {
        printf("- [x] **%s** (`POST %s`): ⚠️ ADVERTENCIA (Usuario ya existe, Status: %d)\n", description, path, status);
    } else {
        printf("- [ ] **%s** (`POST %s`): ❌ FALLO (Status: %d)\n", description, path, status);
    }
    
    if (body) free(body);
}

int main() {
    printf("# Reporte de Pruebas Unitarias del Backend (EDR) en C\n\n");
    
    printf("## 1. Autenticacion y Gestion de Usuarios\n");
    test_get("/api/login?user=sopes&pass=1", "Login Administrador (sopes)");
    test_post("/api/create_user", "{\"username\":\"viewer\",\"password\":\"viewer\",\"role\":\"common_user\"}", "Creacion de Usuario ('viewer')");
    test_get("/api/login?user=viewer&pass=viewer", "Login Usuario Comun (viewer)");
    test_get("/api/login?user=sopes&pass=wrongpass", "Login Fallido (contrasena incorrecta)");

    printf("\n## 2. Metricas y Procesos (Kernel)\n");
    test_get("/api/metrics", "Obtener Metricas del Sistema (Syscall 462)");
    test_get("/api/processes?page=1", "Obtener Lista Paginada de Procesos (Syscall 463)");
    test_get("/api/top_processes", "Obtener Top 20 Procesos por Memoria");
    test_get("/api/process_info?pid=1", "Obtener Informacion del Proceso init (Syscall 464)");
    test_get("/api/process_info?pid=999999", "Obtener Informacion de Proceso Inexistente (Error 404 esperado)");

    printf("\n## 3. Seguridad y Monitoreo\n");
    test_get("/api/alerts", "Listar Alertas de Seguridad");
    test_get("/api/files", "Listar Archivos Escaneados");
    test_get("/api/status", "Obtener Estado de Monitores");
    test_get("/api/toggle_scan", "Activar/Desactivar Escaneo de Archivos");
    test_get("/api/toggle_metrics", "Activar/Desactivar Monitoreo de Metricas");

    printf("\nReporte estructurado completado.\n");
    return 0;
}
