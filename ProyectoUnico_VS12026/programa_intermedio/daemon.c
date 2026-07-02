#include <stdio.h>
#include <security/pam_appl.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <jansson.h>
#include <time.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>   // Para sys_kill
#include <sys/stat.h> // Para cambiar permisos (cuarentena)

#define PROC_FILE "/proc/edr_alerts"
#define MONITOR_DIR "/home/sopes/monitor/"
#define JSON_FILE "blacklist.json"
#define LOG_FILE "alertas_seguridad.log"
#define PORT 8080

// --- ESTRUCTURAS DEL KERNEL ---
struct system_metrics {
    unsigned long memoria_usada;
    unsigned long memoria_libre;
    unsigned long memoria_cache;
    unsigned long swap_usada;
    unsigned long fallos_menores;
    unsigned long fallos_mayores;
    unsigned long paginas_activas;
    unsigned long paginas_inactivas;
};

struct process_info {
    pid_t pid;
    char name[16];
    unsigned long memory_usage;
};

// --- VARIABLES GLOBALES Y MUTEX ---
pthread_mutex_t json_mutex = PTHREAD_MUTEX_INITIALIZER;
char global_metrics_json[16384] = "{}";
json_t *global_alerts_array; // Arreglo para almacenar el historial de alertas

// --- SISTEMA DE ALERTAS ---
void add_alert(const char *type, const char *desc, const char *severity) {
    pthread_mutex_lock(&json_mutex);
    
    json_t *alert = json_object();
    json_object_set_new(alert, "tipo", json_string(type));
    json_object_set_new(alert, "descripcion", json_string(desc));
    json_object_set_new(alert, "severidad", json_string(severity));
    
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%d-%02d-%02d %02d:%02d:%02d", 
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, 
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    json_object_set_new(alert, "fecha", json_string(time_str));

    // Insertar en la posición 0 (las más recientes primero)
    json_array_insert_new(global_alerts_array, 0, alert);
    
    // Mantener un máximo de 50 alertas en memoria
    if (json_array_size(global_alerts_array) > 50) {
        json_array_remove(global_alerts_array, 50);
    }
    
    pthread_mutex_unlock(&json_mutex);
}

// --- LÓGICA DE AUTENTICACIÓN PAM ---
struct pam_response *reply;

int pam_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    *resp = reply;
    return PAM_SUCCESS;
}

int authenticate_user(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    int retval;
    struct pam_conv conv = { pam_conversation, NULL };

    reply = (struct pam_response *)malloc(sizeof(struct pam_response));
    reply[0].resp = strdup(password);
    reply[0].resp_retcode = 0;

    retval = pam_start("su", username, &conv, &pamh);
    if (retval == PAM_SUCCESS) {
        retval = pam_authenticate(pamh, 0);
    }
    pam_end(pamh, retval);
    free(reply[0].resp);
    free(reply);

    return (retval == PAM_SUCCESS);
}

int get_user_role(const char *username) {
    char cmd[256];
    char output[512];
    snprintf(cmd, sizeof(cmd), "id -nG %s 2>/dev/null", username);
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    
    if (fgets(output, sizeof(output), fp) != NULL) {
        pclose(fp);
        if (strstr(output, "admin_user")) return 2; 
        if (strstr(output, "common_user")) return 1;
    } else {
        pclose(fp);
    }
    return 0; 
}

// --- LÓGICA DE ESCANEO DE ARCHIVOS ---
int calculate_sha256(const char *filepath, char *output_buffer) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { fclose(file); return 0; }
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    unsigned char buffer[8192];
    size_t bytes_read;
    EVP_DigestInit_ex(mdctx, md, NULL);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }
    fclose(file);
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(output_buffer + (i * 2), "%02x", hash[i]);
    }
    output_buffer[64] = '\0';
    return 1;
}

int check_blacklist(const char *hash_calculado, char *desc_out) {
    json_error_t error;
    json_t *root = json_load_file(JSON_FILE, 0, &error);
    if (!root) return 0;
    const char *key;
    json_t *value;
    int found = 0;
    json_object_foreach(root, key, value) {
        json_t *hash_json = json_object_get(value, "hash");
        json_t *desc_json = json_object_get(value, "descripcion");
        if (json_is_string(hash_json)) {
            const char *hash_str = json_string_value(hash_json);
            if (strcasecmp(hash_str, hash_calculado) == 0) {
                found = 1;
                if (json_is_string(desc_json)) {
                    strcpy(desc_out, json_string_value(desc_json));
                } else {
                    strcpy(desc_out, "Amenaza identificada");
                }
                break;
            }
        }
    }
    json_decref(root);
    return found;
}

void write_security_log(const char *filename, const char *hash_str, const char *threat_desc) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) return;
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    fprintf(log, "[%d-%02d-%02d %02d:%02d:%02d] ALERTA: %s | Archivo: %s | Hash: %s\n", 
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, 
            tm.tm_hour, tm.tm_min, tm.tm_sec, threat_desc, filename, hash_str);
    fclose(log);
}

void process_alert(const char *filename) {
    char full_path[512];
    char hash_str[65];
    char threat_desc[256];

    snprintf(full_path, sizeof(full_path), "%s%s", MONITOR_DIR, filename);

    if (calculate_sha256(full_path, hash_str)) {
        if (check_blacklist(hash_str, threat_desc)) {
            write_security_log(filename, hash_str, threat_desc);
            printf("[Hilo EDR] ¡AMENAZA DETECTADA! -> %s | %s\n", filename, threat_desc);
            add_alert("archivos", "Hash malicioso detectado", "HIGH"); // Alerta generada
        } else {
            printf("[Hilo EDR] Archivo %s escaneado. Hash limpio.\n", filename);
            add_alert("archivos", "Archivo creado/modificado", "LOW"); // Alerta generada
        }
    }
}

// --- HILO 1: MONITOREO Y JSON ---
void *thread_monitoreo(void *arg) {
    struct system_metrics metrics;
    struct process_info procs[20]; 

    while(1) {
        long int status1 = syscall(462, &metrics);
        long int status2 = syscall(463, procs, 20); 
        
        if (status1 == 0) {
            json_t *root = json_object();
            json_object_set_new(root, "memoria_usada", json_integer(metrics.memoria_usada));
            json_object_set_new(root, "memoria_libre", json_integer(metrics.memoria_libre));
            json_object_set_new(root, "memoria_cache", json_integer(metrics.memoria_cache));
            json_object_set_new(root, "swap_usada", json_integer(metrics.swap_usada));
            json_object_set_new(root, "fallos_menores", json_integer(metrics.fallos_menores));
            json_object_set_new(root, "fallos_mayores", json_integer(metrics.fallos_mayores));

            if (status2 > 0) {
                json_t *json_procs = json_array();
                for (int i = 0; i < status2; i++) {
                    json_t *proc_obj = json_object();
                    json_object_set_new(proc_obj, "pid", json_integer(procs[i].pid));
                    json_object_set_new(proc_obj, "name", json_string(procs[i].name));
                    json_object_set_new(proc_obj, "memory_usage", json_integer(procs[i].memory_usage));
                    json_array_append_new(json_procs, proc_obj);
                }
                json_object_set_new(root, "procesos", json_procs);
            }

            char *json_str = json_dumps(root, JSON_COMPACT);
            
            pthread_mutex_lock(&json_mutex);
            strncpy(global_metrics_json, json_str, sizeof(global_metrics_json) - 1);
            pthread_mutex_unlock(&json_mutex);
            
            free(json_str);
            json_decref(root);
        }
        sleep(2); 
    }
    return NULL;
}

// --- HILO 2: ESCANEO DE EVENTOS ---
void *thread_archivos(void *arg) {
    char buffer[256];
    while(1) {
        FILE *f = fopen(PROC_FILE, "r");
        if (f) {
            if (fgets(buffer, sizeof(buffer), f) != NULL) {
                buffer[strcspn(buffer, "\n")] = 0; 
                if (strlen(buffer) > 0) {
                    process_alert(buffer);
                }
            }
            fclose(f);
        }
        sleep(2);
    }
    return NULL;
}

// --- HILO 3: SERVIDOR HTTP ---
void *thread_servidor_http(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Fallo en socket"); exit(EXIT_FAILURE);
    }
    
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Fallo en bind"); exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("Fallo en listen"); exit(EXIT_FAILURE);
    }

    printf("[Servidor HTTP] Escuchando en http://localhost:%d\n", PORT);

    while(1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            continue;
        }
        
        char buffer[1024] = {0};
        read(new_socket, buffer, 1024);
        
        // 1. OBTENER MÉTRICAS DEL SISTEMA
        if (strncmp(buffer, "GET /api/metrics", 16) == 0) {
            char response[18000];
            pthread_mutex_lock(&json_mutex);
            snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n%s", global_metrics_json);
            pthread_mutex_unlock(&json_mutex);
            write(new_socket, response, strlen(response));
        } 
        
        // 2. INICIO DE SESIÓN (PAM)
        else if (strncmp(buffer, "GET /api/login", 14) == 0) {
            char user[50] = {0};
            char pass[50] = {0};
            sscanf(buffer, "GET /api/login?user=%49[^&]&pass=%49[^ ]", user, pass);
            
            char response[512];
            if (authenticate_user(user, pass)) {
                add_alert("sesion", "Inicio de sesion exitoso", "LOW"); // Alerta
                int role = get_user_role(user);
                if (role == 2) {
                    snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"success\", \"role\":\"admin_user\"}");
                } else if (role == 1) {
                    snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"success\", \"role\":\"common_user\"}");
                } else {
                    snprintf(response, sizeof(response), "HTTP/1.1 403 Forbidden\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"error\", \"message\":\"Usuario sin grupo asignado\"}");
                }
            } else {
                add_alert("sesion", "Inicio de sesion fallido", "MEDIUM"); // Alerta
                snprintf(response, sizeof(response), "HTTP/1.1 401 Unauthorized\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"error\", \"message\":\"Credenciales invalidas\"}");
            }
            write(new_socket, response, strlen(response));
        } 

        // 3. OBTENER ALERTAS
        else if (strncmp(buffer, "GET /api/alerts", 15) == 0) {
            pthread_mutex_lock(&json_mutex);
            char *alerts_str = json_dumps(global_alerts_array, JSON_COMPACT);
            pthread_mutex_unlock(&json_mutex);
            char response[18000];
            snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n%s", alerts_str);
            write(new_socket, response, strlen(response));
            free(alerts_str);
        }

        // 4. MATAR PROCESO
        else if (strncmp(buffer, "GET /api/kill", 13) == 0) {
            int pid_to_kill;
            if (sscanf(buffer, "GET /api/kill?pid=%d", &pid_to_kill) == 1) {
                if (kill(pid_to_kill, SIGKILL) == 0) {
                    add_alert("sistema", "Proceso matado", "MEDIUM"); // Alerta
                    char *resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"success\"}";
                    write(new_socket, resp, strlen(resp));
                } else {
                    char *resp = "HTTP/1.1 500 Error\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"error\"}";
                    write(new_socket, resp, strlen(resp));
                }
            }
        }

        // 5. PONER EN CUARENTENA
        else if (strncmp(buffer, "GET /api/quarantine", 19) == 0) {
            char filename[256] = {0};
            if (sscanf(buffer, "GET /api/quarantine?file=%255[^ &]", filename) == 1) {
                char full_path[512];
                snprintf(full_path, sizeof(full_path), "%s%s", MONITOR_DIR, filename);
                
                if (chmod(full_path, 0000) == 0) {
                    add_alert("archivos", "Archivo puesto en cuarentena", "HIGH"); // Alerta
                    char *resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"success\"}";
                    write(new_socket, resp, strlen(resp));
                } else {
                    char *resp = "HTTP/1.1 500 Error\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"status\":\"error\"}";
                    write(new_socket, resp, strlen(resp));
                }
            }
        }

        else {
            char *not_found = "HTTP/1.1 404 Not Found\r\n\r\n";
            write(new_socket, not_found, strlen(not_found));
        }

        close(new_socket);
    }
    return NULL;
}

int main() {
    pthread_t tid1, tid2, tid3;
    
    // Inicializamos el arreglo de alertas vacío
    global_alerts_array = json_array();

    printf("Iniciando Daemon EDR Híbrido...\n");

    pthread_create(&tid1, NULL, thread_monitoreo, NULL);
    pthread_create(&tid2, NULL, thread_archivos, NULL);
    pthread_create(&tid3, NULL, thread_servidor_http, NULL);

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    pthread_join(tid3, NULL);

    json_decref(global_alerts_array);
    return 0;
}