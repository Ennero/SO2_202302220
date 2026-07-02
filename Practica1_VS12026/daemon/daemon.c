#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // Necesario para strcasecmp (comparación sin distinguir mayúsculas)
#include <unistd.h>
#include <openssl/evp.h>
#include <jansson.h>
#include <time.h>

#define PROC_FILE "/proc/edr_alerts"
#define MONITOR_DIR "/home/sopes/monitor/"
#define JSON_FILE "blacklist.json"
#define LOG_FILE "alertas_seguridad.log"

/**
 * Calcula el hash SHA-256 de un archivo de manera segura usando API EVP_ de OpenSSL.
 * Retorna 1 en caso de exito, 0 si hay error.
 */
int calculate_sha256(const char *filepath, char *output_buffer) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return 0; // Archivo no accesible
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return 0;
    }

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

/**
 * Verifica si un hash dado se encuentra en la blacklist.
 * Retorna 1 si esta, 0 en caso contrario. 
 * Además, extrae la descripción del JSON hacia el buffer proporcionado.
 */
int check_blacklist(const char *hash_calculado, char *desc_out) {
    json_error_t error;
    json_t *root = json_load_file(JSON_FILE, 0, &error);
    if (!root) {
        fprintf(stderr, "Error leyendo JSON: %s en linea %d\n", error.text, error.line);
        return 0;
    }

    const char *key;
    json_t *value;
    int found = 0;

    // Iterar sobre las llaves del objeto raíz en el nuevo formato JSON
    json_object_foreach(root, key, value) {
        json_t *hash_json = json_object_get(value, "hash");
        json_t *desc_json = json_object_get(value, "descripcion");

        if (json_is_string(hash_json)) {
            const char *hash_str = json_string_value(hash_json);
            
            // strcasecmp permite comparar "E29A8..." del JSON con "e29a8..." de OpenSSL
            if (strcasecmp(hash_str, hash_calculado) == 0) {
                found = 1;
                if (json_is_string(desc_json)) {
                    strcpy(desc_out, json_string_value(desc_json));
                } else {
                    strcpy(desc_out, "Amenaza identificada (sin descripción)");
                }
                break;
            }
        }
    }
    
    json_decref(root);
    return found;
}

/**
 * Registra logs locales sobre detecciones maliciosas agregando la descripción.
 */
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

/**
 * Procesa la alerta recibida para validar la seguridad del archivo.
 */
void process_alert(const char *filename) {
    char full_path[512];
    char hash_str[65];
    char threat_desc[256];

    snprintf(full_path, sizeof(full_path), "%s%s", MONITOR_DIR, filename);

    if (calculate_sha256(full_path, hash_str)) {
        if (check_blacklist(hash_str, threat_desc)) {
            write_security_log(filename, hash_str, threat_desc);
            printf("¡AMENAZA DETECTADA! -> %s | %s (Registrado en %s)\n", filename, threat_desc, LOG_FILE);
        } else {
            printf("Archivo %s escaneado. Hash limpio: %s\n", filename, hash_str);
        }
    }
}

int main(void) {
    char buffer[256];

    printf("Daemon EDR iniciado. Monitoreando %s en segundo plano...\n", PROC_FILE);

    while (1) {
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
    return 0;
}