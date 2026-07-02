# Manual Técnico: Sistema EDR Híbrido — Monitoreo y Seguridad del SO

**Nombre:** Enner Esaí Mendizabal Castro  
**Carnet:** 202302220  
**Curso:** Sistemas Operativos 2  
**Institución:** Universidad de San Carlos de Guatemala (USAC)  

---

## Introducción
El presente manual técnico detalla la arquitectura, diseño interno y decisiones de implementación del Sistema Integral de Monitoreo y Seguridad (EDR) Híbrido. Está orientado a desarrolladores, ingenieros de sistemas y auditores que requieran comprender cómo se intercomunican los módulos del kernel con el espacio de usuario, la gestión de memoria y el flujo de los eventos de seguridad en tiempo real.

## Alcance del Sistema
El alcance técnico del sistema incluye:
- **Nivel de Kernel (Ring 0):** Implementación de tres llamadas al sistema (Syscalls) para lectura directa de métricas de paginación y estructuras de procesos (`task_struct`, `mm_struct`), junto con un Loadable Kernel Module (LKM) usando Kprobes para interceptar operaciones VFS.
- **Espacio de Usuario (Ring 3):** Desarrollo de un Daemon en C puro con multihilo (`pthreads`) para orquestación, cálculo de firmas criptográficas (SHA-256) vía OpenSSL, autenticación PAM y exposición de una API HTTP/JSON cruda.
- **Nivel de Presentación:** Interfaz construida en React + Vite que consume la API REST del Daemon.

No se incluye la persistencia en bases de datos relacionales (RDBMS), delegando el almacenamiento a estructuras JSON y archivos binarios/logs planos en el sistema de archivos local para minimizar la huella de recursos.

## Requisitos del Sistema
- **Kernel Linux:** Versión 6.8 o superior con cabeceras de compilación instaladas (`linux-headers-$(unam -er)`).
- **Compiladores:** `gcc` y `make`.
- **Librerías C:** `libssl-dev`, `libpam0g-dev`, `libjansson-dev`.
- **Frontend:** `Node.js` v18+ y `npm`.

---

## 1. Arquitectura General

El sistema opera bajo un enfoque híbrido de Endpoint Detection and Response (EDR) que combina el monitoreo profundo a nivel del Kernel (Ring 0) con un Daemon orquestador en espacio de usuario (Ring 3) y un Dashboard Web para visualización en tiempo real.

```
┌──────────────────────────────────┐
│         Dashboard Web (React)    │ ← Visualización y control
│         Puerto 5173 (Vite)       │
└──────────────┬───────────────────┘
               │ HTTP (JSON)
┌──────────────▼───────────────────┐
│      Daemon Orquestador (C)      │ ← Lógica de negocio, alertas, PAM
│      Puerto 8080 (HTTP raw)      │
│  ┌────────┐ ┌────────┐ ┌──────┐ │
│  │ Hilo 1 │ │ Hilo 2 │ │Hilo 3│ │
│  │Metrics │ │Scanner │ │ HTTP │ │
│  └────┬───┘ └────┬───┘ └──────┘ │
└───────┼──────────┼───────────────┘
        │          │
        │ syscall  │ /proc/edr_alerts
        │ 462-464  │
┌───────▼──────────▼───────────────┐
│          Kernel Linux 6.8        │
│  ┌──────────────┐ ┌───────────┐  │
│  │ Syscalls     │ │ LKM       │  │
│  │ 462,463,464  │ │watcher.ko │  │
│  └──────────────┘ └───────────┘  │
└──────────────────────────────────┘
```

---

## 2. Espacio del Kernel (Syscalls + LKM)

### 2.1 Módulo LKM (Loadable Kernel Module) — `watcher.ko`

El módulo del kernel intercepta llamadas al sistema de archivos para detectar creación y modificación de archivos en el directorio monitoreado.

**Mecanismo:** Utiliza **Kprobes** para engancharse a `vfs_write`, verificando si el directorio padre del archivo coincide con `monitor`. Al detectar un evento, escribe el nombre del archivo en un buffer interno protegido por spinlock, y lo expone a través de `/proc/edr_alerts`.

**Comunicación Kernel → User Space:**
- Archivo virtual: `/proc/edr_alerts` (solo lectura, permisos 0444)
- Protocolo: lectura secuencial; cada lectura consume un evento
- Protección: `spinlock_irqsave` contra condiciones de carrera SMP

### 2.2 Syscalls Implementadas

Se implementaron tres syscalls personalizadas en `kernel/sys.c`:

#### Syscall 462 — `sys_get_system_monitor()`

Recopila métricas completas del sistema operativo directamente desde las estructuras internas del kernel.

| Campo | Fuente Kernel | Descripción |
|---|---|---|
| `memoria_usada` | `si_meminfo()` → `totalram - freeram` | RAM utilizada en bytes |
| `memoria_libre` | `si_meminfo()` → `freeram` | RAM disponible en bytes |
| `memoria_cache` | `global_node_page_state(NR_FILE_PAGES)` | Páginas de caché de archivos |
| `swap_usada` | `si_swapinfo()` → `totalswap - freeswap` | Swap utilizado en bytes |
| `fallos_menores` | `all_vm_events[PGFAULT]` | Minor page faults acumulados |
| `fallos_mayores` | `all_vm_events[PGMAJFAULT]` | Major page faults acumulados |
| `paginas_activas` | `NR_ACTIVE_ANON + NR_ACTIVE_FILE` | Páginas activas en memoria |
| `paginas_inactivas` | `NR_INACTIVE_ANON + NR_INACTIVE_FILE` | Páginas candidatas a ser paginadas |

#### Syscall 463 — `sys_get_process_list()`

Escanea la lista de procesos activos y devuelve un arreglo de estructuras `process_info` al espacio de usuario.

- Itera con `for_each_process()` bajo `rcu_read_lock()`
- Devuelve: PID, nombre (vía `get_task_comm()`), y RSS en páginas crudas (vía `get_mm_rss()`)
- Retorna: cantidad de procesos copiados

> **Nota Técnica:** El kernel envía la memoria en "páginas crudas" (RSS) en lugar de un porcentaje calculado. Esta decisión arquitectónica delega el cálculo de coma flotante al espacio de usuario, ya que el Kernel de Linux no está optimizado para operaciones de punto flotante.

#### Syscall 464 — `sys_get_process_info(pid)`

Obtiene la información de un proceso específico dado su PID.

- Busca el proceso con `find_task_by_vpid(pid)` bajo `rcu_read_lock()`
- Devuelve: PID, nombre, y porcentaje de uso de memoria (`(rss * 100) / totalram_pages()`)
- Retorna: 0 en éxito, `-ESRCH` si no existe el proceso

---

## 3. Daemon Orquestador (Programa Intermedio en C)

El daemon (`daemon_monitor`) está escrito en C modular, compilado con `gcc -Wall -pthread` y enlazado contra `libssl`, `libcrypto`, `libjansson` y `libpam`.

### 3.1 Estructura de Archivos

| Archivo | Responsabilidad |
|---|---|
| `main.c` | Punto de entrada, inicialización, creación de hilos |
| `globals.h` | Definiciones compartidas, estructuras, constantes |
| `metrics.c` / `metrics.h` | Hilo de monitoreo (syscall 462) |
| `scanner.c` / `scanner.h` | Hilo de escaneo de archivos, cálculo SHA-256, blacklist |
| `alerts.c` / `alerts.h` | Sistema de alertas con historial en JSON |
| `auth.c` / `auth.h` | Autenticación PAM y verificación de roles |
| `http_server.c` / `http_server.h` | Servidor HTTP, API REST, ruteo |

### 3.2 Hilos de Ejecución (Pthreads)

El programa levanta tres hilos de ejecución paralela:

1. **Hilo de Monitoreo (`metrics.c`):** Invoca cada 2 segundos la syscall 462, serializando las 8 métricas de memoria a JSON usando `jansson`. Respeta el toggle `metrics_enabled` para que el admin pueda desactivar el monitoreo desde el dashboard.

2. **Hilo de Escaneo de Archivos (`scanner.c`):** Hace polling continuo sobre `/proc/edr_alerts`. Cuando detecta un archivo:
    - Reconstruye la ruta absoluta en `/home/sopes/monitor/`
    - Calcula el hash SHA-256 usando OpenSSL (`EVP_DigestUpdate`)
    - Compara contra `blacklist.json`
    - Registra el archivo en la lista global de archivos escaneados con estado (benigno/infectado), nombre de amenaza y timestamp
    - Genera alertas enriquecidas mediante `add_alert()`

3. **Hilo de Servidor HTTP (`http_server.c`):** Servidor HTTP con sockets TCP nativos que expone la API REST al Frontend.

### 3.3 Control de Concurrencia

- **`metrics_mutex`**: Protege el buffer JSON de métricas compartido entre el hilo de monitoreo y el servidor HTTP.
- **`alerts_mutex`**: Protege el arreglo de alertas contra accesos concurrentes.
- **`files_mutex`**: Protege la lista de archivos escaneados y la lista de cuarentena.

La separación en tres mutex independientes evita deadlocks y minimiza la contención entre hilos.

### 3.4 API REST (Endpoints)

| Método | Ruta | Descripción | Rol Requerido |
|---|---|---|---|
| GET | `/api/metrics` | Métricas del sistema en tiempo real | Todos |
| GET | `/api/processes?page=X&search=Y` | Listado paginado de procesos | Todos |
| GET | `/api/top_processes` | Top 20 procesos por consumo de memoria | Todos |
| GET | `/api/alerts` | Historial de alertas de seguridad | Todos |
| GET | `/api/files` | Lista de archivos escaneados con estado | Todos |
| GET | `/api/login?user=X&pass=Y` | Autenticación PAM, retorna rol | N/A |
| GET | `/api/process_info?pid=X` | Info de proceso específico (syscall 464) | Admin |
| GET | `/api/kill?pid=X` | Envía SIGKILL al proceso | Admin |
| GET | `/api/quarantine?file=X` | Pone archivo en cuarentena (chmod 0000) | Admin |
| GET | `/api/quarantine_list` | Lista de archivos en cuarentena | Admin |
| GET | `/api/toggle_scan` | Activa/desactiva escaneo de archivos | Admin |
| GET | `/api/toggle_metrics` | Activa/desactiva monitoreo de métricas | Admin |
| GET | `/api/status` | Estado actual de los toggles | Todos |
| POST | `/api/update_blacklist` | Actualiza blacklist.json (con validación) | Admin |

### 3.5 Sistema de Alertas

Las alertas se clasifican por severidad:

| Severidad | Eventos |
|---|---|
| **LOW** | Archivo creado/modificado, Monitoreo del sistema activado, Inicio de sesión exitoso |
| **MEDIUM** | Monitoreo del sistema desactivado, Inicio de sesión fallido, Actualización base de datos local, Proceso matado |
| **HIGH** | Hash malicioso detectado, Archivo puesto en cuarentena |

Cada alerta incluye: tipo de evento, descripción, severidad y fecha/hora. Se mantienen las 100 alertas más recientes en memoria (FIFO).

### 3.6 Autenticación PAM

El módulo `auth.c` emplea `libpam` para autenticación nativa del sistema operativo:

- Usa el servicio PAM `su` para verificar credenciales
- Verifica membresía en grupos: `admin_user` (rol 2) o `common_user` (rol 1)
- Si un usuario pertenece a ambos grupos, se toma como administrador
- Los usuarios sin grupo asignado reciben HTTP 403

### 3.7 Detección de Amenazas

- **Algoritmo:** SHA-256 (OpenSSL EVP API)
- **Base de firmas:** `blacklist.json` con formato `{ "NombreAmenaza": { "hash": "...", "descripcion": "..." } }`
- **Comparación:** Case-insensitive (`strcasecmp`)
- **La lógica de detección y severidad reside exclusivamente en espacio de usuario**, no en el kernel

---

## 4. Dashboard Web (Frontend)

### 4.1 Tecnologías

| Tecnología | Justificación |
|---|---|
| **React (Preact)** | Componentes modulares, Virtual DOM para actualizaciones eficientes cada 2s |
| **Vite** | Servidor de desarrollo ultrarrápido con HMR |
| **Tailwind CSS** | Diseño utilitario para interfaces modernas y responsive |
| **Chart.js** | Gráficas interactivas en tiempo real |
| **Axios** | Cliente HTTP asíncrono para consumir la API del daemon |
| **Lucide React** | Iconografía consistente y ligera |

### 4.2 Componentes

| Componente | Función |
|---|---|
| `Login.jsx` | Pantalla de inicio de sesión con PAM |
| `Dashboard.jsx` | Layout principal con sidebar y navegación por pestañas |
| `Metrics.jsx` | 4 gráficas en tiempo real, 4 tarjetas de resumen, tabla top 10 procesos |
| `Processes.jsx` | Listado paginado con búsqueda, matar proceso (con confirmación), consulta por PID |
| `Files.jsx` | Lista de archivos escaneados con estado benigno/infectado y timestamp |
| `Threats.jsx` | Amenazas detectadas con firma, archivo afectado, descripción. Actualización de blacklist |
| `Alerts.jsx` | Panel de alertas con diferenciación visual por severidad |
| `Quarantine.jsx` | Formulario de cuarentena manual y lista de archivos bloqueados |

### 4.3 Control de Roles

El dashboard adapta su interfaz según el rol del usuario autenticado:

- **Todos los usuarios:** Ver métricas, procesos, archivos, alertas
- **Solo administradores:** Matar procesos, consultar PID, activar/desactivar escaneo, activar/desactivar métricas, actualizar blacklist, poner archivos en cuarentena
