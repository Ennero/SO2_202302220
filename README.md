# 🛡️ Sistema Híbrido EDR de Monitoreo - Sistemas Operativos 2

¡Bienvenido al repositorio central de arquitectura y desarrollo Kernel/User-space! 

## 🚀 Inicio Rápido

Este espacio aloja los componentes y prácticas de desarrollo que interconectan el *Kernel de Linux (Ring 0)* con arquitecturas analíticas en *User Space (Ring 3)*. 

Actualmente, puedes explorar:
- **Practica 1 (Monitoreo LKM & Daemon SHA-256):** Un módulo base en espacio de Kernel (`watcher.ko`) que intercepta llamadas VFS y notifica bidireccionalmente a un proceso de usuario (`daemon_monitor`) dedicado a la recolección, validación y gestión de logs criptográficos.
- **Proyecto Único (Sistema Integral de Monitoreo y Seguridad):** Plataforma completa de EDR que combina 3 syscalls personalizadas en el Kernel, un daemon en C con concurrencia (3 hilos), detección de amenazas por firmas SHA-256, autenticación PAM con roles, y un Dashboard Web en tiempo real con gráficas, alertas y gestión de archivos.

---

## 📦 Estructura del Repositorio

```
mapa/
├── Practica1_VS12026/          # Práctica 1: LKM + Daemon base
│   ├── daemon/                 # Daemon de monitoreo básico
│   ├── lkm/                    # Módulo del kernel (watcher.ko)
│   ├── test/                   # Archivos de prueba
│   └── report.md               # Informe técnico
│
├── ProyectoUnico_VS12026/      # Proyecto Único: Sistema EDR Completo
│   ├── linux-6.8/              # Archivos modificados del kernel (syscalls 462-464)
│   ├── programa_intermedio/    # Daemon en C (HTTP, PAM, SHA-256, alertas)
│   ├── dashboard/              # Frontend React + Vite + Tailwind
│   ├── lkm/                    # Módulo del kernel (watcher.ko)
│   ├── test/                   # Archivos de prueba para detección
│   ├── technical_manual.md     # Manual Técnico
│   └── user_manual.md          # Manual de Usuario
│
├── README.md                   # Este archivo
└── state.md                    # Enunciado del proyecto
```

---

## 🔬 Proyecto Único — Sistema Integral de Monitoreo y Seguridad

### Componentes

| Capa | Tecnología | Descripción |
|---|---|---|
| **Kernel (Ring 0)** | C, Kprobes, Syscalls | 3 syscalls personalizadas + LKM para monitoreo VFS |
| **Daemon (Ring 3)** | C, pthreads, OpenSSL, PAM, jansson | Orquestador con 3 hilos, API REST HTTP, SHA-256 |
| **Dashboard** | React, Vite, Tailwind CSS, Chart.js | Visualización en tiempo real, 6 secciones |

### ⚙️ Guía de Ejecución Rápida

**Terminal 1 — LKM:**
```bash
cd ProyectoUnico_VS12026/lkm && make && sudo insmod watcher.ko
```

**Terminal 2 — Daemon:**
```bash
cd ProyectoUnico_VS12026/programa_intermedio && make && sudo ./daemon_monitor
```

**Terminal 3 — Dashboard:**
```bash
cd ProyectoUnico_VS12026/dashboard && npm install && npm run dev
```

**Terminal 4 — Simulación de amenazas:**
```bash
echo "Encrypting all user files..." > ~/monitor/Simulated.Ransomware.Encryptor.txt
echo "Prueba segura" > ~/monitor/saludo.txt
```

### 📚 Documentación del Proyecto

- [Manual Técnico](./ProyectoUnico_VS12026/technical_manual.md) — Arquitectura, syscalls, hilos, API REST, detección
- [Manual de Usuario](./ProyectoUnico_VS12026/user_manual.md) — Guía paso a paso con capturas del dashboard

---

## 📚 Documentación de la Práctica 1

- [Informe Técnico de la Práctica 1 (Monitoreo y Seguridad de Archivos)](./Practica1_VS12026/report.md)

### ⚙️ Guía de Pruebas Rápida (Práctica 1)
1. **Terminal 1 (LKM):** `cd Practica1_VS12026/lkm && make && sudo insmod watcher.ko`
2. **Terminal 2 (Daemon):** `cd Practica1_VS12026/daemon && make && ./daemon_monitor`
3. **Terminal 3 (Simulación en `~/monitor/`):** 
   * *Ransomware:* `echo "Encrypting all user files..." > ~/monitor/Simulated.Ransomware.Encryptor.txt`
   * *Inofensivo:* `echo "Prueba segura" > ~/monitor/saludo.txt`
