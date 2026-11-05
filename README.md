<div align="center">

# 🛡️ Hybrid EDR Monitoring System — Linux Kernel & User-Space

**Sistema de Detección y Respuesta en Endpoint (EDR) con integración Kernel Ring 0 (LKM & Syscalls) y Daemon Multihilo en C (Ring 3)**

[![Linux](https://img.shields.io/badge/Linux_Kernel-6.8-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://kernel.org/)
[![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Preact](https://img.shields.io/badge/Preact-10-673AB8?style=for-the-badge&logo=preact&logoColor=white)](https://preactjs.com/)
[![Vite](https://img.shields.io/badge/Vite-5.x-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![University](https://img.shields.io/badge/USAC-Sistemas_Operativos_2-003366?style=for-the-badge)](https://ingenieria.usac.edu.gt/)

</div>

---

## 🚀 Inicio Rápido

Este espacio aloja los componentes y prácticas de desarrollo que interconectan el **Kernel de Linux (Ring 0)** con arquitecturas analíticas en **User Space (Ring 3)**:

- **Práctica 1 (Monitoreo LKM & Daemon SHA-256):** Un módulo base en espacio de Kernel (`watcher.ko`) que intercepta llamadas VFS y notifica bidireccionalmente a un proceso de usuario (`daemon_monitor`) dedicado a la recolección, validación y gestión de logs criptográficos.
- **Proyecto Único (Sistema Integral de Monitoreo y Seguridad):** Plataforma completa de EDR que combina 3 syscalls personalizadas en el Kernel, un daemon en C con concurrencia (3 hilos), detección de amenazas por firmas SHA-256, autenticación PAM con roles, y un Dashboard Web en tiempo real con gráficas, alertas y gestión de archivos.

---

## 📦 Estructura del Repositorio

```
SO2_202302220/
├── Practica1_VS12026/          # Práctica 1: LKM + Daemon base
│   ├── daemon/                 # Daemon de monitoreo básico
│   ├── lkm/                    # Módulo del kernel (watcher.ko)
│   ├── test/                   # Archivos de prueba
│   └── report.md               # Informe técnico
│
├── ProyectoUnico_VS12026/      # Proyecto Único: Sistema EDR Completo
│   ├── linux-6.8/              # Archivos modificados del kernel (syscalls 462-464)
│   ├── programa_intermedio/    # Daemon en C (HTTP, PAM, SHA-256, alertas)
│   ├── dashboard/              # Frontend Preact (compatibilidad React) + Vite + Tailwind
│   ├── lkm/                    # Módulo del kernel (watcher.ko)
│   ├── test/                   # Archivos de prueba para detección
│   ├── technical_manual.md     # Manual Técnico
│   └── user_manual.md          # Manual de Usuario
│
├── LICENSE                     # Licencia MIT
└── README.md                   # Este archivo
```

---

## 🔬 Proyecto Único — Sistema Integral de Monitoreo y Seguridad

### Componentes de la Arquitectura

| Capa | Tecnología | Descripción |
|---|---|---|
| **Kernel (Ring 0)** | C, Kprobes, Syscalls | 3 syscalls personalizadas (462-464) + LKM para monitoreo VFS |
| **Daemon (Ring 3)** | C, pthreads, OpenSSL, PAM, jansson | Orquestador con 3 hilos concurrentes, API REST HTTP, firmas SHA-256 |
| **Dashboard** | React, Vite, Tailwind CSS, Chart.js | Visualización en tiempo real con métricas, alertas y telemetría |

### Preparar la máquina Linux

Usar una VM Linux de pruebas. Antes de ejecutar `make`, seguir el [manual técnico](ProyectoUnico_VS12026/technical_manual.md) para preparar el kernel 6.8 con las syscalls de la entrega, sus headers y las bibliotecas PAM, OpenSSL y jansson. Un kernel estándar sin esas modificaciones no ofrece todas las operaciones del daemon. El dashboard usa Preact con compatibilidad de React.

### ⚙️ Guía de Ejecución Rápida

**Terminal 1 — LKM (Kernel Module):**
```bash
cd ProyectoUnico_VS12026/lkm && make && sudo insmod watcher.ko
```

**Terminal 2 — Daemon en C:**
```bash
cd ProyectoUnico_VS12026/programa_intermedio && make && sudo ./daemon_monitor
```

**Terminal 3 — Dashboard Web:**
```bash
cd ProyectoUnico_VS12026/dashboard && npm install && npm run dev
```

**Terminal 4 — Simulación de Amenazas (Ransomware Test):**
```bash
echo "Encrypting all user files..." > ~/monitor/Simulated.Ransomware.Encryptor.txt
echo "Prueba segura" > ~/monitor/saludo.txt
```

### 📚 Documentación Técnica Detallada
- [Manual Técnico](./ProyectoUnico_VS12026/technical_manual.md) — Arquitectura, syscalls, hilos, API REST, detección.
- [Manual de Usuario](./ProyectoUnico_VS12026/user_manual.md) — Guía paso a paso con capturas del dashboard.

---

## 📚 Documentación de la Práctica 1

- [Informe Técnico de la Práctica 1 (Monitoreo y Seguridad de Archivos)](./Practica1_VS12026/report.md)

### ⚙️ Guía de Pruebas Rápida (Práctica 1)
1. **Terminal 1 (LKM):** `cd Practica1_VS12026/lkm && make && sudo insmod watcher.ko`
2. **Terminal 2 (Daemon):** `cd Practica1_VS12026/daemon && make && ./daemon_monitor`
3. **Terminal 3 (Simulación en `~/monitor/`):** 
   - *Ransomware:* `echo "Encrypting all user files..." > ~/monitor/Simulated.Ransomware.Encryptor.txt`
   - *Inofensivo:* `echo "Prueba segura" > ~/monitor/saludo.txt`

---

## 📄 Licencia

Este proyecto está liberado bajo la Licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más información.

---

## 👨‍💻 Autor

- **Enner Mendizabal** - [@Ennero](https://github.com/Ennero)  
- *Ingeniería en Ciencias y Sistemas, Universidad de San Carlos de Guatemala.*

Los cambios de kernel y fragmentos de Linux conservan sus licencias y avisos propios. La licencia MIT de la raíz corresponde al código original del proyecto que no tenga otra declaración.
