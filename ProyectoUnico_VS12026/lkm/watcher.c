/*
 * watcher.c - Módulo del Kernel (LKM) para monitoreo de archivos
 * 
 * Este es un Loadable Kernel Module (LKM) que se inserta dinámicamente
 * en el kernel de Linux para interceptar operaciones de escritura
 * en archivos dentro de un directorio específico ("monitor").
 * 
 * ARQUITECTURA:
 * 
 *   [Proceso de usuario escribe archivo]
 *          ↓
 *   [Kernel ejecuta vfs_write()]
 *          ↓
 *   [Kprobe intercepta la llamada]
 *          ↓
 *   [Nuestro handler verifica si es en el directorio "monitor"]
 *          ↓ (si sí)
 *   [Guarda el nombre del archivo en alert_buffer]
 *          ↓
 *   [/proc/edr_alerts expone el nombre del archivo]
 *          ↓
 *   [El daemon (scanner.c) lee /proc/edr_alerts y procesa el archivo]
 * 
 * TECNOLOGÍAS USADAS:
 *   - Kprobes: Mecanismo del kernel para interceptar funciones sin modificarlas
 *   - procfs (/proc): Pseudo-filesystem para comunicar kernel <-> espacio de usuario
 *   - Spinlocks: Mecanismo de sincronización para proteger datos en el kernel
 * 
 * COMANDOS:
 *   Cargar:   sudo insmod watcher.ko
 *   Verificar: lsmod | grep watcher
 *   Descargar: sudo rmmod watcher
 *   Ver logs:  dmesg | tail -10
 * 
 * Autor: Enner Esaí Mendizabal Castro - 202302220
 * Curso: Sistemas Operativos 2 - USAC
 */

#include <linux/module.h>    /* Macros fundamentales para cualquier módulo del kernel */
#include <linux/kernel.h>    /* Para pr_info(), pr_err() (imprimir mensajes en el log del kernel) */
#include <linux/init.h>      /* Para las macros __init y __exit */
#include <linux/proc_fs.h>   /* Para crear archivos en /proc (proc_create, proc_remove) */
#include <linux/kprobes.h>   /* Para Kprobes (interceptar funciones del kernel) */
#include <linux/fs.h>        /* Para struct file (representación de archivos en el kernel) */
#include <linux/string.h>    /* Para strcmp(), strlen(), snprintf() en el kernel */
#include <linux/uaccess.h>   /* Para copy_to_user() (copiar datos del kernel al espacio de usuario) */
#include <linux/spinlock.h>  /* Para spinlocks (mecanismo de sincronización) */

/* Metadatos del módulo (se muestran con 'modinfo watcher.ko') */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Enner Esaí Mendizabal Castro - 202302220");
MODULE_DESCRIPTION("LKM para monitoreo de archivos con Kprobes - SO2");
MODULE_VERSION("2.0");

/* Nombre del archivo que crearemos en /proc */
#define PROC_NAME "edr_alerts"

/* Nombre del directorio que queremos monitorear.
 * Cualquier escritura a archivos dentro de una carpeta llamada "monitor"
 * será interceptada por nuestro kprobe. */
#define DIR_MONITOR "monitor"

/* Puntero al archivo /proc/edr_alerts que crearemos */
static struct proc_dir_entry *proc_file;

/* Buffer donde guardamos el nombre del último archivo detectado */
static char alert_buffer[256];

/* Flag que indica si hay una alerta pendiente de ser leída.
 * 0 = no hay alerta, 1 = hay una alerta lista para leer */
static int alert_ready = 0;

/* 
 * Spinlock para proteger alert_buffer y alert_ready.
 * 
 * ¿Por qué spinlock y no mutex?
 * Porque nuestro código se ejecuta en contexto de interrupción
 * (dentro del handler del kprobe), y los mutexes NO se pueden
 * usar en contexto de interrupción (podrían causar un deadlock).
 * Los spinlocks son seguros en este contexto porque no duermen;
 * simplemente esperan en un bucle (spin) hasta obtener el lock.
 * 
 * DEFINE_SPINLOCK() crea e inicializa el spinlock de forma estática.
 */
static DEFINE_SPINLOCK(alert_lock);

/* ============================================================
 * COMUNICACIÓN A TRAVÉS DE /PROC
 * 
 * /proc es un pseudo-filesystem en Linux que no existe realmente
 * en el disco. Se usa para comunicar información entre el kernel
 * y los programas de espacio de usuario.
 * 
 * Cuando alguien hace "cat /proc/edr_alerts", el kernel llama
 * a nuestra función proc_read_alerts() automáticamente.
 * ============================================================ */

/*
 * proc_read_alerts - Se ejecuta cuando se lee /proc/edr_alerts
 * 
 * Parámetros (los pone el kernel automáticamente):
 *   file  - Estructura que representa el archivo abierto
 *   ubuf  - Puntero al buffer del ESPACIO DE USUARIO donde copiar los datos
 *   count - Cantidad máxima de bytes que el usuario quiere leer
 *   ppos  - Posición actual de lectura (offset)
 * 
 * Retorna:
 *   Número de bytes copiados al usuario, o 0 si no hay datos
 */
static ssize_t proc_read_alerts(struct file *file, char __user *ubuf, 
                                 size_t count, loff_t *ppos) {
    int len;
    ssize_t ret = 0;
    unsigned long flags;

    /* Adquirimos el spinlock (deshabilitando interrupciones locales con irqsave) */
    spin_lock_irqsave(&alert_lock, flags);

    /* 
     * Solo retornamos datos si:
     *   1. El offset es 0 (primera lectura)
     *   2. Hay una alerta pendiente (alert_ready == 1)
     * Si *ppos > 0, significa que ya se leyó y no hay datos nuevos.
     */
    if (*ppos > 0 || alert_ready == 0) {
        spin_unlock_irqrestore(&alert_lock, flags);
        return 0; /* No hay datos que leer */
    }

    /* Calculamos la longitud del nombre del archivo en el buffer */
    len = strlen(alert_buffer);
    if (len > count) {
        len = count; /* No copiar más de lo que el usuario pidió */
    }

    /* 
     * copy_to_user() copia datos del espacio del KERNEL al espacio del USUARIO.
     * 
     * ¿Por qué no podemos usar memcpy()?
     * Porque el kernel y el espacio de usuario tienen espacios de memoria
     * separados por seguridad. copy_to_user() verifica que la dirección
     * del usuario sea válida antes de copiar.
     */
    if (copy_to_user(ubuf, alert_buffer, len)) {
        ret = -EFAULT; /* Error: la dirección del usuario no es válida */
        goto out;
    }

    *ppos = len;        /* Actualizamos la posición de lectura */
    alert_ready = 0;    /* Marcamos la alerta como "consumida" */
    ret = len;          /* Retornamos la cantidad de bytes copiados */

out:
    spin_unlock_irqrestore(&alert_lock, flags);
    return ret;
}

/* 
 * Estructura que define las operaciones del archivo /proc.
 * Le decimos al kernel: "cuando alguien lea este archivo, llama a proc_read_alerts".
 */
static const struct proc_ops proc_file_fops = {
    .proc_read = proc_read_alerts,
};

/* ============================================================
 * KPROBE EN vfs_write
 * 
 * Kprobes es un mecanismo del kernel de Linux que permite
 * "enganchar" (hook) funciones del kernel para ejecutar
 * código personalizado antes o después de que se llamen.
 * 
 * Nosotros interceptamos vfs_write(), que es la función del kernel
 * que se llama cada vez que CUALQUIER proceso escribe a un archivo.
 * 
 * En nuestro handler (pre_vfs_write), verificamos:
 *   1. Si el archivo que se está escribiendo existe
 *   2. Si el directorio padre del archivo se llama "monitor"
 *   3. Si sí, guardamos el nombre del archivo en alert_buffer
 * ============================================================ */

/*
 * pre_vfs_write - Handler que se ejecuta ANTES de cada vfs_write()
 * 
 * Parámetros:
 *   p    - Puntero a la estructura del kprobe
 *   regs - Registros del CPU en el momento de la interceptación
 *          (contiene los parámetros de la función interceptada)
 * 
 * Los parámetros de vfs_write() están en los registros del CPU:
 *   regs->di = primer argumento = struct file *file
 */
static int __kprobes pre_vfs_write(struct kprobe *p, struct pt_regs *regs) {
    /* Obtenemos el puntero al archivo desde el registro DI (primer argumento de vfs_write) */
    struct file *file = (struct file *)regs->di;
    const char *parent_name;
    const char *file_name;
    unsigned long flags;

    /* 
     * Verificamos que el archivo tenga una estructura válida.
     * f_path.dentry contiene la información del directorio del archivo.
     * d_parent es el directorio padre (la carpeta donde está el archivo).
     */
    if (file && file->f_path.dentry && file->f_path.dentry->d_parent) {
        /* Obtenemos el nombre del archivo y de su directorio padre */
        file_name = file->f_path.dentry->d_name.name;
        parent_name = file->f_path.dentry->d_parent->d_name.name;

        /* 
         * Comparamos si el directorio padre se llama "monitor".
         * Si es así, significa que se está escribiendo un archivo
         * dentro del directorio que estamos vigilando.
         */
        if (strcmp(parent_name, DIR_MONITOR) == 0) {
            /* Imprimimos un mensaje en el log del kernel (visible con dmesg) */
            pr_info("Watcher ALERTA: Modificacion detectada -> %s\n", file_name);
            
            /* Guardamos el nombre del archivo en el buffer protegido por spinlock */
            spin_lock_irqsave(&alert_lock, flags);
            snprintf(alert_buffer, sizeof(alert_buffer), "%s\n", file_name);
            alert_ready = 1; /* Marcamos que hay una alerta pendiente */
            spin_unlock_irqrestore(&alert_lock, flags);
        }
    }
    return 0; /* Retornamos 0 para permitir que vfs_write() continúe normalmente */
}

/* 
 * Estructura del kprobe: le decimos al kernel QUÉ función queremos interceptar.
 * symbol_name = "vfs_write" es la función del kernel que se llama
 * cada vez que se escribe a un archivo.
 */
static struct kprobe kp = {
    .symbol_name = "vfs_write",
    .pre_handler = pre_vfs_write, /* Nuestro handler se ejecuta ANTES de vfs_write */
};

/*
 * pre_vfs_copy_file_range - Handler para cp moderno
 * El comando 'cp' moderno usa copy_file_range en lugar de write().
 * Interceptamos esta función donde el 3er argumento (file_out) es el destino.
 */
static int __kprobes pre_vfs_copy_file_range(struct kprobe *p, struct pt_regs *regs) {
    /* El 3er argumento (file_out) está en el registro DX en x86_64 */
    struct file *file = (struct file *)regs->dx;
    const char *parent_name;
    const char *file_name;
    unsigned long flags;

    if (file && file->f_path.dentry && file->f_path.dentry->d_parent) {
        file_name = file->f_path.dentry->d_name.name;
        parent_name = file->f_path.dentry->d_parent->d_name.name;

        if (strcmp(parent_name, DIR_MONITOR) == 0) {
            pr_info("Watcher ALERTA (cp): Modificacion detectada -> %s\n", file_name);
            spin_lock_irqsave(&alert_lock, flags);
            snprintf(alert_buffer, sizeof(alert_buffer), "%s\n", file_name);
            alert_ready = 1;
            spin_unlock_irqrestore(&alert_lock, flags);
        }
    }
    return 0;
}

static struct kprobe kp_copy = {
    .symbol_name = "vfs_copy_file_range",
    .pre_handler = pre_vfs_copy_file_range,
};

/* ============================================================
 * FUNCIONES DE INICIALIZACIÓN Y LIMPIEZA DEL MÓDULO
 * 
 * __init y __exit son macros especiales del kernel:
 *   __init = Esta función se ejecuta UNA vez al cargar el módulo (insmod)
 *            y luego su memoria se libera.
 *   __exit = Esta función se ejecuta UNA vez al descargar el módulo (rmmod).
 * ============================================================ */

/*
 * watcher_init - Se ejecuta cuando hacemos "sudo insmod watcher.ko"
 * 
 * 1. Crea el archivo /proc/edr_alerts con permisos de solo lectura (0444)
 * 2. Registra el kprobe para interceptar vfs_write
 */
static int __init watcher_init(void) {
    int ret;

    /* Creamos el archivo /proc/edr_alerts
     * 0444 = permisos de solo lectura para todos (r--r--r--)
     * NULL = sin directorio padre (va directo en /proc/)
     * &proc_file_fops = las operaciones que definimos arriba */
    proc_file = proc_create(PROC_NAME, 0444, NULL, &proc_file_fops);
    if (!proc_file) {
        pr_err("Watcher: Error al crear nodo /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    /* Registramos el kprobe para interceptar vfs_write */
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("Watcher: Error al registrar kprobe %d\n", ret);
        proc_remove(proc_file); /* Limpiamos si falla */
        return ret;
    }

    /* Registramos el kprobe para interceptar vfs_copy_file_range (usado por cp) */
    ret = register_kprobe(&kp_copy);
    if (ret < 0) {
        pr_err("Watcher: Error al registrar kprobe_copy %d\n", ret);
        unregister_kprobe(&kp);
        proc_remove(proc_file);
        return ret;
    }

    pr_info("Watcher: Inicializado correctamente. Kprobes en vfs_write y vfs_copy_file_range. Vigilando '%s'\n", DIR_MONITOR);
    return 0; /* Éxito */
}

/*
 * watcher_exit - Se ejecuta cuando hacemos "sudo rmmod watcher"
 * 
 * Limpia todos los recursos: desregistra el kprobe y elimina /proc/edr_alerts.
 */
static void __exit watcher_exit(void) {
    unregister_kprobe(&kp_copy); /* Dejamos de interceptar vfs_copy_file_range */
    unregister_kprobe(&kp);      /* Dejamos de interceptar vfs_write */
    proc_remove(proc_file);      /* Eliminamos /proc/edr_alerts */
    pr_info("Watcher: Modulo descargado.\n");
}

/* Estas macros registran nuestras funciones init/exit con el kernel */
module_init(watcher_init);
module_exit(watcher_exit);
