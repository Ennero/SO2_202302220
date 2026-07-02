#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Enner Esaí Mendizabal Castro - 202302220");
MODULE_DESCRIPTION("LKM para monitoreo de archivos con Kprobes - SO2");
MODULE_VERSION("2.0");

#define PROC_NAME "edr_alerts"
#define DIR_MONITOR "monitor"

static struct proc_dir_entry *proc_file;

static char alert_buffer[256];
static int alert_ready = 0;
// Proteccion contra condiciones de carrera en SMP
static DEFINE_SPINLOCK(alert_lock);

// --- INICIO COMUNICACIÓN /PROC ---
static ssize_t proc_read_alerts(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
    int len;
    ssize_t ret = 0;
    unsigned long flags;

    spin_lock_irqsave(&alert_lock, flags);

    // Solo permitir lectura si hay una alerta lista y el offset es 0
    if (*ppos > 0 || alert_ready == 0) {
        spin_unlock_irqrestore(&alert_lock, flags);
        return 0;
    }
    // Copiar la alerta al buffer del usuario
    len = strlen(alert_buffer);
    if (len > count) {
        len = count;
    }

    // Copiar datos al espacio del usuario
    if (copy_to_user(ubuf, alert_buffer, len)) {
        ret = -EFAULT;
        goto out;
    }

    *ppos = len;
    alert_ready = 0;
    ret = len;

out:
    spin_unlock_irqrestore(&alert_lock, flags);
    return ret;
}

// Estructura de operaciones para el archivo /proc/edr_alerts
static const struct proc_ops proc_file_fops = {
    .proc_read = proc_read_alerts,
};

// --- INICIO KPROBES ---
static int __kprobes pre_vfs_write(struct kprobe *p, struct pt_regs *regs) {
    struct file *file = (struct file *)regs->di;
    const char *parent_name;
    const char *file_name;
    unsigned long flags;

    // Verificar que el archivo modificado pertenece al directorio monitor
    if (file && file->f_path.dentry && file->f_path.dentry->d_parent) {
        file_name = file->f_path.dentry->d_name.name;
        parent_name = file->f_path.dentry->d_parent->d_name.name;

        // Si el directorio padre es el monitor, registrar la alerta
        if (strcmp(parent_name, DIR_MONITOR) == 0) {
            pr_info("Watcher ALERTA: Modificacion detectada -> %s\n", file_name);
            
            spin_lock_irqsave(&alert_lock, flags);
            snprintf(alert_buffer, sizeof(alert_buffer), "%s\n", file_name);
            alert_ready = 1;
            spin_unlock_irqrestore(&alert_lock, flags);
        }
    }
    return 0;
}

// Estructura de kprobe para interceptar vfs_write
static struct kprobe kp = {
    .symbol_name = "vfs_write",
    .pre_handler = pre_vfs_write,
};

// --- INICIO MÓDULO ---
static int __init watcher_init(void) {
    int ret;
    proc_file = proc_create(PROC_NAME, 0444, NULL, &proc_file_fops); // 0444: Solo lectura
    if (!proc_file) {
        pr_err("Watcher: Error al crear nodo /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    // Registrar el kprobe para monitorear vfs_write
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("Watcher: Error al registrar kprobe %d\n", ret);
        proc_remove(proc_file);
        return ret;
    }

    pr_info("Watcher: Inicializado correctamente. Kprobe en vfs_write. Vigilando '%s'\n", DIR_MONITOR);
    return 0;
}

// Limpieza del módulo: eliminar el nodo /proc y desregistrar el kprobe
static void __exit watcher_exit(void) {
    unregister_kprobe(&kp);
    proc_remove(proc_file);
    pr_info("Watcher: Modulo descargado.\n");
}

// Macros para registrar las funciones de inicialización y limpieza del módulo
module_init(watcher_init);
module_exit(watcher_exit);
