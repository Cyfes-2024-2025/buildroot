#include "linux/ioport.h"
#include "linux/platform_device.h"
#include "linux/random.h"
#include <linux/kernel.h>
#include <linux/module.h>

// Probing and Memory Mapping
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/io.h>

// Character Device and Platform Device
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>

// mmap
#include <linux/mm.h>
#include <asm/io.h>

// Kprobes
#include <linux/kprobes.h>

// Utilities
#include <linux/errno.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pietro");
MODULE_DESCRIPTION("A kernel module to interface with the ptrauth driver");
MODULE_VERSION("0.1");

#define DRIVER_NAME "ptrauth"
#define DEVICE_NAME "ptrauth"
#define CLASS_NAME "cfi_devices"

#define PTRAUTH_DEBUG

#ifdef PTRAUTH_DEBUG
    #define pa_info(...) pr_info(DRIVER_NAME ": " __VA_ARGS__)
#else
    // If debug is disabled, simply do nothing
    #define pa_info(...)
#endif

#define pa_err(...) pr_err(DRIVER_NAME ": " __VA_ARGS__)

// ==== Forward Declarations ====

static void ptrauth_set_key(uint64_t key_low, uint64_t key_high);
static void ptrauth_clear_ciphertext(void);

static int ptrauth_probe(struct platform_device *pdev);
static int ptrauth_remove(struct platform_device *pdev);

static int ptrauth_open(struct inode*, struct file*);
static ssize_t ptrauth_read(struct file*, char*, size_t, loff_t*);
static ssize_t ptrauth_write(struct file*, const char*, size_t, loff_t*);
static int ptrauth_release(struct inode*, struct file*);
static int ptrauth_mmap(struct file *fp, struct vm_area_struct *vma);

void ptrauth_sched_switch_probe(void *ignore, bool preempt, struct task_struct *prev, struct task_struct *next);

static char *ptrauth_devnode(const struct device *dev, umode_t *mode);

// ==== Test ====

struct ptrauth_process_info {
    int pid;
    uint64_t key_low;
    uint64_t key_high;
    bool valid;
};

#define MAX_PROCESS 256

static struct ptrauth_process_info process_table[MAX_PROCESS] = {0};

// ==== Character Device ====

static struct ptrauth_device {
    uint64_t priviledged_start;
    uint64_t priviledged_size;

    uint64_t unpriviledged_start;
    uint64_t unpriviledged_size;

    void __iomem *priviledged_base;
    void __iomem *key_high;
    void __iomem *key_low;

    void __iomem *unpriviledged_base;
    void __iomem *plaintext;
    void __iomem *tweak;
    void __iomem *ciphertext;
} global_device;

static struct char_dev {
    struct class *driver_class;
    dev_t device_number;
    struct cdev c_dev;
    struct device *registered_device;
} pa_drvr_data = {
    .driver_class = NULL,
};

static struct file_operations fops = {
    .read = ptrauth_read,
    .write = ptrauth_write,
    .open = ptrauth_open,
    .release = ptrauth_release,
    .mmap = ptrauth_mmap
};

static void ptrauth_set_key(uint64_t key_low, uint64_t key_high) {
    if (key_low != 0) {
        pa_info("[set_key] setting key 0x%016llx%016llx (pid = %d)", key_low, key_high, current->pid);
    }
    writeq(key_low, global_device.key_low);
    writeq(key_high, global_device.key_high);
}

static void ptrauth_clear_ciphertext(void) {
    (void)readq(global_device.ciphertext);
}

static int ptrauth_open(struct inode *inod, struct file *fp) {
    pa_info("[open] fp open\n");
    int process_index = -1;

    for (int i = 0; i < MAX_PROCESS; i++) {
        if (!process_table[i].valid) {
            process_table[i].valid = true;
            process_index = i;
            break;
        }
    }

    if (process_index == -1) {
        pa_err("[open] too many processess open, cannot allocate new one.");
        return -EMFILE;
    }

    pa_info("[open] assigning index %d to process %d\n", process_index, current->pid);

    // Generate a new random key
    get_random_bytes(&process_table[process_index].key_low, sizeof(uint64_t));
    get_random_bytes(&process_table[process_index].key_high, sizeof(uint64_t));

    process_table[process_index].pid = current->pid;

    ptrauth_set_key(process_table[process_index].key_low, process_table[process_index].key_high);

    return 0;
}

static int ptrauth_release(struct inode *inod, struct file *fp) {
    ptrauth_clear_ciphertext();
    ptrauth_set_key(0, 0);

    pa_info("[release] freeing process %d\n", current->pid);
    for (int i = 0; i < MAX_PROCESS; i++) {
        if (process_table[i].pid == current->pid && process_table[i].valid) {
            process_table[i].valid = false;
            process_table[i].key_high = 0;
            process_table[i].key_low = 0;

            pa_info("[release] freed index %d\n", i);
            break;
        }
    }

    return 0;
}

static ssize_t ptrauth_read(struct file *fp, char *user_buffer, size_t user_len, loff_t *off) {
    pa_info("[read] entering read\n");

    uint64_t key_high = readq(global_device.key_high);
    uint64_t key_low = readq(global_device.key_low);

    pa_info("[read] key: %016llx%016llx\n", key_high, key_low);
    return 0;
}

static ssize_t ptrauth_write(struct file *fp, const char *user_buffer, size_t user_len, loff_t *off) {
    pa_info("[write] entering write\n");
    return 0;
}


// ==== Platform Device ====

static struct of_device_id pa_driver_of_match[] = {
	{ .compatible = "daem,PtrauthDevice-1.0", },
	{},
};

MODULE_DEVICE_TABLE(of, pa_driver_of_match);


static struct platform_driver pa_driver = {
    .driver = {
        .name = DRIVER_NAME,
        .owner = THIS_MODULE,
        .of_match_table = pa_driver_of_match,
    },
    .probe = ptrauth_probe,
    .remove = ptrauth_remove
};


static int ptrauth_probe(struct platform_device *pdev) {
    struct resource *regs_first, *regs_second;

    pa_info("[probe] device found\n");

    regs_first  = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    regs_second = platform_get_resource(pdev, IORESOURCE_MEM, 1);

    global_device.priviledged_start = regs_first->start;
    global_device.priviledged_size  = regs_first->end - regs_first->start + 1;

    global_device.unpriviledged_start = regs_second->start;
    global_device.unpriviledged_size  = regs_second->end - regs_second->start + 1;

    global_device.priviledged_base = ioremap(global_device.priviledged_start, global_device.priviledged_size);
    global_device.unpriviledged_base = ioremap(global_device.unpriviledged_start, global_device.unpriviledged_size);

    global_device.key_low  = global_device.priviledged_base;
    global_device.key_high = global_device.priviledged_base + 0x8;

    global_device.plaintext  = global_device.unpriviledged_base + 0x10;
    global_device.tweak      = global_device.unpriviledged_base + 0x18;
    global_device.ciphertext = global_device.unpriviledged_base + 0x20;

    pa_info("[probe] priv: { start: %llx, size: %llx }, unpriv: {start: %llx, size: %llx }\n",
            global_device.priviledged_start, global_device.priviledged_size,
            global_device.unpriviledged_start, global_device.unpriviledged_size);

    return 0;
}

// TODO: Implement
static int ptrauth_remove(struct platform_device *pdev) {
    return 0;
}

static int ptrauth_mmap(struct file *fp, struct vm_area_struct *vma) {
    int status;

    vma->vm_pgoff = global_device.unpriviledged_start >> PAGE_SHIFT;
    pa_info("[mmap] address: %lx\n", vma->vm_pgoff);

    status = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, vma->vm_end - vma->vm_start,vma->vm_page_prot);

    if (status != 0) {
        pa_err("[mmap] cannot remap address space: %d\n", status);
        return -EAGAIN;
    }
    return 0;
}

// ==== Kprobes ====

static int ptrauth_sched_ret(struct kretprobe_instance *ri, struct pt_regs *regs);
static int ptrauth_sched_entry(struct kretprobe_instance *ri, struct pt_regs *regs);

static struct kretprobe kret = {
    .handler = ptrauth_sched_ret,
    .entry_handler = ptrauth_sched_entry,
    .maxactive = MAX_PROCESS,
};

static int ptrauth_sched_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    ptrauth_clear_ciphertext();

    // if (current->pid > 105) {
    //     pa_info("[sched_ret] Scheduling pid %d\n", current->pid);
    // }

    if (kret.nmissed > 0) {
        pa_info("[sched_ret] missed %d schedules\n", kret.nmissed);
    }

    for (int i = 0; i < MAX_PROCESS; i++) {
        if (process_table[i].pid == current->pid && process_table[i].valid) {
            ptrauth_set_key(process_table[i].key_low, process_table[i].key_high);

            return 0;
        }
    }

    ptrauth_set_key(0, 0);

    return 0;
}

static int ptrauth_sched_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
    // pa_info("[sched_entry] before: %d", current->pid);
    return 0;
}


static int ptrauth_register_probe(void) {
    kret.kp.symbol_name = "__switch_to";
    int ret = register_kretprobe(&kret);
    if (ret < 0) {
        pa_info("[register_probe] register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    return 0;
}

// ==== Initialization and Deinitialization ====

static char *ptrauth_devnode(const struct device *dev, umode_t *mode) {
    if (!mode)
        return NULL;

    // rw- rw- rw-
    *mode = 0666;

    return NULL;
}


static int __init ptrauth_init(void) {
    pa_info("[init] starting up...\n");

    if (alloc_chrdev_region(&pa_drvr_data.device_number, 0, 1, DRIVER_NAME) < 0) {
        pa_err("[init] could not allocate device number\n");
        return -1;
    }

    pa_info(
        "[init] device number = %d, major = %d, minor = %d\n",
        pa_drvr_data.device_number,
        MAJOR(pa_drvr_data.device_number),
        MINOR(pa_drvr_data.device_number)
    );

    pa_drvr_data.driver_class = class_create(CLASS_NAME);
    if (IS_ERR(pa_drvr_data.driver_class)) {
        pa_err("[init] could not create class\n");
        unregister_chrdev_region(pa_drvr_data.device_number, 1);
        return -1;
    }

    pa_drvr_data.driver_class->devnode = ptrauth_devnode;

    pa_drvr_data.registered_device = device_create(
        pa_drvr_data.driver_class,
        NULL,
        pa_drvr_data.device_number,
        NULL,
        DEVICE_NAME
    );

    if (IS_ERR(pa_drvr_data.registered_device)) {
        pa_err("[init] device initialization failed\n");
        class_destroy(pa_drvr_data.driver_class);
        unregister_chrdev_region(pa_drvr_data.device_number, 1);
        return -1;
    }

    cdev_init(&pa_drvr_data.c_dev, &fops);

    if (cdev_add(&pa_drvr_data.c_dev, pa_drvr_data.device_number, 1) == -1) {
        pa_err("[init] cdev initialization failed\n");
        device_destroy(pa_drvr_data.driver_class, pa_drvr_data.device_number);
        class_destroy(pa_drvr_data.driver_class);
        unregister_chrdev_region(pa_drvr_data.device_number, 1);
        return -1;
    }

    if (platform_driver_register(&pa_driver) != 0) {
        pa_err("[init] cannot initializing platform driver\n");
        return -1;
    }

    if (ptrauth_register_probe() != 0) {
        return -1;
    }

    pa_info("[init] all done!\n");
    return 0;
}

static void __exit ptrauth_exit(void) {
    cdev_del(&pa_drvr_data.c_dev);
    device_destroy(pa_drvr_data.driver_class, pa_drvr_data.device_number);
    class_destroy(pa_drvr_data.driver_class);
    platform_driver_unregister(&pa_driver);

    pa_info("[exit] module unloaded\n");
}

module_init(ptrauth_init);
module_exit(ptrauth_exit);
