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

// Utilities
#include <linux/errno.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pietro");
MODULE_DESCRIPTION("A kernel module to interface with the ptrauth driver");
MODULE_VERSION("0.1");

#define DRIVER_NAME "ptrauth"
#define DEVICE_NAME "ptrauth"
#define CLASS_NAME "ptrauth"

#define PTRAUTH_DEBUG

#ifdef PTRAUTH_DEBUG
    #define pa_info(...) pr_info(DRIVER_NAME ": " __VA_ARGS__)
#else
    // If debug is disabled, simply do nothing
    #define pa_info(...)
#endif

#define pa_err(...) pr_err(DRIVER_NAME ": " __VA_ARGS__)

// ==== Forward Declarations ====

static int ptrauth_probe(struct platform_device *pdev);
static int ptrauth_remove(struct platform_device *pdev);

static int ptrauth_open(struct inode*, struct file*);
static ssize_t ptrauth_read(struct file*, char*, size_t, loff_t*);
static ssize_t ptrauth_write(struct file*, const char*, size_t, loff_t*);
static int ptrauth_release(struct inode*, struct file*);

static char *ptrauth_devnode(const struct device *dev, umode_t *mode);

// ==== Character Device ====

static struct ptrauth_device {
    void __iomem *base_addr;
    void __iomem *key_high;
    void __iomem *key_low;

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
    .release = ptrauth_release
};

static int ptrauth_open(struct inode *inod, struct file *fp) {
    pa_info("[open] fp open\n");
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

static int ptrauth_release(struct inode *inod, struct file *fp) {
    pa_info("[open] fp closed\n");
    return 0;
}

// ==== Platform Device ====
static struct of_device_id pa_driver_of_match[] = {
	{ .compatible = "todo,Todo-1.0", },
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


// TODO: Implement
static int ptrauth_probe(struct platform_device *pdev) {
    return 0;
}

// TODO: Implement
static int ptrauth_remove(struct platform_device *pdev) {
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

    // NOTE: This should not be done here
    const uint64_t start = 0x80000000;
    const uint64_t size  = 0x00002000;
    global_device.base_addr = ioremap(start, size);
    if (!global_device.base_addr) {
        pa_err("[init] cannot allocate iomem\n");
        return -EIO;
    }

    global_device.key_low = global_device.base_addr;
    global_device.key_high = global_device.base_addr + 0x8;

    global_device.plaintext = global_device.base_addr + 0x1010;
    global_device.tweak = global_device.base_addr + 0x1018;
    global_device.ciphertext = global_device.base_addr + 0x1020;

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
