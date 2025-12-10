#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/kernel.h>

#define CPUMON_DEV_NAME "cpumon"

static int cpumon_major;
static struct cdev cpumon_cdev;
static struct class *cpumon_class;

/* open */
static int cpumon_open(struct inode *inode, struct file *file)
{
    pr_info("cpumon: device opened\n");
    return 0;
}

/* release */
static int cpumon_release(struct inode *inode, struct file *file)
{
    pr_info("cpumon: device closed\n");
    return 0;
}

/* read() : CPU 상태 문자열 반환 */
static ssize_t cpumon_read(struct file *file, char __user *buf,
                           size_t len, loff_t *offset)
{
    struct file *f;
    loff_t pos = 0;
    char stat_buf[256];
    char out_buf[512];
    int ret;

    unsigned long long user, nice, system, idle;
    unsigned long long iowait, irq, softirq, steal;
    unsigned long long uptime_sec;
    int out_len;

    if (*offset > 0)
        return 0;

    /* /proc/stat 읽기 */
    f = filp_open("/proc/stat", O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("cpumon: failed to open /proc/stat\n");
        return PTR_ERR(f);
    }

    ret = kernel_read(f, stat_buf, sizeof(stat_buf) - 1, &pos);
    filp_close(f, NULL);

    if (ret <= 0) {
        pr_err("cpumon: failed to read /proc/stat\n");
        return ret < 0 ? ret : -EIO;
    }

    stat_buf[ret] = '\0';

    ret = sscanf(stat_buf,
                 "cpu  %llu %llu %llu %llu %llu %llu %llu %llu",
                 &user, &nice, &system, &idle,
                 &iowait, &irq, &softirq, &steal);
    if (ret < 4)
        return -EINVAL;

    /* uptime */
    uptime_sec = ktime_get_boottime_seconds();

    /* 한국어 기반 보기 쉬운 출력 */
    out_len = snprintf(out_buf, sizeof(out_buf),
        "===== CPU 상태 모니터 (/dev/cpumon) =====\n"
        "일반 프로그램 수행 시간: %llu\n"
        "낮은 우선순위 작업 시간: %llu\n"
        "운영체제 작업 시간: %llu\n"
        "대기 시간(작업 없음): %llu\n"
        "디스크/장치 대기 시간: %llu\n"
        "하드웨어 인터럽트 처리 시간: %llu\n"
        "소프트웨어 인터럽트 처리 시간: %llu\n"
        "CPU 사용 순서를 기다린 시간: %llu\n"
        "부팅 이후 경과 시간: %llu초\n",
        user, nice, system, idle,
        iowait, irq, softirq, steal,
        uptime_sec
    );

    if (copy_to_user(buf, out_buf, out_len))
        return -EFAULT;

    *offset += out_len;
    return out_len;
}

static const struct file_operations cpumon_fops = {
    .owner   = THIS_MODULE,
    .open    = cpumon_open,
    .release = cpumon_release,
    .read    = cpumon_read,
};

static int __init cpumon_init(void)
{
    int ret;
    dev_t dev;

    ret = alloc_chrdev_region(&dev, 0, 1, CPUMON_DEV_NAME);
    if (ret < 0)
        return ret;

    cpumon_major = MAJOR(dev);

    cdev_init(&cpumon_cdev, &cpumon_fops);
    cdev_add(&cpumon_cdev, dev, 1);

    cpumon_class = class_create(CPUMON_DEV_NAME);
    if (IS_ERR(cpumon_class)) {
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(cpumon_class);
    }

    device_create(cpumon_class, NULL, dev, NULL, CPUMON_DEV_NAME);

    pr_info("cpumon: loaded /dev/cpumon\n");
    return 0;
}

static void __exit cpumon_exit(void)
{
    dev_t dev = MKDEV(cpumon_major, 0);

    device_destroy(cpumon_class, dev);
    class_destroy(cpumon_class);
    cdev_del(&cpumon_cdev);
    unregister_chrdev_region(dev, 1);

    pr_info("cpumon: unloaded\n");
}

module_init(cpumon_init);
module_exit(cpumon_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Virtual CPU Monitoring Driver");
