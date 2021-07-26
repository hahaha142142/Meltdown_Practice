#include <linux/module.h>	//最小Linux驱动必备
#include <linux/init.h>		//最小Linux驱动必备
#include <linux/kernel.h>	//printk函数 
#include <linux/cdev.h>		//cdev结构体
#include <linux/errno.h>	//EINVAL、ERESTARTSYS和EFAULT错误代码
#include <linux/fs.h>		//各种变量类型和数据结构的定义
#include <linux/uaccess.h>	//copy_to_user函数

#define MEM_SIZE 4096		//表示存储设备的存储空间大小
#define IOCTL 0			//ioctl的cmd为0时调用IOCTL功能

MODULE_LICENSE("Dual BSD/GPL");		//模块的许可证声明
MODULE_DESCRIPTION("Meltdown DEMO");	//模块的描述
MODULE_AUTHOR("ZYY");			//模块的作者

//定义存储设备结构体
struct mem_dev{
    struct cdev char_dev;	//字符设备
    char mem[MEM_SIZE];		//存储空间
    dev_t devno;		//设备号
    struct semaphore sem;	//信号量
};
struct mem_dev memory_dev;

//IO控制
static long mem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
    switch(cmd){		//根据cmd的值调用相应的功能
    case IOCTL:
        printk("<0> memdev.ioctl is called");
        break;
    default:
        return -EINVAL;		//EINVAL为“无效参数”的错误代码，值为22
    }
    
    return 0;
}

//打开和创建文件
static int mem_open(struct inode *inode, struct file *filp){
    int num = MINOR(inode->i_rdev);	//得到次设备号的值
    if(num == 0){
        filp -> private_data = memory_dev.mem;
    }
    return 0;
}

//读操作
static ssize_t mem_read(struct file *filp, char __user *buf, size_t size, loff_t *ppos){
    unsigned long p = *ppos;
    unsigned int count = size;
    int ret = 0;
    char *pmem = memory_dev.mem;		//指向结构体成员的指针
    uint64_t address = (uint64_t)pmem;		//等价于原指针的64位（8字节）地址
    char Secret[]="Secret{XXXXXXXXXX}";		//内核空间中的秘密信息

    strcpy(memory_dev.mem, Secret);		//更新存储设备的存储内容

    if(p >= MEM_SIZE)				//分析和获取有效的读长度
        return 0;
    if(count > MEM_SIZE - p)
        count = MEM_SIZE - p;
    
    if(down_interruptible(&memory_dev.sem))	//等待和获取信号量
        return -ERESTARTSYS;			//ERESTARTSYS为“重启系统调用”的错误代码，值为512
	
    if(copy_to_user(buf,&address,8)){		//将64位（8字节）地址从内核空间的存储位置送入用户空间的缓冲接收
       ret = -EFAULT;				//EFAULT为“无效存储地址”的错误代码，值为14
    }else{
        *ppos += count;				//更新偏移值
        ret = count;
    }
	
    
    up(&memory_dev.sem);			//信号量加一，释放设备资源

    return ret;
}

//关联系统调用和驱动程序的关键结构
const struct file_operations mem_ops = {
    .unlocked_ioctl = mem_ioctl,
    .open = mem_open,
    .read = mem_read
};

//存储设备初始化
static int memdev_init(void){
    int ret = -1;
    char *Secret="No Secret";

    ret = alloc_chrdev_region(&memory_dev.devno,0,1,"memdev");	//请求内核分配一个尚未使用的主设备号

    if (ret >= 0){						//初始化字符设备并注册该设备
        cdev_init(&memory_dev.char_dev,&mem_ops);
        cdev_add(&memory_dev.char_dev,memory_dev.devno,1);
    }

    sema_init(&memory_dev.sem,1);				//初始化该设备的信号量

    strcpy(memory_dev.mem, Secret);				//初始化该设备的存储内容
	
    return ret;
}

//存储设备终止化
static void memdev_exit(void){
    cdev_del(&memory_dev.char_dev);				//释放字符设备占用的存储空间，注销该设备
    unregister_chrdev_region(memory_dev.devno,1);		//释放原先申请的主设备号
}

//关联初始化和终止化函数
module_init(memdev_init);
module_exit(memdev_exit);

