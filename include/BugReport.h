/*
 * 文件名：bugreport.h
 * 用途：当系统发生异常信号时，写出错日志到指定文件
 * 隐患：在信号处理函数中使用了不可重入函数
 */


#ifndef BUG_REPORT_H
#define BUG_REPORT_H


#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <setjmp.h>
#include <inttypes.h>


/*******************************************
    VARIABLE
*******************************************/

// 出错信息回调函数
typedef void (*pf_info)(const char *msg);
// 出错处理回调函数
typedef void (*pf_exit)(const int sig);


// 堆栈信息数
#ifndef STACK_NUM
#   define STACK_NUM 50
#endif


// 进程名称
static char BR_process_name[PATH_MAX] = "";
// 日志路径
static char BR_log_dir_path[PATH_MAX] = "/home/petra/bugreport";

static pf_info BR_pf_info;
static pf_exit BR_pf_exit;
static int BR_dumping_stack = 0; //是否正在打印堆栈信息,调试用
static sigjmp_buf BR_jmp_buf; //信号跳转jmp 


/*******************************************
    SIGNAL
*******************************************/
/*
 * #include <bits/signum.h> in kernel 2.4.x
 * Signals

#define SIGHUP          1       // Hangup (POSIX).
#define SIGINT          2       // Interrupt (ANSI).
#define SIGQUIT         3       // Quit (POSIX).
#define SIGILL          4       // Illegal instruction (ANSI).
#define SIGTRAP         5       // Trace trap (POSIX).
#define SIGABRT         6       // Abort (ANSI).
#define SIGIOT          6       // IOT trap (4.2 BSD).
#define SIGBUS          7       // BUS error (4.2 BSD).
#define SIGFPE          8       // Floating-point exception (ANSI).
#define SIGKILL         9       // Kill, unblockable (POSIX).
#define SIGUSR1         10      // User-defined signal 1 (POSIX).
#define SIGSEGV         11      // Segmentation violation (ANSI).
#define SIGUSR2         12      // User-defined signal 2 (POSIX).
#define SIGPIPE         13      // Broken pipe (POSIX).
#define SIGALRM         14      // Alarm clock (POSIX).
#define SIGTERM         15      // Termination (ANSI).
#define SIGSTKFLT       16      // Stack fault.
#define SIGCLD          SIGCHLD // Same as SIGCHLD (System V).
#define SIGCHLD         17      // Child status has changed (POSIX).
#define SIGCONT         18      // Continue (POSIX).
#define SIGSTOP         19      // Stop, unblockable (POSIX).
#define SIGTSTP         20      // Keyboard stop (POSIX).
#define SIGTTIN         21      // Background read from tty (POSIX).
#define SIGTTOU         22      // Background write to tty (POSIX).
#define SIGURG          23      // Urgent condition on socket (4.2 BSD).
#define SIGXCPU         24      // CPU limit exceeded (4.2 BSD).
#define SIGXFSZ         25      // File size limit exceeded (4.2 BSD).
#define SIGVTALRM       26      // Virtual alarm clock (4.2 BSD).
#define SIGPROF         27      // Profiling alarm clock (4.2 BSD).
#define SIGWINCH        28      // Window size change (4.3 BSD, Sun).
#define SIGPOLL         SIGIO   // Pollable event occurred (System V).
#define SIGIO           29      // I/O now possible (4.2 BSD).
#define SIGPWR          30      // Power failure restart (System V).
#define SIGSYS          31      // Bad system call.
#define SIGUNUSED       31

 */
static const char BR_signals[32][32] = {
"SIGNONE",           // 0
"SIGHUP",            // 1
"SIGINT",            // 2
"SIGQUIT",           // 3
"SIGILL",            // 4
"SIGTRAP",           // 5
"SIGABRT | SIGIOT",  // 6
"SIGBUS",            // 7
"SIGFPE",            // 8
"SIGKILL",           // 9
"SIGUSR1",           // 10
"SIGSEGV",           // 11
"SIGUSR2",           // 12
"SIGPIPE",           // 13
"SIGALRM",           // 14
"SIGTERM",           // 15
"SIGSTKFLT",         // 16
"SIGCHLD | SIGCLD",  // 17
"SIGCONT",           // 18
"SIGSTOP",           // 19
"SIGTSTP",           // 20
"SIGTTIN",           // 21
"SIGTTOU",           // 22
"SIGURG",            // 23
"SIGXCPU",           // 24
"SIGXFSZ",           // 25
"SIGVTALRM",         // 26
"SIGPROF",           // 27
"SIGWINCH",          // 28
"SIGIO | SIGPOLL",   // 29
"SIGPWR",            // 30
"SIGSYS | SIGUNUSED" // 31
};

/*
  *函数功能：打印堆栈顶部1KB数据
  *参数 [IN] log_fd:BUGREPORT日志文件句柄
  *参数 [IN] stack_top:堆栈顶部首地址
  *返回值:成功返回0，参数不正确返回-1
*/
static int BR_DumpStack1K(int log_fd, struct sigcontext* sc)
{
#define STACK_DATA_STRING "\nStack Data:\n"
#define STACK_DWORD_1K      1024
#define STACK_BELOW_128     128

#ifndef __x86_64__
	#define STACK_DWORD_PER_LINE 4
	typedef uint32_t dword_t;
    const dword_t* stack_top = (const dword_t*)sc->esp;
    const dword_t* stack_begin = (const dword_t*)sc->ebp;
#else
	#define STACK_DWORD_PER_LINE 8
	typedef uint64_t dword_t;
    const dword_t* stack_top = (const dword_t*)sc->rsp;
    const dword_t* stack_begin = (const dword_t*)sc->rbp;
#endif // __x86_64__

    int i = -2; //多打印32个字节，针对踩堆栈导致函数返回后才出现问题的情况
    int loop_cnt = STACK_DWORD_1K/(sizeof(dword_t)*STACK_DWORD_PER_LINE);
    char hex_buf[128] = {0};    
    static int cause_fault_flag = 0;
    int next_loop_cnt = 0;
    BR_dumping_stack = 1;
    
    if(write(log_fd, STACK_DATA_STRING, strlen(STACK_DATA_STRING)) < 0)
    {
        return -1;
    }
    if(stack_begin - stack_top > 2*STACK_DWORD_1K)
    {
        next_loop_cnt = (STACK_DWORD_1K+STACK_BELOW_128)/(sizeof(dword_t)*STACK_DWORD_PER_LINE);
        stack_begin = stack_begin - STACK_DWORD_1K;
    }
    else if(stack_begin - stack_top > STACK_DWORD_1K)
    {
        next_loop_cnt = (stack_begin - stack_top+STACK_BELOW_128)/(sizeof(dword_t)*STACK_DWORD_PER_LINE);
        stack_begin = stack_top + STACK_DWORD_1K;
    }
BR_DUMP_NEXT:
    for(; i < loop_cnt; ++i)
    {
        if(sigsetjmp(BR_jmp_buf, 1) == 0)
        {
#ifndef __x86_64__
            snprintf(hex_buf, sizeof(hex_buf), "%p:\t%08x %08x %08x %08x\n"
#else
            snprintf(hex_buf, sizeof(hex_buf), "%p:\t%012"PRIx64" %012"PRIx64" %012"PRIx64" %012"PRIx64"\n"
#endif // __x86_64__
            , stack_top + i*STACK_DWORD_PER_LINE
            , *(stack_top + i*STACK_DWORD_PER_LINE)
            , *(stack_top + i*STACK_DWORD_PER_LINE + 1)
            , *(stack_top + i*STACK_DWORD_PER_LINE + 2)
            , *(stack_top + i*STACK_DWORD_PER_LINE + 3)); 
            
            if(write(log_fd, hex_buf, strlen(hex_buf)) < 0)
            {
                return -1;
            }
        }
        else
        {
            cause_fault_flag = 1;
            break;
        }
    }
    if(next_loop_cnt != 0 && cause_fault_flag ==0)
    {
        stack_top = stack_begin;
        loop_cnt = next_loop_cnt;
        next_loop_cnt = 0;
        goto BR_DUMP_NEXT;
    }
    BR_dumping_stack = 0;
    
    return 0;
}

/*
 *函数功能:打印寄存器信息到BUGREPORT
 *参数 [IN] log_fd:BUGREPORT日志文件句柄
 *参数 [IN] sc:出现信号时的线程上下文
 *返回值:成功返回0，参数不正确返回-1
*/
static int BR_WriteRegInfo(int log_fd,struct sigcontext* sc)
{
    char reg_buf[1024] = {0};    
    if(log_fd == -1 || sc == NULL)
    {
        return -1;
    }

#ifndef __x86_64__    
    snprintf(reg_buf, sizeof(reg_buf), 
        "\nRegisters:\n"
        "\tEAX=%08x\n"
        "\tEBX=%08x\n"
        "\tECX=%08x\n"
        "\tEDX=%08x\n"
        "\tEDI=%08x\n"
        "\tESI=%08x\n"
        "\tEIP=%08x\n"
        "\tEBP=%08x\n"
        "\tESP=%08x\n"
        "\tEFLAGS=%08x\n"
        "\tLast Access Address=%08x\n" //最后访问地址
        , (unsigned int)sc->eax, 
          (unsigned int)sc->ebx, 
          (unsigned int)sc->ecx,
          (unsigned int)sc->edx,
          (unsigned int)sc->edi,
          (unsigned int)sc->esi,
          (unsigned int)sc->eip,
          (unsigned int)sc->ebp,
          (unsigned int)sc->esp,
          (unsigned int)sc->eflags,
          (unsigned int)sc->cr2);
#else
    snprintf(reg_buf, sizeof(reg_buf), 
        "\nRegisters:\n"
        "\tRAX=%012"PRIx64"\n"
        "\tRBX=%012"PRIx64"\n"
        "\tRCX=%012"PRIx64"\n"
        "\tRDX=%012"PRIx64"\n"
        "\tRDI=%012"PRIx64"\n"
        "\tRSI=%012"PRIx64"\n"
        "\tRIP=%012"PRIx64"\n"
        "\tRBP=%012"PRIx64"\n"
        "\tRSP=%012"PRIx64"\n"
        "\tEFLAGS=%012"PRIx64"\n"
        "\tLast Access Address=%012"PRIx64"\n" //最后访问地址
        , sc->rax, 
          sc->rbx, 
          sc->rcx,
          sc->rdx,
          sc->rdi,
          sc->rsi,
          sc->rip,
          sc->rbp,
          sc->rsp,
          sc->eflags,
          sc->cr2);
#endif // __x86_64__

    if(write(log_fd, reg_buf, strlen(reg_buf)) < 0)
    {
        return -1;
    }
    return 0;
}

/*
 *函数功能:打印进程模块列表
 *参数 [IN] log_fd:BUGREPORT日志文件句柄
 *返回值: 成功返回0,失败返回-1
*/
static int BR_WriteModuleInfo(int log_fd)
{
    char proc_modules[128] = {0};
    char proc_buf[1024] = {0};
    int proc_fd = -1;
    int read_len = 0;
    int ret = 0;
    snprintf(proc_modules, sizeof(proc_modules), "/proc/%d/maps", getpid());
    proc_fd = open(proc_modules, O_RDONLY);
    if(proc_fd < 0)
    {
        return -1;
    }

    if(write(log_fd , "\nProcess Modules:\n", strlen("\nProcess Modules:\n")) < 0)
    {
        close(proc_fd);
        return -1;
    }

    while((read_len = read(proc_fd, proc_buf, sizeof(proc_buf))) > 0)
    {
        if(write(log_fd, proc_buf, read_len) < 0)
        {
            ret = -1;
            break;
        }
    }

    close(proc_fd);
    return ret;
}

/*******************************************
    FUNCTION
*******************************************/

/*
 * 函数名：BR_WriteErrorMsg
 * 功能：写出错信息（堆栈信息）到指定文件，供bugreport上传
 * 返回值：-1：失败 0：成功
 */
static int BR_WriteErrorMsg(const int sig, const char *process_name, const char *log_dir_path, struct sigcontext* sc)
{
    int size = 0;
    int logfd = -1;
    int memfd = -1;
    void *array[STACK_NUM] = {};
    char buf[1024] = "";
    int ret = -1;

    // 确定文件名
    (void)snprintf(buf, sizeof(buf), "%s/%s.txt", log_dir_path, process_name);

    // 采用覆盖写，防止产生过大的日志文件
    if ((logfd = open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0666)) < 0)
    {
        goto Clean;
    }

    // 写入时间日期、进程名、进程号、信号值
    (void)snprintf(buf, sizeof(buf), "%ld\n\nPROCESS: %s PID: %d SIGNAL: %d{%s}\n\nSTACK: \n",
                   time(NULL), process_name, (int)getpid(), sig, BR_signals[sig]);
    if (write(logfd, buf, strlen(buf)) < 0)
    {
        goto Clean;
    }

    // 取得堆栈信息
    size = backtrace(array, STACK_NUM);
    backtrace_symbols_fd(array, size, logfd);

    // 写入内存信息
    if ((memfd = open("/proc/meminfo", O_RDONLY)) < 0)
    {
        goto Clean;
    }
    if ((size = (int)read(memfd, buf, sizeof(buf))) < 0)
    {
        goto Clean;
    }
    if (write(logfd, buf, (size_t)size) < 0)
    {
        goto Clean;
    }

    if(BR_WriteRegInfo(logfd, sc) < 0)
    {
        goto Clean;
    }

    if(BR_WriteModuleInfo(logfd) < 0)
    {
        goto Clean;
    }
    
    //other information
    
    if(BR_DumpStack1K(logfd, sc) < 0)
    {
        goto Clean;
    }
        
    ret = 0;

Clean:
    if (logfd != -1)
    {
        (void)close(logfd);
    }
    if (memfd != -1)
    {
        (void)close(memfd);
    }

    return ret;
}

/*
 * 函数名：BR_SignalHandler
 * 功 能：BugReport信号处理函数
 */
static void BR_SignalHandler(const int sig, struct sigcontext sc)
{
    int old_errno = errno;
    switch (sig)
    {
    case SIGILL:
    case SIGFPE:
    case SIGBUS:
    case SIGABRT:
    case SIGSEGV:
        {
            static int s_first = 0;
            if (s_first == 0)
            {
                // 防止在多线程环境下该处理函数被调用多次
                s_first++;

                (void)BR_WriteErrorMsg(sig, BR_process_name, BR_log_dir_path, &sc);

                // 调用出错信息回调函数
                if (BR_pf_info != NULL)
                {
                    BR_pf_info(BR_signals[sig]);
                }
                // 调用出错处理回调函数
                if (BR_pf_exit != NULL)
                {
                    BR_pf_exit(sig);
                }
            }
            else if(BR_dumping_stack) 
            {
                /*
                    打印堆栈时候再次出现段错误
                    这种判断方式在多线程多次出现段错误时可能不大准确，但是仅影响一部分堆栈不会打印出来，其他处理正常
                */
                siglongjmp(BR_jmp_buf, 1);
                
                //never execute here
            }
            (void)signal(sig, SIG_DFL);
            (void)raise(sig); // 重新生成该信号
        }
        break;
    default:
        break;
    }
    errno = old_errno;
}

/*
 * 函数名：BR_SignalRegister
 * 功 能：BugReport信号注册函数
 */
static int BR_SignalRegister(int sig)
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = (__sighandler_t)BR_SignalHandler;
    act.sa_flags = 0;
    (void)sigemptyset(&act.sa_mask);

    while (sigaction(sig, &act, NULL) < 0)
    {
        if (errno != EINTR)
        {
            (void)fprintf(stderr, "[BugReport]sigaction %s failed: %s\n", BR_signals[sig], strerror(errno));
            return -1;
        }
    }

    return 0;
}

/*
 * 函数名：BugReportRegister
 * 功能：注册BugReport功能，如果发生SIGILL，SIGFPE，SIGBUS，SIGABRT，SIGSEGV信号将按格式写出错信息到指定路径文件（供bugreport上传使用）
 * 参数：
 * [IN] process_name
 * 调用的进程名，不能为NULL
 * [IN] log_dir_path
 * 日志文件存放路径，NULL使用默认路径"/home/petra/bugreport"
 * [IN] pfinfo
 * 出错信息回调函数，NULL不做处理
 * [IN] pfexit
 * 出错处理回调函数，NULL不做处理
 *
 * 返回值：0：注册成功 -1：注册失败
 */
static int BugReportRegister(const char *process_name, /*@null@*/const char *log_dir_path, /*@null@*/pf_info pfinfo, /*@null@*/pf_exit pfexit)
{
    if (process_name != NULL)
    {
        (void)snprintf(BR_process_name, sizeof(BR_process_name), "%s", process_name);
    }
    else
    {
        errno = EINVAL;
        return -1;
    }

    if (log_dir_path != NULL)
    {
        (void)snprintf(BR_log_dir_path, sizeof(BR_log_dir_path), "%s", log_dir_path);
    }

    BR_pf_info = pfinfo;
    BR_pf_exit = pfexit;

    if (BR_SignalRegister(SIGILL)  < 0
     || BR_SignalRegister(SIGFPE)  < 0
     || BR_SignalRegister(SIGBUS)  < 0
     || BR_SignalRegister(SIGABRT) < 0
     || BR_SignalRegister(SIGSEGV) < 0)
    {
        return -1;
    }

    return 0;
}

/* UNIX风格接口 */
#define bugreport_register BugReportRegister

/* JAVA风格接口 */
#define bugreportRegister  BugReportRegister


/*******************************************
    USAGE
*******************************************/

/*

#include "BugReport.h"

static int g_running = 1;

static void exp_info(const char *msg)
{
    printf("catch signal %s\n", msg);
}

static void exp_exit(const int sig)
{
    g_running = 0;
}

// 在主函数开始处调用BugReportRegister函数
int main(void)
{
    // 注意所传的日志文件存放路径必须是已经存在的路径
    (void)BugReportRegister("fool", ".", exp_info, exp_exit);

    printf("begin!\n");

    // waiting for crash
    while (g_running != 0)
    {
        (void)sleep(1);
        printf("running...\n");
    }

    printf("end!\n");
    return 0;
}

// link -rdynamic

*/

#endif // BUG_REPORT_H

// splint BugReport.h +posixlib -globstate -compdestroy

// vi:ts=8:nowrap

