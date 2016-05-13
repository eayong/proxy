#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h> 
#include <limits.h> 

#include "proxy.h"
#include "BugReport.h"

string g_proxy_host = "172.0.0.1";
int g_proxy_port = 5061;
string g_cert_path = "./proxy.pem";
string g_key_path;
string g_data_file = "./data.txt";
FILE * g_dataFp = NULL;
FILE * g_logFp = NULL;

#define LOG_FILE "error.log"

int g_bind_port = 80;
bool g_deamon = false;

static void usage()
{
    printf("usage:\n");
    printf("\t-h --hellp    : show help\n");
    printf("\t-b --bind     : proxy bind port.\n");
    printf("\t-a --addr     : proxy remote addr.\n");
    printf("\t-p --port     : proxy remote port.\n");
    printf("\t-k --key      : proxy crypto key.\n");
    printf("\t-c --cert     : proxy signature cert.\n");
    printf("\t-f --file     : record recv data file path.\n");
}

static int Deamon(void)
{
    pid_t pid;
    if ((pid = fork()) < 0)
    {
        return -1; //fork失败
    }
    else if (pid > 0)
    {
        exit(0);    //是父进程，结束父进程
    }
    //是第一子进程，后台继续执行
    setsid();//第一子进程成为新的会话组长和进程组长
    
    //并与控制终端分离
    if ((pid = fork()) < 0)
    {
        return -1;  //fork失败，退出
    }
    else if (pid > 0)
    {
        exit(0);    //是第一子进程，结束第一子进程
    }
    
    //是第二子进程，继续
    //第二子进程不再是会话组长
    
    close(0);
    close(1);
    close(2);
    chdir("/tmp");  //改变工作目录到/tmp
    umask(0);   //重设文件创建掩模
    return 0;
}

void PrintLog(FILE *fp, const char *format...)
{
    int len = 0;
    va_list ap;
    va_start(ap,format);    
    char buffer[2048] = {0};
    len = vsnprintf(buffer, sizeof(buffer), format, ap);
    buffer[len] = 0;
    fprintf(fp, "%s", buffer);
    va_end(ap);
    fflush(fp);
}

int main(int argc, char **argv)
{
    BugReportRegister(argv[0], ".", NULL, NULL);

    g_logFp = fopen(LOG_FILE, "w");
    if (g_logFp == NULL)
    {
        printf("can't open log file %s\n", LOG_FILE);
        return -1;
    }
    
    const char* short_options = "b:a:p:k:c:f:hd";
    struct option long_options[] = {
        { "bind",   1,  NULL,   'b' },
        { "addr",   1,  NULL,   'a' },
        { "port",   1,  NULL,   'p' },
        { "key",    1,  NULL,   'k' },
        { "cert",   1,  NULL,   'c' },
        { "file",   1,  NULL,   'f' },
        { "deamon", 0,  NULL,   'd' },
        { "help",   0,  NULL,   'h' },
        { 0, 0, 0, 0},
    };

    int c;
    while((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'b':
            g_bind_port = strtoul(optarg, NULL, 0);
            break;
        case 'a':
            g_proxy_host = optarg;
            break;
        case 'p':
            g_proxy_port = strtoul(optarg, NULL, 0);
            break;
        case 'k':
            g_key_path.assign(optarg);
            break;
        case 'c':
            g_cert_path.assign(optarg);
            break;
        case 'f':
            g_data_file.assign(optarg);
            break;
        case 'd':
            g_deamon = true;
            break;
        case 'h':
            usage();
            return 0;
        default:
            PrintLog(g_logFp, "unkown type %c\n", c);
            break;
        }
    }

    if (g_deamon && Deamon() < 0)
    {
        return -1;
    }

    if (g_key_path.empty())
        g_key_path = g_cert_path;

    if (!g_data_file.empty())
    {
        g_dataFp = fopen(g_data_file.c_str(), "w");
        if (g_dataFp == NULL)
        {
            PrintLog(g_logFp, "can't open log file %s\n", g_data_file.c_str());
            fclose(g_dataFp);
            return -1;
        }
    }

    PrintLog(g_logFp, "proxy is run...\n");
    
    Proxy proxy;
    proxy.Run(g_bind_port);

    if (g_dataFp)
    {
        fclose(g_dataFp);
        g_dataFp = NULL;
    }

    PrintLog(g_logFp, "proxy is exit...\n");

    if (g_logFp)
    {
        fclose(g_logFp);
        g_logFp = NULL;
    }
    
    return 0;
}
