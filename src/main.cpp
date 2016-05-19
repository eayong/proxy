#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/resource.h>

#include "proxy.h"
#include "BugReport.h"

string g_proxy_host = "172.0.0.1";
int g_proxy_port = 5061;
string g_cert_path = "./proxy.pem";
string g_key_path;
string g_data_file = "./data.txt";
FILE * g_dataFp = NULL;
FILE * g_logFp = NULL;
string g_replaceServ = "12.194.127.36:5061;encoded-parm";
string g_replaceUE = "172.16.71.190:5061;encoded-parm";

#define LOG_FILE "./error.log"

int g_bind_port = 80;
bool g_daemon = false;

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
    printf("\t-d --daemon   : run as daemon.\n");
    printf("\t-s --server   : replace string from server package.\n");
    printf("\t-u --ue       : replace string to UE package.\n");
}

static int Daemon()
{
	int fd0, fd1, fd2;
	pid_t pid;
	struct rlimit rl;
	unsigned i = 0;
	struct sigaction sa;

	umask(0);

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
	{
		return -1;
	}

	if ((pid = fork()) < 0)
	{
		return -1;
	}
	else if (pid != 0)//parent
	{
		exit(0);
	}

	setsid();

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
	{
		return -1;
	}
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
    {
        return -1;
    }

	if ((pid = fork()) < 0)
	{
		return -1;
	}
	else if (pid != 0) //parent
	{
		exit(0);
	}
	
	if (rl.rlim_max == RLIM_INFINITY)
	{
		rl.rlim_max = 1024;
	}

	for (i = 0; i < rl.rlim_max; ++i)
	{
		close(i);
	}

	fd0 = open("/dev/null", O_RDWR);
	if (fd0 < 0)
	{
		return -1;
	}

	fd1 = dup(0);
	fd2 = dup(0);

	if (fd0 != 0 || fd1 != 1 || fd2 != 2)
	{
		return -1;
	}

	return 0;
}

void SetSignal()
{
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
    {
        return;
    }
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
    {
        return;
    }
}

void PrintLog(FILE *fp, const char *format...)
{
    int len = 0;
    va_list ap;
    va_start(ap,format);    
    char buffer[2048] = {0};
    len = vsnprintf(buffer, sizeof(buffer), format, ap);
    buffer[len] = 0;
    char timebuf[256] = {0};
    struct tm tmv;
    time_t timev = time(NULL);
    localtime_r(&timev, &tmv);
    asctime_r(&tmv, timebuf);
    fprintf(fp, "%s", timebuf);
    fprintf(fp, "%s", buffer);
    va_end(ap);
    fflush(fp);
}

void PrintDatetime(FILE *fp)
{
    char timebuf[256] = {0};
    struct tm tmv;
    time_t timev = time(NULL);
    localtime_r(&timev, &tmv);
    asctime_r(&tmv, timebuf);
    fprintf(fp, "%s", timebuf);
}

int main(int argc, char **argv)
{
    const char* short_options = "b:a:p:k:c:f:s:u:hd";
    struct option long_options[] = {
        { "bind",   1,  NULL,   'b' },
        { "addr",   1,  NULL,   'a' },
        { "port",   1,  NULL,   'p' },
        { "key",    1,  NULL,   'k' },
        { "cert",   1,  NULL,   'c' },
        { "file",   1,  NULL,   'f' },
        { "daemon", 0,  NULL,   'd' },
        { "server", 0,  NULL,   's' },
        { "ue",     0,  NULL,   'u' },
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
        case 's':
            g_replaceServ.assign(optarg);
            break;
        case 'u':
            g_replaceUE.assign(optarg);
            break;
        case 'd':
            g_daemon = true;
            break;
        case 'h':
            usage();
            return 0;
        default:
            printf("unkown type %c\n", c);
            break;
        }
    }

    if (g_daemon && Daemon() < 0)
    {
        return -1;
    }

    BugReportRegister(argv[0], ".", NULL, NULL);
    SetSignal();

    g_logFp = fopen(LOG_FILE, "w");
    if (g_logFp == NULL)
    {
        printf("can't open log file %s\n", LOG_FILE);
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
            fclose(g_logFp);
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
