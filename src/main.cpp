#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "proxy.h"
#include "BugReport.h"

extern string g_proxy_host;
extern int g_proxy_port;
extern string g_cert_path;
extern string g_key_path;

int g_bind_port = 80;

void usage()
{
    printf("usage:\n");
    printf("\t-h --hellp    : show help\n");
    printf("\t-b --bind     : proxy bind port.\n");
    printf("\t-a --addr     : proxy remote addr.\n");
    printf("\t-p --port     : proxy remote port.\n");
    printf("\t-k --key      : proxy crypto key.\n");
    printf("\t-c --cert     : proxy signature cert.\n");
}


int main(int argc, char **argv)
{
    BugReportRegister(argv[0], ".", NULL, NULL);
    const char* short_options = "b:a:p:k:c:h";
    struct option long_options[] = {
        { "bind",   1,  NULL,   'b' },
        { "addr",   1,  NULL,   'a' },
        { "port",   1,  NULL,   'p' },
        { "key",    1,  NULL,   'k' },
        { "cert",   1,  NULL,   'c' },
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
        case 'h':
            usage();
            return 0;
        default:
            printf("unkown type %c\n", c);
            break;
        }
    }

    if (g_key_path.empty())
        g_key_path = g_cert_path;
    
    printf("proxy is run...\n");
    
    Proxy proxy;
    proxy.Run(g_bind_port);

    printf("proxy is exit...\n");
    return 0;
}
