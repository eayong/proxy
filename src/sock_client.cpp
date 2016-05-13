#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>

#include "sock_client.h"
#include "sock_ssl.h"
#include "sock_tcp.h"

extern FILE *g_logFp;
#define TIME_OUT_TIME 5

extern void PrintLog(FILE *fp, const char *format...);

#ifdef HAS_OPENSSL
ClientSocket::ClientSocket(string host, int port, SSL_CTX * sslCtx)
    :m_sock(NULL), m_host(host), m_port(port), m_sslCtx(sslCtx)
{
    
}
#else
ClientSocket::ClientSocket(string host, int port)
    :m_sock(NULL), m_host(host), m_port(port)
{
    
}
#endif // HAS_OPENSSL

ClientSocket::~ClientSocket()
{
    if (m_sock)
    {
        delete m_sock;
        m_sock = NULL;
    }
}

int ClientSocket::Connect()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        PrintLog(g_logFp, "initialize socket failed. error: %s\n", strerror(errno));
        return -1;
    }
    
    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(m_host.c_str());   /* Server IP */
    sa.sin_port        = htons(m_port);          /* Server Port number */

    int error = -1;
    int len = sizeof(int);
    unsigned long ul = 1;
    
    ioctl(fd, FIONBIO, &ul); //设置为非阻塞模式

    bool ret = false;
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == -1)
    {
        struct timeval tm;
        fd_set set;
        tm.tv_sec = TIME_OUT_TIME;
        tm.tv_usec = 0;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        if (select(fd+1, NULL, &set, NULL, &tm) > 0)
        {
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if (error == 0)
                ret = true;
            else
                ret = false;
        } 
        else
            ret = false;
    }
    else ret = true;
    ul = 0;
    ioctl(fd, FIONBIO, &ul); //设置为阻塞模式

    if (!ret) 
    {
        close(fd);
        PrintLog(g_logFp, "connect socket %s:%d failed. error: %s\n",
            m_host.c_str(), m_port, strerror(errno));
        return -1;
    }
    
#ifdef HAS_OPENSSL
    if (m_sslCtx != NULL)
    {
        m_sock = new SslSocket(fd, SOCKET_SSL_CLIENT, m_sslCtx);
    }
    else
    {
        m_sock = new TcpSocket(fd, SOCKET_TCP_CLIENT);
    }
#else
    m_sock = new TcpSocket(fd);
#endif // HAS_OPENSSL

    if (m_sock == NULL)
    {
        PrintLog(g_logFp, "new socket failed.\n");
        close(fd);
        return -1;
    }
    
    return 0;
}

int ClientSocket::Send(const char * data, uint32_t len)
{
    if (m_sock == NULL)
    {
        PrintLog(g_logFp, "socket is not initialized.\n");
        return -1;
    }

    return m_sock->Send(data, len);
}

int ClientSocket::Recv(char * data, uint32_t len)
{
    if (m_sock == NULL)
    {
        PrintLog(g_logFp, "socket is not initialized.\n");
        return -1;
    }

    return m_sock->Recv(data, len);
}


