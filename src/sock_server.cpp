#include "sock_server.h"
#include "sock_ssl.h"
#include "sock_tcp.h"


#ifdef HAS_OPENSSL
ServerSocket::ServerSocket(int port, SSL_CTX * sslCtx)
    :m_port(port), m_sslCtx(sslCtx)
{
}
#else
ServerSocket::ServerSocket(int port)
    :m_port(port)
{
}
#endif // HAS_OPENSSL

ServerSocket::~ServerSocket()
{
    
}

int ServerSocket::Listen()
{
    m_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_fd < 0)
    {
        printf("initialize socket failed. error: %s\n", strerror(errno));
        return -1;
    }
    
    int yes = 1;
    setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    
    struct sockaddr_in sa_serv;
    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(m_port);   /* Server Port number */

    int ret = bind(m_fd, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
    if (ret < 0)
    {
        printf("bind socket failed. error: %s\n", strerror(errno));
        return -1;
    }

    ret = listen(m_fd, 5);
    if (ret < 0)
    {
        printf("listen socket failed. error: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

// The caller needs to release the Socket
Socket * ServerSocket::Accept()
{
    struct sockaddr_in sa_cli;
    size_t client_len;
    int fd = accept(m_fd, (struct sockaddr*)&sa_cli, (socklen_t*)&client_len);
    if (fd < 0)
    {
        printf("accept socket failed. error: %s\n", strerror(errno));
        return NULL;
    }

    printf("accept client fd %d[%s:%d]\n", fd, inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));

    Socket *sock = NULL;
#ifdef HAS_OPENSSL
    if (m_sslCtx != NULL)
    {
        sock = new SslSocket(fd, m_sslCtx);
    }
    else
    {
        sock = new TcpSocket(fd);
    }
#else
    sock = new TcpSocket(fd);
#endif // HAS_OPENSSL

    if (sock == NULL)
    {
        printf("new socket failed.\n");
        close(fd);
        return NULL;
    }
    
#ifdef HAS_OPENSSL
    if (m_sslCtx)
    {
        int ret = SSL_accept(sock->GetSsl());
        if (ret < 0)
        {
            delete sock;
            return NULL;
        }
    }
#endif

    return sock;
}

