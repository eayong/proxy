#include "sock_client.h"
#include "sock_ssl.h"
#include "sock_tcp.h"

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
        printf("initialize socket failed. error: %s\n", strerror(errno));
        return -1;
    }
    
    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(m_host.c_str());   /* Server IP */
    sa.sin_port        = htons(m_port);          /* Server Port number */

    int ret = connect(fd, (struct sockaddr*)&sa, sizeof(sa));
    if (ret < 0)
    {
        printf("connect socket %s:%d failed. error: %s\n",
            m_host.c_str(), m_port, strerror(errno));
        return -1;
    }
    
#ifdef HAS_OPENSSL
    if (m_sslCtx != NULL)
    {
        m_sock = new SslSocket(fd, m_sslCtx);
    }
    else
    {
        m_sock = new TcpSocket(fd);
    }
#else
    m_sock = new TcpSocket(fd);
#endif // HAS_OPENSSL

    if (m_sock == NULL)
    {
        printf("new socket failed.\n");
        close(fd);
        return -1;
    }

#ifdef HAS_OPENSSL
    if (m_sslCtx)
    {
        ret = SSL_connect(m_sock->GetSsl());
        if (ret < 0)
        {
            delete m_sock;
            m_sock = NULL;
        }
    }
#endif
    
    return 0;
}

int ClientSocket::Send(const char * data, uint32_t len)
{
    if (m_sock == NULL)
    {
        printf("socket is not initialized.\n");
        return -1;
    }

    return m_sock->Send(data, len);
}

int ClientSocket::Recv(char * data, uint32_t len)
{
    if (m_sock == NULL)
    {
        printf("socket is not initialized.\n");
        return -1;
    }

    return m_sock->Recv(data, len);
}


