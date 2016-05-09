#ifndef __SOCK_SERVER_H__
#define __SOCK_SERVER_H__

#include "sock_base.h"

using namespace std;

class ServerSocket
{
public:
#ifdef HAS_OPENSSL
    ServerSocket(int port, SSL_CTX *sslCtx = NULL);
#else
    ServerSocket(int port);
#endif // HAS_OPENSSL
    ~ServerSocket();
    
public:
    Socket *Accept();

    int Listen();
    int GetFd() { return m_fd; }
    int GetPort() { return m_port; }
    
    
private:
    int         m_fd;
    int         m_port;
    
#ifdef HAS_OPENSSL
    SSL_CTX     *m_sslCtx;
#endif // HAS_OPENSSL
};

#endif // __SOCK_SERVER_H__

