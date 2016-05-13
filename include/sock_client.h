#ifndef __SOCK_CLIENT_H__
#define __SOCK_CLIENT_H__

#include <string>
#include "sock_base.h"

using namespace std;

class ClientSocket
{
public:
#ifdef HAS_OPENSSL
    ClientSocket(string host, int port, SSL_CTX *sslCtx = NULL);
#else
    ClientSocket(string host, int port);
#endif // HAS_OPENSSL

    virtual ~ClientSocket();

public:
    int Connect();
    int Send(const char *data, uint32_t len);
    int Recv(char *data, uint32_t len);

    int GetFd() { return m_sock->GetFd(); }
    string &GetHost() { return m_host; }
    int GetPort() { return m_port; }
    Socket *GetSocket() { return m_sock; }
    
private:
    Socket      *m_sock;
    string      m_host;
    int         m_port;

#ifdef HAS_OPENSSL
    SSL_CTX     *m_sslCtx;
#endif // HAS_OPENSSL
};


#endif // __SOCK_CLIENT_H__
