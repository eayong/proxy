#ifndef __PROXY_SOCK_SSL_H__
#define __PROXY_SOCK_SSL_H__

#include "sock_base.h"

class SslSocket : public Socket
{
public:
    SslSocket(int fd, int type, SSL_CTX *sslCtx);
    ~SslSocket();

public:
    int InitCtx(SSL_CTX *sslCtx);
    void Finish();
    
    int Send(const char *data, uint32_t len);
    int Recv(char *data, uint32_t len);
    int Handshake();
    void ShowCertificate();
};

#endif // __PROXY_SOCK_SSL_H__

