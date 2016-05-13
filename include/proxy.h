#ifndef __PROXY_H__
#define __PROXY_H__

#include <string>
#include <map>
#include "sock_base.h"
#include "sock_client.h"
#include "sock_server.h"

using namespace std;

typedef struct
{
    Socket          *local;
    ClientSocket    *remote;
}SocketPair;

class Proxy
{
public:
    typedef map<string, SocketPair*> SocketPairMap;
    Proxy();
    ~Proxy();

    void Run(int port = 80);
    void Stop();
    ServerSocket *GetServer() { return m_server; }
    struct event_base *GetBase() { return m_evBase; }

    static void AddSocketPair(SocketPair *pair);
    static void DelSocketPair(SocketPair *pair);

#ifdef HAS_OPENSSL
    SslContext *GetSslCtx() { return m_sslCtx; }
#endif // HAS_OPENSSL  

private:
    int Init();
    
    int             m_port;
    ServerSocket    *m_server;
    struct event_base   *m_evBase;

    static SocketPairMap m_pair;
    
#ifdef HAS_OPENSSL
    SslContext          *m_sslCtx;
#endif // HAS_OPENSSL
};

#endif // __PROXY_H__

