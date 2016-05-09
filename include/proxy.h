#ifndef __PROXY_H__
#define __PROXY_H__

#include <string>
#include <map>
#include "sock_base.h"
#include "sock_client.h"
#include "sock_server.h"
#include "event.h"

using namespace std;

typedef struct
{
    Socket          *local;
    ClientSocket    *remote;
    struct event    local_ev;
    struct event    remote_ev;
}SocketPair;

class Proxy
{
public:
    typedef map<string, SocketPair*> SocketPairMap;
    Proxy();
    ~Proxy();

    void Run(int port = 80);
    void Stop();
    ClientSocket *GetClient() { return m_client; }
    ServerSocket *GetServer() { return m_server; }
    struct event_base *GetBase() { return m_evBase; }

    void AddSocketPair(SocketPair *pair);

#ifdef HAS_OPENSSL
    SslContext *GetSslCtx() { return m_sslCtx; }
#endif // HAS_OPENSSL  

private:
    int Init();

    int             m_port;
    ClientSocket    *m_client;
    ServerSocket    *m_server;
    struct event_base   *m_evBase;

    SocketPairMap m_pair;
    
#ifdef HAS_OPENSSL
    SslContext          *m_sslCtx;
#endif // HAS_OPENSSL
};

#endif // __PROXY_H__

