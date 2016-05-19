#include <signal.h>
#include <assert.h>
#include "proxy.h"

#define DEFAULT_BUFFER_SIZE 10240
#define DEFUALT_REPLACE_BUFFER_SIZE 11264

extern string g_proxy_host;
extern int g_proxy_port;
extern string g_data_file;
extern FILE * g_logFp;
extern FILE *g_dataFp;
extern string g_replaceServ;
extern string g_replaceUE;
extern int g_bind_port;

extern void PrintLog(FILE *fp, const char *format...);
extern void PrintDatetime(FILE *fp);

static void ReplaceString(const char *input, string &output, const char *src, const char *des)
{
    assert(input && src && des);
    int srclen = strlen(src);
    const char *begin = input;
    const char *pos = NULL;
    while (true)
    {
        if ((pos = strstr(begin, src)) != NULL)
        {
            output.append(begin, pos - begin);
            output.append(des);
        }
        else
        {
            output.append(begin);
            break;
        }
        begin = pos + srclen;
    }
}

static void OnReadServer(int fd, short event, void* arg)
{
    SocketPair *pair = (SocketPair*)arg;
    if (pair == NULL)
    {
        return;
    }

    struct sockaddr_in servAddr = pair->remote->GetSocket()->GetRemoteAddr();
    struct sockaddr_in proxyAddr = pair->remote->GetSocket()->GetLocalAddr();
    struct sockaddr_in ueAddr = pair->local->GetRemoteAddr();
    string servIp = inet_ntoa(servAddr.sin_addr);
    int servPort = ntohs(servAddr.sin_port);
    string proxyIp = inet_ntoa(proxyAddr.sin_addr);
    int proxyPort = ntohs(proxyAddr.sin_port);
    string ueIp = inet_ntoa(ueAddr.sin_addr);
    int uePort = ntohs(ueAddr.sin_port);
    
    char data[DEFAULT_BUFFER_SIZE] = {0};
    int len = pair->remote->Recv(data, DEFAULT_BUFFER_SIZE - 1);

    if (len <= 0)
    {
        PrintLog(g_logFp, "[%s:%d->%s:%d] [OnReadServer] Recv Server error.\n",
            servIp.c_str(), servPort, proxyIp.c_str(), proxyPort);
        Proxy::DelSocketPair(pair);
        return;
    }

    
    if (g_dataFp)
    {
        PrintDatetime(g_dataFp);
        fprintf(g_dataFp, "[%s:%d->%s:%d] recv from Server =============================>>\n",
            servIp.c_str(), servPort, proxyIp.c_str(), proxyPort);
        fwrite(data, len, 1, g_dataFp);
        fprintf(g_dataFp, "\n\n");
        fflush(g_dataFp);
    }
    PrintLog(g_logFp, "[%s:%d->%s:%d] recv from Server: len %d\n",
        servIp.c_str(), servPort, proxyIp.c_str(), proxyPort, len);

    string output;
    ReplaceString(data, output, g_replaceServ.c_str(), g_replaceUE.c_str());

    PrintDatetime(g_dataFp);
    fprintf(g_dataFp, "[%s:%d->%s:%d] Send Replace to UE ============ %s -> %s ============>>\n",
        proxyIp.c_str(), proxyPort, ueIp.c_str(), uePort, g_replaceServ.c_str(), g_replaceUE.c_str());
    fwrite(output.c_str(), output.length(), 1, g_dataFp);
    fprintf(g_dataFp, "\n\n");
    fflush(g_dataFp);

    len = pair->local->Send(output.c_str(), output.length());
    if (len <= 0)
    {
        PrintLog(g_logFp, "[%s:%d->%s:%d] [OnReadServer] Send to UE error.\n",
            proxyIp.c_str(), proxyPort, ueIp.c_str(), uePort);
        Proxy::DelSocketPair(pair);
        return;
    }
    
    PrintLog(g_logFp, "[%s:%d->%s:%d] [OnReadClient] Send to UE OK: len %d.\n",
        proxyIp.c_str(), proxyPort, ueIp.c_str(), uePort, len);
}

static void OnReadClient(int fd, short event, void* arg)
{
    SocketPair *pair = (SocketPair*)arg;
    if (pair == NULL)
    {
        return;
    }
    
    struct sockaddr_in servAddr = pair->remote->GetSocket()->GetRemoteAddr();
    struct sockaddr_in proxyAddr = pair->remote->GetSocket()->GetLocalAddr();
    struct sockaddr_in ueAddr = pair->local->GetRemoteAddr();
    string servIp = inet_ntoa(servAddr.sin_addr);
    int servPort = ntohs(servAddr.sin_port);
    string proxyIp = inet_ntoa(proxyAddr.sin_addr);
    int proxyPort = ntohs(proxyAddr.sin_port);
    string ueIp = inet_ntoa(ueAddr.sin_addr);
    int uePort = ntohs(ueAddr.sin_port);


    char data[DEFAULT_BUFFER_SIZE] = {0};
    int len = pair->local->Recv(data, DEFAULT_BUFFER_SIZE - 1);

    if (len <= 0)
    {
        PrintLog(g_logFp, "[%s:%d->%s:%d] [OnReadClient] Recv UE error.\n",
            ueIp.c_str(), uePort, proxyIp.c_str(), g_bind_port);
        Proxy::DelSocketPair(pair);
        return;
    }
    
    if (g_dataFp)
    {
        PrintDatetime(g_dataFp);
        fprintf(g_dataFp, "[%s:%d->%s:%d] recv from UE =================================>>:\n",
            ueIp.c_str(), uePort, proxyIp.c_str(), proxyPort);
        fwrite(data, len, 1, g_dataFp);
        fprintf(g_dataFp, "\n\n");
        fflush(g_dataFp);
    }
    PrintLog(g_logFp, "[%s:%d->%s:%d] recv from UE OK: len %d\n",
        ueIp.c_str(), uePort, proxyIp.c_str(), g_bind_port, len);

    string output;
    ReplaceString(data, output, g_replaceUE.c_str(), g_replaceServ.c_str());

    PrintDatetime(g_dataFp);
    fprintf(g_dataFp, "[%s:%d->%s:%d] Send Replace to Server ============ %s -> %s ==============>>\n",
        proxyIp.c_str(), proxyPort, servIp.c_str(), servPort, g_replaceUE.c_str(), g_replaceServ.c_str());
    fwrite(output.c_str(), output.length(), 1, g_dataFp);
    fprintf(g_dataFp, "\n\n");
    fflush(g_dataFp);

    len = pair->remote->Send(output.c_str(), output.length());
    if (len <= 0)
    {
        PrintLog(g_logFp, "[%s:%d->%s:%d] [OnReadClient] Send to Server error.\n",
            proxyIp.c_str(), proxyPort, servIp.c_str(), servPort);
        Proxy::DelSocketPair(pair);
        return;
    }
    
    PrintLog(g_logFp, "[%s:%d->%s:%d] [OnReadClient] Send to Server OK: len %d.\n",
        proxyIp.c_str(), proxyPort, servIp.c_str(), servPort, len);
}

static void SignalCallBack(int sig, short events, void *user_data)
{
	Proxy *proxy = (Proxy *)user_data;
    proxy->Stop();
}


static void OnAccept(int fd, short event, void* arg)
{
    Proxy *proxy = (Proxy *)arg;
    Socket *local = proxy->GetServer()->Accept();
    if (local == NULL)
    {
        PrintLog(g_logFp, "accept failed with fd %d, reason: %s\n", fd, strerror(errno));
        return;
    }
#ifdef HAS_OPENSSL
    int ret = local->Handshake();
    switch (ret)
    {
    case SOCKET_ERR_NONE:
        break;
    default:
        delete local;
        return;
    }
    
    ClientSocket *remote = new ClientSocket(g_proxy_host, g_proxy_port, proxy->GetSslCtx()->GetCliCtx());
#else
    ClientSocket *remote = new ClientSocket(g_proxy_host, g_proxy_port);
#endif // HAS_OPENSSL
    if (remote == NULL)
    {
        PrintLog(g_logFp, "new remote ssl socket failed.\n");
        delete local;
        return;
    }

    if (remote->Connect() < 0)
    {
        delete local;
        delete remote;
        return;
    }
    
#ifdef HAS_OPENSSL
    ret = remote->GetSocket()->Handshake();
    switch (ret)
    {
    case SOCKET_ERR_NONE:
        break;
    default:
        delete local;
        delete remote;
        return;
    }
#endif

    SocketPair *pair = new SocketPair();
    if (pair == NULL)
    {
        delete local;
        delete remote;
        return;
    }

    pair->local = local;
    pair->remote = remote;
    
    //pair->local->SetNonBlocking();
    //pair->remote->GetSocket()->SetNonBlocking();
    pair->local->SetTimeout(1);
    pair->remote->GetSocket()->SetTimeout(1);

    
    event_assign(&pair->local->GetEvent(), proxy->GetBase(), local->GetFd(), EV_READ|EV_PERSIST, OnReadClient, pair);
    event_assign(&pair->remote->GetSocket()->GetEvent(), proxy->GetBase(), remote->GetFd(), EV_READ|EV_PERSIST, OnReadServer, pair);
    event_add(&pair->local->GetEvent(), NULL);
    event_add(&pair->remote->GetSocket()->GetEvent(), NULL);
    
    Proxy::AddSocketPair(pair);
}

Proxy::SocketPairMap Proxy::m_pair;

Proxy::Proxy()
    :m_port(0), m_server(NULL), m_evBase(NULL)
#ifdef HAS_OPENSSL
    , m_sslCtx(NULL)
#endif // HAS_OPENSSL
{

}

Proxy::~Proxy()
{
    if (m_server)
    {
        delete m_server;
        m_server = NULL;
    }

    SocketPairMap::iterator it = m_pair.begin();
    for (; it != m_pair.end(); it++)
    {
        if (it->second != NULL)
        {
            if (it->second->local)
                delete it->second->local;
            if (it->second->remote)
                delete it->second->remote;
            delete it->second;
        }
    }
}

int Proxy::Init()
{
#ifdef HAS_OPENSSL
    m_sslCtx = new SslContext();
    if (m_sslCtx == NULL)
    {
        PrintLog(g_logFp, "new ssl context failed.\n");
        return -1;
    }

    if (m_sslCtx->Init() < 0)
    {
        PrintLog(g_logFp, "initialize ssl context failed.\n");
        return -1;
    }
    
    m_server = new ServerSocket(m_port, m_sslCtx->GetServCtx());
    if (m_server == NULL)
    {
        PrintLog(g_logFp, "new server ssl socket failed.\n");
        return -1;
    }

#else
    m_server = new ServerSocket(m_port);
    if (m_server == NULL)
    {
        PrintLog(g_logFp, "new server ssl socket failed.\n");
        return -1;
    }
#endif // HAS_OPENSSL

    if (m_server->Listen() < 0)
    {
        PrintLog(g_logFp, "server listen failed.\n");
        return -1;
    }
    return 0;
}

void Proxy::Run(int port)
{
    m_port = port;
    if (Init() < 0)
    {
        return;
    }
    
    struct event *accept_event;
	struct event *signal_event;
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    m_evBase = event_base_new();
    if (m_evBase == NULL)
    {
        PrintLog(g_logFp, "event_base_new failed\n");
        return;
    }
    
    accept_event = event_new(m_evBase, m_server->GetFd(), EV_READ|EV_PERSIST, OnAccept, this);
	if (!accept_event || event_add(accept_event, NULL) < 0)
    {
		PrintLog(g_logFp, "Could not create/add a accept event!\n");
        event_base_free(m_evBase);
        m_evBase = NULL;
		return;
	}
    
	signal_event = evsignal_new(m_evBase, SIGINT, SignalCallBack, (void *)this);
	if (!signal_event || event_add(signal_event, NULL) < 0)
    {
		PrintLog(g_logFp, "Could not create/add a accept event!\n");
	    event_free(accept_event);
        event_base_free(m_evBase);
        m_evBase = NULL;
		return;
	}
    
    event_base_dispatch(m_evBase);
	event_free(accept_event);
	event_free(signal_event);
    event_base_free(m_evBase);
    m_evBase = NULL;
    PrintLog(g_logFp, "stop base dispatch.\n");
}

void Proxy::Stop()
{
	event_base_loopbreak(m_evBase);
}

void Proxy::AddSocketPair(SocketPair *pair)
{
    if (pair == NULL)
    {
        return;
    }

    char key[32] = {0};
    snprintf(key, sizeof(key), "%d+%d", pair->local->GetFd(), pair->remote->GetFd());
    SocketPairMap::iterator it = m_pair.find(key);
    if (it != m_pair.end())
    {
        if (it->second != NULL)
        {
            delete it->second->local;
            delete it->second->remote;
            delete it->second;
        }
        it->second = pair;
    }
    else
    {
        m_pair[key] = pair;
    }
}

void Proxy::DelSocketPair(SocketPair * pair)
{
    if (pair == NULL)
    {
        return;
    }

    char key[32] = {0};
    snprintf(key, sizeof(key), "%d+%d", pair->local->GetFd(), pair->remote->GetFd());
    SocketPairMap::iterator it = m_pair.find(key);
    if (it != m_pair.end())
    {
        m_pair.erase(it);
    }
    event_del(&pair->local->GetEvent());
    event_del(&pair->remote->GetSocket()->GetEvent());
    delete pair->local;
    delete pair->remote;
    delete pair;
    pair = NULL;
}
