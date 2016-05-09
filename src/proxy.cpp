#include <fcntl.h>
#include <signal.h>
#include "proxy.h"

#define DEFAULT_BUFFER_SIZE 65535

string g_proxy_host = "172.0.0.1";
int g_proxy_port = 5061;

static int SetNonBlocking(int fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
    {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void OnReadServer(int fd, short event, void* arg)
{
    SocketPair *pair = (SocketPair*)arg;
    if (pair == NULL)
    {
        return;
    }

    char data[DEFAULT_BUFFER_SIZE] = {0};
    int len = pair->remote->Recv(data, DEFAULT_BUFFER_SIZE - 1);

    if (len <= 0)
    {
        delete pair->local;
        delete pair->remote;
        delete pair;
        event_del(&pair->local_ev);
        event_del(&pair->remote_ev);
        pair = NULL;
        return;
    }

    printf("recv remote: %s\n", data);
    
    len = pair->local->Send(data, len);
    if (len <= 0)
    {
        delete pair->local;
        delete pair->remote;
        event_del(&pair->local_ev);
        event_del(&pair->remote_ev);
        delete pair;
        pair = NULL;
        return;
    }
}

static void OnReadClient(int fd, short event, void* arg)
{
    SocketPair *pair = (SocketPair*)arg;
    if (pair == NULL)
    {
        return;
    }

    char data[DEFAULT_BUFFER_SIZE] = {0};
    int len = pair->local->Recv(data, DEFAULT_BUFFER_SIZE - 1);

    if (len <= 0)
    {
        delete pair->local;
        delete pair->remote;
        delete pair;
        event_del(&pair->local_ev);
        event_del(&pair->remote_ev);
        pair = NULL;
        return;
    }

    printf("recv local: %s\n", data);

    len = pair->remote->Send(data, len);
    if (len <= 0)
    {
        delete pair->local;
        delete pair->remote;
        delete pair;
        event_del(&pair->local_ev);
        event_del(&pair->remote_ev);
        pair = NULL;
        return;
    }
}

static void SignalCallBack(int sig, short events, void *user_data)
{
	Proxy *proxy = (Proxy *)user_data;
    proxy->Stop();
}


static void OnAccept(int fd, short event, void* arg)
{
    Proxy *proxy = (Proxy *)arg;
    struct sockaddr_in cli_addr;
    socklen_t sin_size = sizeof(struct sockaddr_in);
    Socket *local = proxy->GetServer()->Accept();
    if (local == NULL)
    {
        printf("accept failed with fd %d, reason: %s\n", fd, strerror(errno));
        return;
    }
#ifdef HAS_OPENSSL
    ClientSocket *remote = new ClientSocket(g_proxy_host, g_proxy_port, proxy->GetSslCtx()->GetCliCtx());
#else
    ClientSocket *remote = new ClientSocket(g_proxy_host, g_proxy_port);
#endif // HAS_OPENSSL
    if (remote == NULL)
    {
        printf("new remote ssl socket failed.\n");
        delete local;
        return;
    }

    if (remote->Connect() < 0)
    {
        delete local;
        delete remote;
        return;
    }

    SocketPair *pair = new SocketPair();
    if (pair == NULL)
    {
        delete local;
        delete remote;
        return;
    }

    pair->local = local;
    pair->remote = remote;
    
    SetNonBlocking(local->GetFd());
    SetNonBlocking(remote->GetFd());

    proxy->AddSocketPair(pair);

    struct event local_ev, remote_ev;
    event_assign(&pair->local_ev, proxy->GetBase(), local->GetFd(), EV_READ|EV_PERSIST, OnReadClient, pair);
    event_assign(&pair->remote_ev, proxy->GetBase(), remote->GetFd(), EV_READ|EV_PERSIST, OnReadServer, pair);
    event_add(&pair->local_ev, NULL);
    event_add(&pair->remote_ev, NULL);
}

Proxy::Proxy()
    :m_port(0), m_client(NULL), m_server(NULL), m_evBase(NULL)
#ifdef HAS_OPENSSL
    , m_sslCtx(NULL)
#endif // HAS_OPENSSL
{

}

Proxy::~Proxy()
{
    if (m_client)
    {
        delete m_client;
        m_client = NULL;
    }
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
            delete it->second->local;
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
        printf("new ssl context failed.\n");
        return -1;
    }

    if (m_sslCtx->Init() < 0)
    {
        printf("initialize ssl context failed.\n");
        return -1;
    }
    
    m_server = new ServerSocket(m_port, m_sslCtx->GetServCtx());
    if (m_server == NULL)
    {
        printf("new server ssl socket failed.\n");
        return -1;
    }

#else
    m_server = new ServerSocket(m_port);
    if (m_server == NULL)
    {
        printf("new server ssl socket failed.\n");
        return -1;
    }
#endif // HAS_OPENSSL

    if (m_server->Listen() < 0)
    {
        printf("server listen failed.\n");
        return -1;
    }
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
        printf("event_base_new failed\n");
        return;
    }
    
    accept_event = event_new(m_evBase, m_server->GetFd(), EV_READ|EV_PERSIST, OnAccept, this);
	if (!accept_event || event_add(accept_event, NULL) < 0)
    {
		printf("Could not create/add a accept event!\n");
        event_base_free(m_evBase);
        m_evBase = NULL;
		return;
	}
    
	signal_event = evsignal_new(m_evBase, SIGINT, SignalCallBack, (void *)this);
	if (!signal_event || event_add(signal_event, NULL) < 0)
    {
		printf("Could not create/add a accept event!\n");
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
    printf("stop base dispatch.\n");
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
