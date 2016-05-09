#ifndef __PROXY_SOCK_TCP_H__
#define __PROXY_SOCK_TCP_H__

#include <string>
#include "sock_base.h"

using namespace std;

class TcpSocket : public Socket
{
public:
    TcpSocket(int fd);
    ~TcpSocket();

public:
    int Send(const char *data, uint32_t len);
    int Recv(char *data, uint32_t len);
};

#endif // __PROXY_SOCK_TCP_H__

