#include "device_ping.h"

#ifdef _MSC_VER
	#define __WIN32__ 1
	#include <process.h>
#endif

#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#else
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <sys/types.h>

#include <chrono>
#include <thread>
#include <cstring>

#if 0 //DEBUG
#include <cstdio>
#define logPrintf(__fmt, ...) do{printf(__fmt , ##__VA_ARGS__);} while(0)
#else
#define logPrintf(__fmt, ...)
#endif

#define EC_ASSERT(x) \
    do { \
        auto ec = x; \
        if (!ec) { \
            logPrintf("Error line %u, func '%s' return false\n", __LINE__, #x); \
            if (result) result->status.append(impl->status);\
            return ec;\
        } \
    } while(0)

/*!
 * \brief The dev_ping class
 *
 * https://github.com/sotter/ping-cpp/blob/master/ping.cpp
 * https://github.com/dreamcat4/lwip/blob/master/contrib/apps/ping/ping.c
 * https://github.com/matt-kimball/mtr/blob/master/packet/construct_unix.c
 * https://stackoverflow.com/questions/9913661/what-is-the-proper-process-for-icmp-echo-request-reply-on-unreachable-destinatio
 * https://stackoverflow.com/questions/43239862/socket-sock-raw-ipproto-icmp-cant-read-ttl-response
 *
 */
 
/* For Mac OS X and FreeBSD */
#ifndef SOL_IP
	#define SOL_IP IPPROTO_IP
#endif

/*  ICMPv4 type codes  */
#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11

/*  ICMP_DEST_UNREACH codes */
#define ICMP_PORT_UNREACH 3

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

struct ipHeader {
    u_char  ip_hl:4,        /* header length */
        ip_v:4;         /* version */
    u_char  ip_tos;         /* type of service */
    short   ip_len;         /* total length */
    u_short ip_id;          /* identification */
    short   ip_off;         /* fragment offset field */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
    u_char  ip_ttl;         /* time to live */
    u_char  ip_p;           /* protocol */
    u_short ip_sum;         /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


#define MAX_ICMP_SIZE (16 * 1024)

class dev_ping::Impl
{
private:
    uint16_t    m_ping_seq_num = 0;
    sockaddr_in m_dest_addr;
    sockaddr_in m_from_addr;
    char m_send_packet[MAX_ICMP_SIZE];
    char m_recv_packet[MAX_ICMP_SIZE];

    bool socket_is_init     = false;
    bool host_is_resolve    = false;

#ifdef __WIN32__
    SOCKET sock             = INVALID_SOCKET;
    bool wsa_is_init        = false;

#else
    int sock = -1;
#endif
    bool getsockaddr(const char * host, struct sockaddr_in* sockaddr);

    /*  Compute the IP checksum (or ICMP checksum) of a packet.  */
    static uint16_t compute_checksum(const void *packet, int size);

public:
    Impl()
    {
    }
    virtual ~Impl() {
        deinit();
    };
    std::string status;
    uint16_t    m_ping_size_payload = 32;

    bool init();
    bool init_socket();
    bool host_resolve(const std::string &hostname);
    bool send_icmp();
    bool recv_icmp(uint32_t timeout_ms, result_t *result = nullptr);
    bool deinit();
};

dev_ping::dev_ping()
    : impl(std::make_unique<Impl>())
{
    logPrintf("dev_ping()\n");
}

dev_ping::dev_ping(const std::string &hostname)
    : impl(std::make_unique<Impl>())
    , m_hostname(hostname)
{
    logPrintf("dev_ping(%s)\n", hostname.c_str());
}

dev_ping::~dev_ping() {
}

bool dev_ping::check(const std::string &hostname, result_t *result)
{
    m_hostname = hostname;
    return check(result);
}

bool dev_ping::check(result_t *result)
{
    if (result) {
        result->icmp_id     = 0;
        result->icmp_seq    = 0;
        result->icmp_len    = 0;
        result->ip_ttl      = 0;
        result->rtt         = 0;
        result->from_addr.clear();
        result->status.clear();
    }
    EC_ASSERT(impl->init());
    EC_ASSERT(impl->init_socket());
    EC_ASSERT(impl->host_resolve(m_hostname));
    EC_ASSERT(impl->send_icmp());
    EC_ASSERT(impl->recv_icmp(3000, result));
    EC_ASSERT(impl->deinit());
    return true;
}

void dev_ping::setSize(uint16_t size)
{
    if (size > 16 && size < MAX_ICMP_SIZE) {
        impl->m_ping_size_payload = size - 16;
    }
}

bool dev_ping::Impl::init_socket()
{
    // get proto
    protoent *protocol = getprotobyname("icmp");
    if (protocol == NULL) {
        status.append("Ping:        Failed to getprotobyname!\n");
        deinit();
        return false;
    }

#ifdef __APPLE__
    int type = SOCK_DGRAM;
#else
    int type = SOCK_RAW;
#endif

    sock = socket(AF_INET, type, protocol->p_proto); /*IPPROTO_ICMP*/
    if (sock < 0) {
        status.append("Ping:        Failed to create socket! ");
        status.append("Errno: " + std::string(std::to_string(errno)) + " - '" + std::string(std::strerror(errno)) + "'");
        status.append("\n");
        deinit();
        return false;
    }
    socket_is_init = true;

    int size = MAX_ICMP_SIZE;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof(size)) < 0) {
        status.append("Ping:        Failed to setsockopt1!\n");
        deinit();
        return false;
    }

#ifdef __WIN32__
    int val = 1;
    if (setsockopt(sock, SOL_IP, IP_DONTFRAGMENT, (char *)&val, sizeof(val)) < 0) {
#else
#ifdef __APPLE__
    int val = 1;
    if (setsockopt(sock, SOL_IP, IP_HDRINCL, (char *)&val, sizeof(val)) < 0) {
#else // UNIX
    int val = IP_PMTUDISC_DO;
    if (setsockopt(sock, SOL_IP, IP_MTU_DISCOVER , &val, sizeof(val)) < 0) {
#endif // __APPLE__
#endif // __WIN32__
        status.append("Ping:        Failed to setsockopt2!\n");
        deinit();
        return false;
    }

//    struct timeval timeout;
//    timeout.tv_sec  = 1;
//    timeout.tv_usec = 0;

//    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
//        status.append("Ping:        Failed to setsockopt3!\n");
//        deinit();
//        return false;
//    }

//    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
//        status.append("Ping:        Failed to setsockopt4!\n");
//        deinit();
//        return false;
//    }

    return true;
}

bool dev_ping::Impl::host_resolve(const std::string &hostname)
{
    // host resolve
    if (!getsockaddr(hostname.c_str(), &m_dest_addr)) {
        status.append("Ping:        Unknow host '" + hostname + "' !\n");
        deinit();
        return false;
    }

    status.append("Ping: hostname '" + hostname + "' (to ip: " + inet_ntoa(m_dest_addr.sin_addr) + /*", from self iface ip " + inet_ntoa(m_from_addr.sin_addr) +*/ ")\n");

    host_is_resolve = true;
    return true;
}

bool dev_ping::Impl::init()
{
    status.clear();
    // ====================================================================
#ifdef __WIN32__
    if (!wsa_is_init) {
        WSADATA wsadata;
        int err = WSAStartup(MAKEWORD(2,0), &wsadata);
        if (err != 0) {
            status.append("Ping:        WSAStartup failed error " + std::to_string(err) +" !\n");
            return false;
        }
        wsa_is_init = true;
    }
    else {
        status.append("Ping:        WSA is init!\n");
        return false;
    }
#endif
    return true;
}

bool dev_ping::Impl::deinit()
{
    int32_t rv = 0;
    if (host_is_resolve) {
        memset(static_cast<void *>(&m_dest_addr), 0, sizeof(sockaddr_in));
        host_is_resolve = false;
    }
    // 3 ====================================================================
    if (socket_is_init) {
#ifdef __WIN32__
        int32_t err = closesocket(sock);
        if (err) {
            status.append("Ping:        WSA closesocket failed error " + std::to_string(err) +" !\n");
            rv += -1;
        }
        else socket_is_init = false;
        sock = INVALID_SOCKET;
#else
        int32_t err = close(sock);
        if (err) {
            status.append("Ping:        Close socket failed " + std::to_string(errno) +" !\n");
            rv += -1;
        }
        else socket_is_init = false;
        sock = -1;
#endif
    }
    // ====================================================================
#ifdef __WIN32__
    if (wsa_is_init) {
        int err = WSACleanup();
        if (err != 0) {
            status.append("Ping:        WSACleanup failed" + std::to_string(err) +" !\n");
            rv += -1;
        }
        else wsa_is_init = false;
    }
#endif

    return rv ? false : true;
}

bool dev_ping::Impl::send_icmp()
{
    char *data = m_send_packet;
#ifdef _MSC_VER
    uint16_t pid = _getpid() & 0xFFFF;
#else
    uint16_t pid = getpid() & 0xFFFF;
#endif
	

    int size = m_ping_size_payload + sizeof(ICMPHeader) + sizeof(timeval); // MTU

    ICMPHeader *pkt = (ICMPHeader *)data;
    pkt->type       = ICMP_ECHO;
    pkt->code       = 0;
    pkt->checksum   = 0;
    pkt->id         = htons(pid);
    pkt->sequence   = htons(m_ping_seq_num);

#ifdef __WIN32__
    LARGE_INTEGER StartingTime;
    QueryPerformanceCounter(&StartingTime);
    uint64_t time = StartingTime.QuadPart;
#else
    uint64_t time = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
#endif

    memcpy(&data[sizeof(ICMPHeader)], &time, sizeof (time));
    logPrintf("tim1 %u\n", time);

    // fill the additional data buffer with some data
    for(int i = 0; i < m_ping_size_payload; i++) {
        data[sizeof(ICMPHeader) + sizeof(timeval) + i] = '0' + (char)(i & 0x3f);
    }

    // compute checksum of full packet
    pkt->checksum   = htons(compute_checksum(pkt, size));

    int bytes = sendto(sock, data, size, 0, (sockaddr *)&m_dest_addr, sizeof(sockaddr_in));
    if (bytes < 0) {
        status.append("Ping:        Failed to send to receiver!\n");
        deinit();
        return false;
    }
    else if(bytes != size) {
        status.append("Ping:        Failed to write the whole packet ---  bytes: " + std::to_string(bytes) + " sizeof packet: " + std::to_string(size) +"\n");
        deinit();
        return false;
    }

    char buf[128];
    sprintf(buf, "Ping:        send: %s (id %x, seq %u, len %u)\n", inet_ntoa(m_dest_addr.sin_addr), pid, m_ping_seq_num, size);
    status.append(buf);

    m_ping_seq_num ++;

    return true;
}

bool dev_ping::Impl::recv_icmp(uint32_t timeout_ms, result_t *result)
{
    char *data = m_recv_packet;
    int len = 0;
    int maxfds = sock + 1;
    int nfd = 0;
    fd_set rset;
    FD_ZERO(&rset);

    socklen_t fromlen = sizeof(m_from_addr);

    timeval timeout;
    timeout.tv_sec  = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    logPrintf("timeout %u.%u\n", timeout.tv_sec, timeout.tv_usec);

    int size = MAX_ICMP_SIZE;//m_ping_size_payload + sizeof(ICMPHeader) + sizeof(timeval) + sizeof (ipHeader); // MTU

    int retry = 4;
    while (retry --) {

        FD_SET(sock, &rset);
        if ((nfd = select(maxfds, &rset, NULL, NULL, &timeout)) == -1) {
            status.append("Ping:        Select error!\n");
            continue;
        }
        if (nfd == 0) {
            status.append("Ping:        Request timeout!\n");
            continue;
        }

        if (FD_ISSET(sock, &rset)) {
            if ((len = (int)recvfrom(sock, data, size, 0, (struct sockaddr *) &m_from_addr, &fromlen)) < 0) {
                status.append("Ping:        Recvfrom error!\n");
                continue;
            }

            std::string from_addr = inet_ntoa(m_from_addr.sin_addr);
            std::string dest_addr = inet_ntoa(m_dest_addr.sin_addr);
            if (from_addr != dest_addr) {
                status.append("Ping:        Invalid address, discard!\n");
                continue;
            }

            ipHeader *ip = (ipHeader *)data;
            int iphdrlen = ip->ip_hl << 2;

            len -= iphdrlen;
            if (len < 8)  {
                status.append("Ping:        ICMP packets\'s length is less than 8\n");
                break;
            }

            ICMPHeader *icmp = (ICMPHeader *) (&data[iphdrlen]);

            if (icmp->type == ICMP_ECHOREPLY) {
                uint16_t id         = ntohs(icmp->id);
                uint16_t icmpseq    = ntohs(icmp->sequence);
                uint8_t  ttl        = ip->ip_ttl;
                uint16_t icmp_len   = len;
#ifdef __WIN32__
                LARGE_INTEGER Frequency;
                QueryPerformanceFrequency(&Frequency);
                LARGE_INTEGER  EndingTime;
                QueryPerformanceCounter(&EndingTime);
                uint64_t time_recv = EndingTime.QuadPart;
#else
                uint64_t time_recv = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
                logPrintf("tim2 %u\n", time_recv);
#endif
                uint64_t time_send;
                memcpy(&time_send, &data[iphdrlen + sizeof (ICMPHeader)], sizeof (time_send));
#ifdef __WIN32__
                uint64_t time_elapsed = time_recv - time_send;
                time_elapsed *=  1000000;
                time_elapsed /= Frequency.QuadPart;
                double rtt = time_elapsed / 1000000.;
#else
                double rtt = (time_recv - time_send) / 1000000000.;
#endif

                char buf[128];
                sprintf(buf, "Ping:        recv: %s (id %x, seq %u, len %u, ttl %u, time %8.6f us)\n", from_addr.c_str(), id, icmpseq, icmp_len, ttl, rtt);
                status.append(buf);

                if (result) {
                    result->icmp_id     = id;
                    result->icmp_seq    = icmpseq;
                    result->icmp_len    = icmp_len;
                    result->ip_ttl      = ttl;
                    result->rtt         = rtt;
                    result->from_addr   = from_addr;
                    result->status      = status;
                }

                return true;
            }
        }
    }

    if (result) {
        result->icmp_id     = 0;
        result->icmp_seq    = 0;
        result->icmp_len    = 0;
        result->ip_ttl      = 0;
        result->rtt         = 0;
        result->from_addr   = inet_ntoa(m_from_addr.sin_addr);
        result->status      = status;
    }
    deinit();
    return false;
}

bool dev_ping::Impl::getsockaddr(const char *host, sockaddr_in *sockaddr)
{
    memset(static_cast<void *>(sockaddr), 0, sizeof(sockaddr));
    sockaddr->sin_family = AF_INET;

    bool rc = true;
    if (host == NULL || host[0] == '\0') {
        sockaddr->sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
        char c;
        const char *p = host;
        bool is_ipaddr = true;
        while ((c = (*p++)) != '\0') {
            if ((c != '.') && (!((c >= '0') && (c <= '9')))) {
                is_ipaddr = false;
                break;
            }
        }

        if (is_ipaddr) {
            sockaddr->sin_addr.s_addr = inet_addr(host);
        }
        else {
            struct hostent *hostname = gethostbyname(host);
            if (hostname != NULL) {
                memcpy(&(sockaddr->sin_addr), *(hostname->h_addr_list), sizeof(struct in_addr));
            }
            else {
                rc = false;
            }
        }
    }
    return rc;
}

uint16_t dev_ping::Impl::compute_checksum(const void *packet, int size)
{
    const uint8_t *packet_bytes = static_cast<const uint8_t *>(packet);
    uint32_t sum = 0;

    for (int i = 0; i < size; i++) {
        if ((i & 1) == 0) {
            sum += packet_bytes[i] << 8;
        } else {
            sum += packet_bytes[i];
        }
    }

    /* Sums which overflow a 16-bit value have the high bits added back into the low 16 bits. */
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    /* The value stored is the one's complement of the mathematical sum. */
    return (~sum & 0xffff);
}

