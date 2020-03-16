#pragma once

#include <cstdint>
#include <string>
#include <memory>

class dev_ping {
public:
    dev_ping();
    dev_ping(const std::string &hostname);
    virtual ~dev_ping();

    typedef struct result_s {
        uint16_t    icmp_id;    // id proccess
        uint16_t    icmp_seq;   // sequence number
        uint16_t    icmp_len;   // lenght of icmp packet
        uint8_t     ip_ttl;     // time to live
        double      rtt;        // round trip time
        std::string from_addr;  // ip addres of host
        std::string status;     // status string of result
    } result_t;

    bool check(const std::string &hostname, result_t *result = nullptr);
    bool check(result_t *result = nullptr);
    void setSize(uint16_t size);

private:
    class Impl;
    std::unique_ptr<Impl> impl;
    std::string m_hostname;

private:
    dev_ping(const dev_ping&) = delete;
    dev_ping(const dev_ping&&) = delete;
    dev_ping& operator=(const dev_ping&) = delete;
    dev_ping& operator=(const dev_ping&&) = delete;
};
