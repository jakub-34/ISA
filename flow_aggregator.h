// Author: Jakub Hrdlička, xhrdli18

#ifndef FLOW_AGGREGATOR_H
#define FLOW_AGGREGATOR_H


#include <map>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Structure for flow identification
struct FlowKey{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator<(const FlowKey &other) const{
        return std::tie(src_ip, dst_ip, src_port, dst_port) <
               std::tie(other.src_ip, other.dst_ip, other.src_port, other.dst_port);
    }
};

// Structure for flow statistics
struct FlowStats{
    uint32_t packet_count;
    uint32_t byte_count;
    struct timeval start_time;
    struct timeval end_time;
};

#endif //FLOW_AGGREGATOR_H