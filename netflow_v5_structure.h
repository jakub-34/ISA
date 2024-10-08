#ifndef NETFLOW_V5_STRUCTURE_H
#define NETFLOW_V5_STRUCTURE_H

#include <stdint.h>

// Structure for NetFlow v5 header
struct NetFlowV5Header{
    uint16_t version;       // NetFlow export format version number
    uint16_t count;         // Number of flows exported in this packet
    uint32_t sys_uptime;    // Current time in milliseconds since the export device booted
    uint32_t unix_secs;     // Current time
    uint32_t unix_nsecs;    // Nano seconds part of the current time
    uint32_t flow_sequence; // Message sequence number
    uint8_t engine_type;    // Type of flow-switching engine
    uint8_t engine_id;      // ID number of the flow-switching engine
    uint16_t sampling_interval; // Sampling interval
};


// Structure for NetFlow v5 flow record
struct NetFlowV5Record{
    uint32_t src_ip;      // Source IP address
    uint32_t dst_ip;      // Destination IP address
    uint32_t next_hop;      // IP address of next hop router
    uint16_t input;         // SNMP index of input interface
    uint16_t output;        // SNMP index of output interface
    uint32_t packets;       // Packets in the flow
    uint32_t bytes;         // Bytes in the flow
    uint32_t first;         // Start time for the flow
    uint32_t last;          // End time for the flow
    uint16_t src_port;      // Source port
    uint16_t dst_port;      // Destination port
    uint8_t pad1;           // Padding
    uint8_t tcp_flags;      // TCP flags
    uint8_t protocol;           // IP protocol
    uint8_t tos;            // IP type of service
    uint16_t src_as;        // Autonomous system number of the source
    uint16_t dst_as;        // Autonomous system number of the destination
    uint8_t src_mask;       // Source address prefix mask bits
    uint8_t dst_mask;       // Destination address prefix mask bits
    uint16_t pad2;          // Padding
};

#endif //NETFLOW_V5_STRUCTURE_H