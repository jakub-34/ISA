#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "flow_aggregator.h"
#include "netflow_v5_structure.h"


// Map for storing flow statistics
std::map <FlowKey, FlowStats> flow_map;

// Global variables
uint32_t flow_sequence = 0;
NetFlowV5Record records[30];
int record_count = 0;


// Function to send NetFlow messages
void send_netflow(int sock, struct sockaddr_in *collector_addr, NetFlowV5Header *header, NetFlowV5Record *records, int record_count){
    // Create buffer for NetFlow message
    uint8_t buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    // Copy header to buffer
    memcpy(buffer, header, sizeof(NetFlowV5Header));

    // Copy records to buffer
    memcpy(buffer + sizeof(NetFlowV5Header), records, sizeof(NetFlowV5Record) * record_count);

    // Send NetFlow message via UDP
    ssize_t sent_bytes = sendto(sock, buffer, sizeof(NetFlowV5Header) + sizeof(NetFlowV5Record) * record_count, 0, (struct sockaddr *)collector_addr, sizeof(*collector_addr));
    if(sent_bytes < 0){
        fprintf(stderr, "Error sending NetFlow message\n");
        exit(1);
    }
}


// Create NetFlow header
NetFlowV5Header create_netflow_header(uint16_t record_count, uint32_t flow_sequence){
    NetFlowV5Header header;
    header.version = htons(5);
    header.count = htons(record_count);

    header.sys_uptime = htonl((uint32_t)time(NULL) * 1000);
    header.unix_secs = htonl((uint32_t)time(NULL));
    header.unix_nsecs = htonl(0);
    header.flow_sequence = htonl(flow_sequence);
    header.engine_type = 0;
    header.engine_id = 0;
    header.sampling_interval = htons(0);

    return header;
}


// Create NetFlow record
NetFlowV5Record create_netflow_record(const FlowKey &flow_key, const FlowStats &flow_stats){
    NetFlowV5Record record;
    record.src_ip = flow_key.src_ip;
    record.dst_ip = flow_key.dst_ip;
    record.src_port = htons(flow_key.src_port);
    record.dst_port = htons(flow_key.dst_port);
    record.packets = htonl(flow_stats.packet_count);
    record.bytes = htonl(flow_stats.byte_count);

    // Time flags in miliseconds
    record.first = htonl((flow_stats.start_time.tv_sec * 1000) + (flow_stats.start_time.tv_usec / 1000));
    record.last = htonl((flow_stats.end_time.tv_sec * 1000) + (flow_stats.end_time.tv_usec / 1000));

    record.protocol = IPPROTO_TCP;
    record.tcp_flags = 0;
    record.tos = 0;
    record.next_hop = 0;
    record.input = 0;
    record.output = 0;
    record.src_as = 0;
    record.dst_as = 0;
    record.src_mask = 0;
    record.dst_mask = 0;

    return record;
}


// Print help message
void print_help(){
    printf("Ussage: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]\n");
    printf("<pcap_file_path> - path to PCAP file\n");
    printf("<host> - IP address or domain name of collector\n");
    printf("<port> - port of collector\n");
    printf("-a <active_timout> - number of seconds for active_timeout (default value = 60)\n");
    printf("-i <inactive_timeout> - number of seconds for inactive_timeout (default value = 60)\n");

}


// Check if argument is in format <host>:<port>
int check_host_port(const char *arg){
    return strchr(arg, ':') != NULL;
}


// Check if argument is .pcap file path
int check_pcap_file_path(const char *arg){
    const char *extension = strrchr(arg, '.');
    return extension != NULL && strcmp(extension, ".pcap") == 0;
}


void process_tcp_packet(const struct pcap_pkthdr *header, const u_char *packet, int sock, struct sockaddr_in *collector_addr, int active_timeout, int inactive_timeout){
    struct ip *iph = (struct ip *)(packet + 14);
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);

    FlowKey flow_key;
    flow_key.src_ip = iph->ip_src.s_addr;
    flow_key.dst_ip = iph->ip_dst.s_addr;
    flow_key.src_port = ntohs(tcph->th_sport);
    flow_key.dst_port = ntohs(tcph->th_dport);

    // Find or create new flow
    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    // Flow already exists - update statistics
    if(flow_map.find(flow_key) != flow_map.end()){
        FlowStats &flow = flow_map[flow_key];

        // Check for active timeout
        if((current_time.tv_sec - flow.start_time.tv_sec) >= active_timeout){
            records[record_count++] = create_netflow_record(flow_key, flow);
            flow_map.erase(flow_key);
        }

        // Check for inactive timeout
        else if((current_time.tv_sec - flow.end_time.tv_sec) >= inactive_timeout){
            records[record_count++] = create_netflow_record(flow_key, flow);
            flow_map.erase(flow_key);
        }

        // Update flow statistics
        else{
            flow.packet_count++;
            flow.byte_count += header->len;
            flow.end_time = header->ts;
        }
    }

    // New flow
    else{
        FlowStats new_flow;
        new_flow.packet_count = 1;
        new_flow.byte_count = header->len;
        new_flow.start_time = header->ts;
        new_flow.end_time = header->ts;
        flow_map[flow_key] = new_flow;
    }

    // Send NetFlow message
    if(record_count == 30){
        NetFlowV5Header header = create_netflow_header(record_count, flow_sequence);
        send_netflow(sock, collector_addr, &header, records, record_count);
        flow_sequence++;
        record_count = 0;
    }

    // Debug prints
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(flow_key.src_ip), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(flow_key.dst_ip), dst_ip_str, INET_ADDRSTRLEN);

    printf("TCP Packet: %s -> %s, Packet count: %d, Byte count: %d\n",
           src_ip_str, dst_ip_str, flow_map[flow_key].packet_count, flow_map[flow_key].byte_count);

}


// Function to filter only TCP packets
void process_packet(const struct pcap_pkthdr *header, const u_char *packet, int sock, struct sockaddr_in *collector_addr, int active_timeout, int inactive_timeout){
    struct ip *iph = (struct ip *)(packet + 14);
    if(iph->ip_p == IPPROTO_TCP){
        process_tcp_packet(header, packet, sock, collector_addr, active_timeout, inactive_timeout);
    }
}


// Function to process pcap file
int read_pcap_file(const char *pcap_file_path, int sock, struct sockaddr_in *collector_addr, int active_timeout, int inactive_timeout){
    // Open pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file_path, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Error opening pcap file %s: %s\n", pcap_file_path, errbuf);
        return 1;
    }

    // Process packets
    const u_char *packet;
    struct pcap_pkthdr header;
    while((packet = pcap_next(handle, &header)) != NULL){
        process_packet(&header, packet, sock, collector_addr, active_timeout, inactive_timeout);
    }

    pcap_close(handle);

    // Send remaining NetFlow records
    if(record_count > 0){
        NetFlowV5Header header = create_netflow_header(record_count, flow_sequence);
        send_netflow(sock, collector_addr, &header, records, record_count);
        flow_sequence++;
        record_count = 0;
    }

    return 0;
}


int main(int argc, char *argv[]){

    // Default values
    int active_timeout = 60;
    int inactive_timeout = 60;
    char *host = NULL;
    char *port = NULL;
    char *pcap_file_path = NULL;

    // Parse command line arguments
    int opt;
    while((opt = getopt(argc, argv, "a:i:h")) != -1){
        switch(opt){
            case 'a':
                active_timeout = atoi(optarg);
                break;
            case 'i':
                inactive_timeout = atoi(optarg);
                break;
            case 'h':
                print_help();
                return 0;
            default:
                print_help();
                return 1;
        }
    }

    for(int i = optind; i < argc; i++){
        if(check_host_port(argv[i])){
            char *colon_pos = strchr(argv[i], ':');
            if(colon_pos != NULL){
                *colon_pos = '\0';
                host = argv[i];
                port = colon_pos + 1;
            }
            else{
                fprintf(stderr, "Invalid argument: %s\n", argv[i]);
                return 1;
            }
        }
        else if(check_pcap_file_path(argv[i])){
            pcap_file_path = argv[i];
        }
    }

    // Check if all required arguments are provided
    if(host == NULL || port == NULL || pcap_file_path == NULL){
        fprintf(stderr, "Invalid arguments\n");
        print_help();
        return 1;
    }

    // Set up UDP socket and collector address
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        fprintf(stderr, "Error creating socket\n");
        return 1;
    }

    struct sockaddr_in collector_addr;
    memset(&collector_addr, 0, sizeof(collector_addr));
    collector_addr.sin_family = AF_INET;
    collector_addr.sin_port = htons(atoi(port));
    if(inet_pton(AF_INET, host, &collector_addr.sin_addr) <= 0){
        fprintf(stderr, "Invalid address: %s\n", host);
        return 1;
    }

    // Read pcap file
    if(read_pcap_file(pcap_file_path, sock, &collector_addr, active_timeout, inactive_timeout) != 0){
        return 1;
    }

    close(sock);
    return 0;
}