#include <bits/stdc++.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <chrono>

volatile sig_atomic_t stop_sniffing = 0;

void interruptHandle(int signal) {
    stop_sniffing = 1;
}

struct HashTuple {
    size_t operator()(const std::tuple<uint32_t, uint32_t, uint16_t, uint16_t>& x) const
    { 
        return ((static_cast<uint64_t>(std::get<0>(x) ^ std::get<1>(x)))<<32) | (((static_cast<uint64_t>(std::get<2>(x))) << 16) & (static_cast<uint64_t>(std::get<3>(x)))); 
    }
};

int main() {
    signal(SIGINT, interruptHandle);
    bool timedout = false;
    sockaddr sendaddr;
    unsigned int saddr_size, data_size, min_size = (1<<16) + 1, max_size = 0, max_packets = 0;
    std::tuple<uint32_t, uint32_t, uint16_t, uint16_t> mptuple;
    long long int total_bytes = 0, total_packets = 0, mal_count = 0;
    unsigned char buffer[(1<<16)-1];
    char srcIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];

    int rawsock = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL));

    FILE* undefprotos = fopen("undefined_protocols.txt", "w");
    FILE* malpackets = fopen("malicious_packets.txt", "w");
    FILE* attackemails = fopen("attackers_email_packets.txt", "w");

    struct iphdr* ipHeader;
    struct tcphdr* tcpHeader;
    struct udphdr* udpHeader;
    struct icmphdr* icmpHeader;
    const uint16_t* sctp_header;

    std::vector<int> data_sizes;
    data_sizes.reserve(300000);

    std::unordered_map<std::tuple<uint32_t, uint32_t, uint16_t, uint16_t>, uint32_t, HashTuple> unique_sd;
    std::unordered_map<uint32_t, uint32_t> src_count, dest_count;
    
    if (rawsock < 0) {
        fprintf(stderr, "Error in creating RAW Socket...\n%s\n", strerror(errno));
        return 1;
    }

    fprintf(stdout, "Started Sniffing...\n\n");
    fflush(stdout);
    std::chrono::time_point<std::chrono::high_resolution_clock> start, stop;
    std::chrono::duration<long long int, std::ratio<1, (long long int) 1e9>> total_time;
    start = std::chrono::high_resolution_clock::now();
    while (!stop_sniffing) {
        saddr_size = sizeof(sendaddr);

        data_size = recvfrom(rawsock, buffer, 1<<16, 0, &sendaddr, (socklen_t*)(&saddr_size));
        
        
        if (data_size < 0) {
            fprintf(stderr, "Error in receiving packets.\n");
            return 1;
        }
        
        if(!stop_sniffing) {
            total_packets++;
            
            total_bytes += data_size;
            min_size = std::min(data_size, min_size);
            max_size = std::max(data_size, max_size);
            data_sizes.push_back(data_size);
            
            ipHeader = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            src_count[ipHeader->saddr]++;
            dest_count[ipHeader->daddr]++;
            
            switch (ipHeader->protocol)
            {
            case IPPROTO_TCP:
                tcpHeader = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ipHeader->ihl*4);
                unique_sd[std::make_tuple(ipHeader->saddr, ipHeader->daddr, ntohs(tcpHeader->source), ntohs(tcpHeader->dest))]++;
                if(ntohs(tcpHeader->dest) == 25) {
                    // insecure SMTP protocol, store the packet as potentially attacker's email.
                    for (int i = 0; i < data_size; i++) {
                        if (isprint(buffer[i])) {
                            fprintf(attackemails, "%c", buffer[i]);
                        } else {
                            fprintf(attackemails, "\\x%02x", buffer[i]);
                        }
                    }
                }
                break;
            case IPPROTO_UDP:
                udpHeader = (struct udphdr*)(buffer + sizeof(struct ethhdr) + ipHeader->ihl*4);
                unique_sd[std::make_tuple(ipHeader->saddr, ipHeader->daddr, ntohs(udpHeader->source), ntohs(udpHeader->dest))]++;
                break;
            case IPPROTO_ICMP:
                unique_sd[std::make_tuple(ipHeader->saddr, ipHeader->daddr, 0, 0)]++;
                break;
            case 128:
                sctp_header = reinterpret_cast<const uint16_t*>(buffer + sizeof(struct ethhdr) + ipHeader->ihl*4);
                unique_sd[std::make_tuple(ipHeader->saddr, ipHeader->daddr, ntohs(sctp_header[0]), ntohs(sctp_header[1]))]++;
                break;
            default:
                fprintf(undefprotos, "%d\n", ipHeader->protocol);
                break;
            }
            
            if(total_packets%50000 == 0)
            fprintf(stdout, "%lld packets received so far...\n", total_packets);

            if (((ipHeader->saddr)<<8) == ((ipHeader->daddr)<<8)) {
                mal_count++;
                inet_ntop(AF_INET, &(ipHeader->saddr), srcIP, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ipHeader->daddr), destIP, INET_ADDRSTRLEN);
                fprintf(malpackets, "%s --> %s\n", srcIP, destIP);
                for (int i = 0; i < data_size; i++) {
                    if (isprint(buffer[i])) {
                        fprintf(malpackets, "%c", buffer[i]);
                    } else {
                        fprintf(malpackets, "\\x%02x", buffer[i]);
                    }
                }
                fprintf(malpackets, "\n\n");
            }

        }
    }
    stop = std::chrono::high_resolution_clock::now();
    total_time = stop - start;
    close(rawsock);
    fclose(undefprotos);
    fclose(malpackets);
    fclose(attackemails);
    FILE* sizeputs = fopen("packet_sizes.txt", "w");
    for(int size : data_sizes)
        fprintf(sizeputs, "%d\n", size);
    fclose(sizeputs);
    FILE* unsdputs = fopen("unique_srcdest_pairs.txt", "w");
    for(auto& val : unique_sd) {
        inet_ntop(AF_INET, &(std::get<0>(val.first)), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(std::get<1>(val.first)), destIP, INET_ADDRSTRLEN);
        fprintf(unsdputs, "%s:%d --> %s:%d\n", srcIP, std::get<2>(val.first), destIP, std::get<3>(val.first));
        if(val.second > max_packets) {
            max_packets = val.second;
            mptuple = val.first;
        }
    }
    fclose(unsdputs);
    FILE* srcputs = fopen("source_ips.txt", "w");
    for(auto& val : src_count) {
        inet_ntop(AF_INET, &val.first, srcIP, INET_ADDRSTRLEN);
        fprintf(srcputs, "%s : %d\n", srcIP, val.second);
    }
    fclose(srcputs);
    FILE* destputs = fopen("dest_ips.txt", "w");
    for(auto& val : dest_count) {
        inet_ntop(AF_INET, &val.first, destIP, INET_ADDRSTRLEN);
        fprintf(destputs, "%s : %d\n", destIP, val.second);
    }
    fclose(destputs);
    inet_ntop(AF_INET, &(std::get<0>(mptuple)), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(std::get<1>(mptuple)), destIP, INET_ADDRSTRLEN);
    fprintf(stdout, "\nMaximum Packets transferred by source-destination pair:\t\t %s:%d --> %s:%d\n", srcIP, std::get<2>(mptuple), destIP, std::get<3>(mptuple));
    fprintf(stdout, "Number of packets transferred by the above pair:\t\t %d\n", max_packets);
    fprintf(stdout, "Average Packet Size received (in bytes):\t\t\t %f\n", ((double)total_bytes/total_packets));
    fprintf(stdout, "Minimum Packet Size received (in bytes):\t\t\t %d\n", min_size);
    fprintf(stdout, "Maximum Packet Size received (in bytes):\t\t\t %d\n", max_size);
    fprintf(stdout, "Total number of malicious packets received:\t\t\t %lld\n", mal_count);
    fprintf(stdout, "Total number of bytes received:\t\t\t\t\t %lld\n", total_bytes);
    fprintf(stdout, "Total number of packets received:\t\t\t\t %lld\n", total_packets);
    fprintf(stdout, "PPS Speed:\t\t\t\t\t\t\t %lf pps\n", ((double)total_packets/(double)(std::chrono::duration_cast<std::chrono::seconds>(total_time)).count()));
    fprintf(stdout, "MBPS Speed:\t\t\t\t\t\t\t %lf MBps\n", ((double)total_bytes/((double)(std::chrono::duration_cast<std::chrono::seconds>(total_time)).count() * 1e6)));
    return 0;
}
