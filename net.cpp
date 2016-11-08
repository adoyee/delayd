#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <tins/tins.h>
#include "net.h"

namespace lonlife{
    
    static uint16_t     ip_id = 345;
    static int          udp_fd = -1;
    static int          raw_fd = -1;
    static uint16_t     udp_port = 0;
    static socklen_t    sock_len = 0;
    static int          sock_buf = 32 * 1024 * 1024;
    static int		zero_buf = 0;
    
    int tot_recv = 0;
    int tot_send = 0;
    using namespace Tins;
    
    bool init(uint16_t port){
        raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(raw_fd < 0){
            perror("Create raw socket failed");
            return false;
        }
        
        int one = 1;
        const int *val = &one;
        int err = setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
        if (err != 0){
            perror("Set raw socket options");
            return false;
        }
        
        err = setsockopt(raw_fd, SOL_SOCKET, SO_SNDBUF, &sock_buf, sizeof(sock_buf));
        if (err != 0){
            perror("Set raw socket send buff");
            return false;
        }

        err = setsockopt(raw_fd, SOL_SOCKET, SO_RCVBUF, &zero_buf, sizeof(zero_buf));
        if (err != 0){
            perror("Set raw socket recv buff");
            return false;
        }
        
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(udp_fd < 0) {
            perror("Create udp socket failed");
            return false;
        }
        
        err = setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUF, &sock_buf, sizeof(sock_buf));
        if (err != 0){
            perror("Set udp socket recv buff");
            return false;
        }
        
        err = setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUF, &zero_buf, sizeof(zero_buf));
        if (err != 0){
            perror("Set udp socket send buff");
            return false;
        }
        sockaddr_in local;
        memset(&local, 0, sizeof(sockaddr_in));
        //local.sin_len = sizeof(sockaddr_in);
        local.sin_port = htons(port);
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        
        err = bind(udp_fd, (sockaddr*)&local, sizeof(sockaddr_in));
        if(err != 0){
            perror("Bind udp socket");
            return false;
        }

        udp_port = port;
        sock_len = sizeof(sockaddr_in);
        return true;
    }
    
    void run(){
        for (;;) {
            detail::read_udp_socket();
        }
    }

    
    namespace detail{
        void send_error(sockaddr_in& remote, int8_t error, void* buff, size_t size){
            auto* msg = (msghdr*)buff;
            msg->error = error;
            msg->dir = dir_down;
            ssize_t s = sendto(udp_fd, msg, size, 0, (struct sockaddr *)&remote, sock_len);
            if(s <= 0){
                printf("send_error error\n");
            }
        }
        
        void read_udp_socket(){
            uint8_t buff[2048];
            sockaddr_in remote;
            socklen_t socklen = sizeof(sockaddr_in);
            memset(&remote, 0, sizeof(sockaddr_in));
            ssize_t size = recvfrom(udp_fd, buff, sizeof(buff), 0, (struct sockaddr*)&remote, &socklen);
            if(size <= 0){
                perror("Read udp socket");
                return;
            }
            tot_recv++;
            if (size < sizeof(msghdr) + sizeof(ip_pair)) {
                perror("Read udp socket too short");
                return;
            }
            if(!check_hops((msghdr*)buff, size)){
                printf("check error\n");
                return;
            }
            
            if(remote.sin_port != htons(udp_port)){
                on_origin_msg(remote, (msghdr*)buff, size);
            } else {
                on_forward_msg((msghdr*)buff , size);
            }
            send_msg((msghdr*)buff, size);
        }
        
        void on_origin_msg(sockaddr_in& remote, msghdr* msg, size_t size){
            msg->cur_hops = 1;
            msg->dir = dir_up;
            msg->origin_port = remote.sin_port;
            msg->origin_size = size;
        }
        
        bool check_hops(const msghdr* msg, size_t size){
            auto total_hops = msg->tot_hops;
            if(total_hops <= 0){
                return false;
            }

            if(size < (sizeof(msghdr) + total_hops * sizeof(ip_pair))){
                return false;
            }

            if((msg->cur_hops > msg->tot_hops) && (msg->dir == dir_down)){
                return false;
            }

            if((msg->cur_hops >= msg->tot_hops) && (msg->dir == dir_up)){
                return false;
            }
            return true;
        }
        
        void send_msg(msghdr* msg, size_t size){
            auto dir = msg->dir;
            auto cur_hop = msg->cur_hops;
            auto tot_hop = msg->tot_hops;
            
            if(cur_hop > tot_hop){
                return;
            }
            
            if(dir == dir_up && tot_hop == 1){
                send_down_last_msg(msg, size);
                return;
            }
            
            if(dir == dir_up && cur_hop < tot_hop){
                send_up_msg(msg, size);
                return;
            }
            
            if(dir == dir_up && cur_hop == tot_hop){
                send_up_last_msg(msg, size);
                return;
            }
            
            
            if(dir == dir_down && cur_hop != 1){
                send_down_msg(msg, size);
                return;
            }
            
            if(dir == dir_down && cur_hop == 1){
                send_down_last_msg(msg, size);
                return;
            }
        }
        
        void on_forward_msg(msghdr* msg, size_t size){
            if(msg->dir == dir_down){
                msg->cur_hops--;
            } else if(msg->dir == dir_up){
                msg->cur_hops++;
            }
        }
        
        void send_up_msg(msghdr* msg, size_t size){
            ip_pair* pair = &msg->ips[msg->cur_hops];
            sockaddr_in src, remote;
            memset(&src, 0 ,sizeof(sockaddr_in));
            memset(&remote, 0, sizeof(sockaddr_in));
            src.sin_addr.s_addr = pair->src;
            src.sin_port = htons(udp_port);
            remote.sin_addr.s_addr = pair->dest;
            remote.sin_port = htons(udp_port);
            send_raw_socket(src, remote, msg, size);
        }
        
        void send_down_msg(msghdr* msg, size_t size){
            ip_pair* pair = &msg->ips[msg->cur_hops-1];
            sockaddr_in src, remote;
            memset(&src, 0 ,sizeof(sockaddr_in));
            memset(&remote, 0, sizeof(sockaddr_in));
            src.sin_addr.s_addr = pair->dest;
            src.sin_port = htons(udp_port);
            remote.sin_addr.s_addr = pair->src;
            remote.sin_port = htons(udp_port);
            send_raw_socket(src, remote, msg, size);
        }
        
        void send_up_last_msg(msghdr* msg, size_t size){
            ip_pair* pair = &msg->ips[msg->cur_hops-1];
            sockaddr_in src, remote;
            memset(&src, 0 ,sizeof(sockaddr_in));
            memset(&remote, 0, sizeof(sockaddr_in));
            src.sin_addr.s_addr = pair->dest;
            src.sin_port = htons(udp_port);
            remote.sin_addr.s_addr = pair->src;
            remote.sin_port = htons(udp_port);
            msg->dir = dir_down;
            send_raw_socket(src, remote, msg, size);
        }
        
        void send_down_last_msg(msghdr* msg, size_t size){
            ip_pair* pair = &msg->ips[msg->cur_hops-1];
            sockaddr_in src, remote;
            memset(&src, 0 ,sizeof(sockaddr_in));
            memset(&remote, 0, sizeof(sockaddr_in));
            src.sin_addr.s_addr = pair->dest;
            src.sin_port = htons(udp_port);
            remote.sin_addr.s_addr = pair->src;
            remote.sin_port = msg->origin_port;
            send_raw_socket(src, remote, msg, size);
        }
        
        void send_raw_socket(sockaddr_in& src, sockaddr_in& remote, msghdr* msg, size_t size){
            Tins::IP ip(IPv4Address(remote.sin_addr.s_addr), IPv4Address(src.sin_addr.s_addr));
            Tins::UDP udp(ntohs(remote.sin_port), ntohs(src.sin_port));
            Tins::RawPDU pdu((const uint8_t*)msg, (uint32_t)size);
            ip.id(ip_id++);
            auto pkt = ip / udp / pdu;
            auto data = pkt.serialize();
	    src.sin_family = AF_INET;
	    int err = bind(raw_fd, (sockaddr*)&src, sizeof(sockaddr_in));
	    if (err != 0){
		perror("Bind raw socket");
	        return;
	    }
            ssize_t s = sendto(raw_fd, data.data(), data.size(), 0, (sockaddr*)&remote, sizeof(sockaddr_in));
            if(s <= 0){
                char buff[256];
                snprintf(buff, sizeof(buff),
                        "Send raw socket %s:%d -> %s:%d",
                        ip.src_addr().to_string().c_str(),
                        udp.sport(),
                        ip.dst_addr().to_string().c_str(),
                        udp.dport());
                perror(buff);
                return;
            }
            tot_send++;
            
        }
    }
} /// namespace lonlife
