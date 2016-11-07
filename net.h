#pragma once


#include <stdint.h>
#include <stddef.h>


struct sockaddr_in;

namespace lonlife {
    
    enum{
        ERR_SUCCESS = 0,
        ERR_TOO_SHORT,
        ERR_INVALID_IP_NUM,
        ERR_CUR_HOP,
        ERR_TOT_HOP,
    };
    
    const int8_t dir_up         = 0;
    const int8_t dir_down       = 1;
    
    struct ip_pair{
        uint32_t src{0};
        uint32_t dest{0};
    }__attribute__((__packed__));
    
    struct msghdr{
        int64_t ts_sec{0};
        int64_t ts_msec{0};
        int8_t  tot_hops{0};
        int8_t  cur_hops{0};
        int8_t  dir{0};
        int8_t  error{0};
        int16_t origin_port{0};
        uint16_t origin_size{0};
        int8_t  resv[8]{0};
        ip_pair ips[0];
    }__attribute__((__packed__));
    

    
    static_assert(sizeof(msghdr) == 32, "assert failed");
    
    bool init(unsigned short port);
    void run();
    
    namespace detail{
        void send_error(sockaddr_in& remote, int8_t error, void* buff, size_t size);
        
        void read_udp_socket(); // 收到数据包
        void send_msg(msghdr* msg, size_t size);
        void send_up_msg(msghdr* msg, size_t size);
        void send_down_msg(msghdr* msg, size_t size);
        void send_up_last_msg(msghdr* msg, size_t size);
        void send_down_last_msg(msghdr* msg, size_t size);
        void send_raw_socket(sockaddr_in& src, sockaddr_in& remote, msghdr* msg, size_t size);

        void on_origin_msg(sockaddr_in& remote, msghdr* msg, size_t size);
        void on_forward_msg(msghdr* msg, size_t size);
        
        bool check_hops(const msghdr* msg, size_t size);
    }
}
