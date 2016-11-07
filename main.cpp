#include <stdio.h>
#include <stdlib.h>
#include "net.h"

void usage(){
    printf("Usage: delayd port\n");
}

int main(int argc, const char * argv[]) {
    
    if(argc != 2){
        usage();
        return 1;
    }

    auto port = atoi(argv[1]);
    if(port <= 0 || port >= UINT16_MAX ){
        usage();
        return 2;
    }
    
    bool init = lonlife::init(port);
    if(!init){
        return 1;
    }
    lonlife::run();
    return 0;
}
