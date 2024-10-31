#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/null.h"
#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"


int main(int argc, char *argv[]){
    struct net_device *dev;
    /*プロトコル・スタックの初期化k*/
    signal(SIGINT, on_signal);
    if(net_init() == -1){
        errorf("net_init() failure");
        return -1;
    }
    /*ダミーデバイスの初期化*/
    dev = dummy_init();
    if(!dev){
        errorf("dummy_init() failure");
        return -1;
    }
    /*プロトコル・スタックの起動*/
    if(net_run == -1){
        errorf("net_run() failure");
        return -1;
    }
    /*Ctrl+Cが押されるとシグナルハンドラon_signal()の中でterminateに1が設定される*/
    while(!terminate){
        if(net_device_output(dev, 0x0800, test_data, sizeof(test_data), NULL) == -1){
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }
    /*プロトコル・スタックの停止*/
    net_shutdown();
    return 0;
}