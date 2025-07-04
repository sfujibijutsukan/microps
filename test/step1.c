#include "util.h"
#include "net.h"
#include "driver/dummy.h"
#include "test.h"

#include <signal.h>

static volatile sig_atomic_t terminate;

static void
on_signal(int sig)
{
    (void)sig;
    terminate = 1;
}


int
main(int argc, char *argv[])
{
    struct net_device *dev;

    signal(SIGINT, on_signal);
    if(net_init() < 0){
        errorf("net_init() failed");
        return -1;
    }
    dev = dummy_init();
    if(!dev){
        errorf("dummy_init() failed");
        return -1;
    }
    if(net_run() < 0){
        errorf("net_run() failed");
        return -1;
    }
    while (!terminate){
        if(net_device_output(dev, 0x0800, test_data, sizeof(test_data), NULL) < 0){
            errorf("net_device_output() failed");
            break;
        }
        sleep(1);
    }
    net_shutdown();
    return 0;
}