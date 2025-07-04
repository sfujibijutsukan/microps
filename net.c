#include "net.h"
#include "util.h"
#include "platform.h"

static struct net_device *devices;

struct net_device 
*net_device_alloc(void){
    struct net_device *dev;

    dev = memory_alloc(sizeof(*dev));
    if(!dev) {
        errorf("memory_alloc() failed");
        return NULL;
    }
    return dev;
}

int
net_device_register(struct net_device *dev){
    static unsigned int index = 0;

    dev->index = index++; // デバイスのインデックス番号を設定
    snprintf(dev->name, IFNAMESIZ, "net%d", dev->index); // デバイス名を生成(例: net0, net1, ...)
    dev->next = devices; // 既存のデバイスリストの先頭に追加
    devices = dev; // デバイスをリストに追加
    infof("Registered device: %s (index: %u)", dev->name, dev->index);
    return 0;
}

static int
net_device_open(struct net_device *dev) {
    if(NET_DEVICE_IS_UP(dev)){
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    if(dev->ops->open){
        if(dev->ops->open(dev) < 0) {
            errorf("failed to open device %s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP; // UPフラグをセット
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int
net_device_close(struct net_device *dev){
    if(!NET_DEVICE_IS_UP(dev)){
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if(dev->ops->close){
        if(dev->ops->close(dev) < 0) {
            errorf("failed to close device %s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP; // UPフラグをクリア
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    // UPかチェック
    if(!NET_DEVICE_IS_UP(dev)){
        errorf("device %s is not up", dev->name);
        return -1;
    }
    // データの長さがMTUを超えていないかチェック
    if (len > dev->mtu){
        errorf("data length %zu exceeds MTU %u for device %s", len, dev->mtu, dev->name);
        return -1;
    }
    debugf("Transmitting %zu bytes on device %s, type=0x%04x", len, dev->name, type);
    debugdump(data, len);
    // デバドラの出力関数を呼び出す
    if(dev->ops->transmit(dev, type, data, len, dst) < 0){
        errorf("failed to transmit data on device %s", dev->name);
        return -1;
    }
    return 0;
}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    return 0;
}

int
net_run(void)
{
    struct net_device *dev;

    debugf("open all devices...");
    // 登録済みのすべてのデバイスをopen
    for (dev = devices; dev; dev = dev->next){
        net_device_open(dev);
    }
    debugf("running...");
    return 0;
}

void
net_shutdown(void)
{
    struct net_device *dev;
    
    debugf("close all devices...");
    // 登録済みのすべてのデバイスをclose
    for(dev = devices; dev; dev = dev->next){
        net_device_close(dev);
    }
    debugf("shutting down...");
}

int
net_init(void)
{
    infof("Initialized");
    return 0;
}