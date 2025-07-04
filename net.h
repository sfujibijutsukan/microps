#ifndef IFNAMESIZ
#define IFNAMESIZ 16

#include <stdint.h>
#include <stddef.h>

#define NET_DEVICE_TYPE_DUMMY    0x0000
#define NET_DEVICE_TYPE_LOOPBACK 0x0001
#define NET_DEVICE_TYPE_ETHERNET 0x0002

#define NET_DEVICE_FLAG_UP        0x0001 // デバイスがアップしている
#define NET_DEVICE_FLAG_LOOPBACK  0x0010 // ループバックデバイス
#define NET_DEVICE_FLAG_BROADCAST 0x0020 // ブロードキャストアドレスを持つ
#define NET_DEVICE_FLAG_P2P       0x0040 // P2Pデバイス
#define NET_DEVICE_FLAG_NEED_ARP  0x0100 // ARPが必要なデバイス

#define NET_DEVICE_ADDR_LEN 16 // MACアドレスの長さ

// デバイスがUPかどうかを判定するマクロ
#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
// デバイスがアップしているかどうかを文字列で返すマクロ
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "UP" : "DOWN")

// デバイス構造体
struct net_device{
    struct net_device *next; // 次のデバイスへのポインタ
    unsigned int index;
    char name[IFNAMESIZ];
    uint16_t type; // デバイスのタイプ
    uint16_t mtu;
    uint16_t flags; // デバイスのフラグ
    uint16_t hlen; // ヘッダの長さ
    uint16_t alen; // アドレスの長さ
    uint8_t addr[NET_DEVICE_ADDR_LEN]; // デバイスのアドレス
    union {
        uint8_t peer[NET_DEVICE_ADDR_LEN];
        uint8_t broadcast[NET_DEVICE_ADDR_LEN];
    };
    struct net_device_ops *ops; // デバイス操作関数へのポインタ
    void *priv; // デバドラが使うプライベートなデータへのポインタ  
};

struct net_device_ops{
    int (*open)(struct net_device *dev);
    int (*close)(struct net_device *dev);
    int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
};

// デバイスを割り当てる関数
struct net_device 
*net_device_alloc(void);
// デバイスを登録する関数
int 
net_device_register(struct net_device *dev);

// デバイス出力関数
int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

// デバイスからの入力を処理する関数
// この関数は、デバドラから呼び出される。プロトコルスタックへのデータの入口。
int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);


int
net_run(void);

// ネットワークシャットダウン関数
void 
net_shutdown(void);

// ネットワーク初期化関数
int
net_init(void);


#endif