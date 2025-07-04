#include "util.h"
#include "net.h"

#define DUMMY_MTU 1500 // Dummy device MTU

struct net_device *
dummy_init(void);