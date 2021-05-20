#ifndef H_IPC_SHIM
#define H_IPC_SHIM

#include <stdint.h>
#include <pthread.h>
#include <stdarg.h>

#define KVM_HC_SHM_READ 28
#define KVM_HC_SHM_WRITE 29
#define KVM_HC_PIPE_READ 30
#define KVM_HC_PIPE_WRITE 31

#define KVM_HYPERCALL ".byte 0x0f,0x01,0xc1"
static inline long do_kvm_hypercall(unsigned int nr, unsigned long p1,
				  unsigned long p2, unsigned long p3,
				  unsigned long p4) {
	long ret;
	asm volatile(KVM_HYPERCALL
		     : "=a"(ret)
		     : "a"(nr), "b"(p1), "c"(p2), "d"(p3), "S"(p4)
		     : "memory");
	return ret;
}

static inline long read_host_shm(int idx, unsigned long offset, void *dst, unsigned long size) {

	return do_kvm_hypercall(KVM_HC_SHM_READ, idx, offset, (unsigned long) dst, size);

}

static inline long write_host_shm(int idx, unsigned long offset, void *src, unsigned long size) {

	return do_kvm_hypercall(KVM_HC_SHM_WRITE, idx, offset, (unsigned long) src, size);

}

// Read 1 byte for each page in [dst, dst+size]
// Assume [dst, dst+size) is user readable
static inline void read_pages(void *dst, unsigned long size) {
	volatile char t;
	char *st = (char *)(dst);
	char *ed = (char *)(((unsigned long)dst+size-1) & ~0xffful);
	do {
		// Enforce memory read
		t = t = *st;
		st += 0x1000ul;
	} while(st <= ed);
}

// Enforce physical memory allocation. E.g. mmap allocates physical pages on demand.
static inline long read_host_shm_safe(int idx, unsigned long offset, void *dst, unsigned long size) {
	read_pages(dst, size);
	return read_host_shm(idx, offset, dst, size);
}

// Enforce physical memory allocation. E.g. mmap allocates physical pages on demand.
static inline long write_host_shm_safe(int idx, unsigned long offset, void *dst, unsigned long size) {
	read_pages(dst, size);
	return write_host_shm(idx, offset, dst, size);
}

static inline long read_host_pipe(int idx, void *dst, unsigned long size) {

	return do_kvm_hypercall(KVM_HC_PIPE_READ, idx, (unsigned long) dst, size, 0ul);

}

static inline long write_host_pipe(int idx, void *src, unsigned long size) {

	return do_kvm_hypercall(KVM_HC_PIPE_WRITE, idx, (unsigned long) src, size, 0ul);

}

// print to pipe, use va_list
static inline int vpprintf(int idx, const char *msg, va_list args) {
	static pthread_mutex_t buf_lock = PTHREAD_MUTEX_INITIALIZER;
	static char buf[8192] = {0};
	int len;
	pthread_mutex_lock(&buf_lock);
	len = vsnprintf(buf, sizeof(buf), msg, args);
	if (len == -1) {
		return -1;
	}
	write_host_pipe(idx, buf, len);
	pthread_mutex_unlock(&buf_lock);
	return len;
} 

// print to pipe
static inline int pprintf(int idx, const char *msg, ...) {
	va_list args;
	int len;
	va_start(args, msg);
	len = vpprintf(idx, msg, args);
	va_end(args);
	return len;
} 

// print to pipe end with new line, use va_list
static inline int vpprintln(int idx, const char *msg, va_list args) {
	static pthread_mutex_t buf_lock = PTHREAD_MUTEX_INITIALIZER;
	static char buf[8192] = {0};
	int len;
	pthread_mutex_lock(&buf_lock);
	len = vsnprintf(buf, sizeof(buf)-1, msg, args);
	if (len == -1) {
		return -1;
	}
	buf[len++] = '\n';
	buf[len] = 0;
	write_host_pipe(idx, buf, len);
	pthread_mutex_unlock(&buf_lock);
	return len;
} 

// print to pipe end with new line
static inline int pprintln(int idx, const char *msg, ...) {
	va_list args;
	int len;
	va_start(args, msg);
	len = vpprintln(idx, msg, args);
	va_end(args);
	return len;
} 


#endif