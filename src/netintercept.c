/* standard includes */
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <memory.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#include <arpa/inet.h>

#include <link.h>

/* libpcap includes */
#include <pcap/pcap.h>

#include "netintercept.h"
#include "stream.h"

static struct netintercept_context ctx;
//static char type_string[128] = {0};
static __thread size_t lock_counter = 0;
/*
static char domain_string[128] = {0};

#define domain_case(domain)\
	case domain:\
		name = #domain;\
		break

static const char *domain_to_string(int domain) {
	const char *name = NULL;
	switch(domain) {
	domain_case(AF_UNIX);
	domain_case(AF_INET);
	domain_case(AF_INET6);
	domain_case(AF_IPX);
	domain_case(AF_NETLINK);
	domain_case(AF_X25);
	domain_case(AF_AX25);
	domain_case(AF_ATMPVC);
	domain_case(AF_APPLETALK);
	domain_case(AF_ALG);

	default:
		name = "UNKNOWN";
		break;
	}
	snprintf(domain_string, sizeof(domain_string), "%s(%d)", name, domain);
	return domain_string;
}
*/

/*
static const char *type_to_string(int domain) {
	const char *name = NULL;
	//if(SOCK_STREAM & )
	snprintf(type_string, sizeof(type_string), "%s(%d)", name, domain);
	return type_string;
}
*/

struct dl_iterate_phdr_data {
	const char *func_name;
	void *func_cur;
	void *func_ptr;
};

static int
dl_iterate_phdr_callback(struct dl_phdr_info *info, size_t __attribute__((unused)) size, void *__data)
{
	struct dl_iterate_phdr_data *data = (struct dl_iterate_phdr_data *)__data;
	void *dlh = dlopen(info->dlpi_name, RTLD_LAZY);
	void *func_ptr = dlsym(dlh, data->func_name);
	if(func_ptr && func_ptr != data->func_cur) {
		data->func_ptr = func_ptr;
		return 1;
	}
	return 0;
}

#define NETINTERCEPT_STACK_PUSH() lock_counter++
#define NETINTERCEPT_STACK_POP() lock_counter--
#define NETINTERCEPT_STACK_SIZE() lock_counter

#define NETINTERCEPT_SETUP_HOOK(hook_name, func_name)\
	netintercept_lock();\
	if(!ctx.hook_name) {\
		ctx.hook_name = dlsym(RTLD_NEXT, func_name);\
		if(!ctx.hook_name) {\
			struct dl_iterate_phdr_data data = {\
				func_name,\
				dlsym(RTLD_DEFAULT, func_name),\
				NULL\
			};\
			dl_iterate_phdr(dl_iterate_phdr_callback, &data);\
			if(!data.func_ptr) {\
				fprintf(stderr, "[%d] Could not hook %s\n", getpid(), func_name);\
				abort();\
			}\
			ctx.hook_name = data.func_ptr;\
		}\
	}\
	netintercept_unlock();

void netintercept_lock() {
	if(lock_counter == 1) {
		if(pthread_mutex_lock(&ctx.lock) != 0) {
			perror("pthread_mutex_lock");
			abort();
		}
	}
}

void netintercept_unlock() {
	if(lock_counter == 1) {
		if(pthread_mutex_unlock(&ctx.lock) != 0) {
			perror("pthread_mutex_unlock");
			abort();
		}
	}
}

void netintercept_dump(uint8_t *data, size_t len) {
	netintercept_lock();
	if(!ctx.pcap_dumper) {
		ctx.pcap_dumper = pcap_dump_open(ctx.pcap, ctx.path);
		if(!ctx.pcap_dumper) {
			fprintf(stderr, "pcap_dump_open error: could not open \"%s\"%s\n", ctx.path, pcap_geterr(ctx.pcap));
			abort();
		}
	}

	struct pcap_pkthdr pkthdr;
	memset(&pkthdr, 0, sizeof(pkthdr));

	gettimeofday(&pkthdr.ts, NULL);
	pkthdr.len = len;
	pkthdr.caplen = pkthdr.len;

	bool match = true;
	if(ctx.filter.bf_len) {
		match = pcap_offline_filter(&ctx.filter, &pkthdr, data);
	}

	if(match) {
		pcap_dump((uint8_t *)ctx.pcap_dumper, &pkthdr, data);
		pcap_dump_flush(ctx.pcap_dumper);
	}
	netintercept_unlock();
}

struct stream *netintercept_add_stream(struct stream *stream) {
	netintercept_lock();

	struct stream_node *node = ctx.head;
	while(node) {
		if(node->stream.fd == -1) {
			break;
		}
		node = node->next;
	}

	if(!node) {
		node = calloc(1, sizeof(*node));
		if(!node) {
			perror("calloc");
			abort();
		}
		node->prev = NULL;
		if(ctx.head) {
			ctx.head->prev = node;
		}
		node->next = ctx.head;
		ctx.head = node;
	}

	if(pthread_mutex_init(&stream->lock, NULL) != 0) {
		perror("pthread_mutex_init");
		abort();
	}

	node->stream = *stream;

	netintercept_unlock();

	return &node->stream;
}

struct stream *netintercept_get_stream(int fd, const struct sockaddr *remote_addr, socklen_t remote_addrlen) {

	netintercept_lock();

	struct stream *stream = NULL;
	struct stream_node *node = ctx.head;
	while(node) {
		if(node->stream.fd == fd) {
			stream = &node->stream;
		}
		node = node->next;
	}

	netintercept_unlock();

	struct stream new_stream;
	stream_init(&new_stream, fd, remote_addr, remote_addrlen);

	if(stream) {
		stream_lock(stream);
		new_stream.lock = stream->lock;
		if(stream_compare(stream, &new_stream) != 0 && S_ISSOCK(stream->mode)) {
			stream_close(stream, netintercept_dump);
			*stream = new_stream;
		}
		stream_unlock(stream);
		//printf("[%d] replacing old stream\n", getpid());
	} else {
		stream = netintercept_add_stream(&new_stream);
		//printf("[%d] creating new stream\n", getpid());
	}

	return stream;
}

void __attribute__((constructor)) netintercept_init(void) {
	if(pthread_mutex_init(&ctx.lock, NULL) != 0) {
		perror("pthread_mutex_init");
		abort();
	}

	pid_t pid = getpid();

	ctx.pcap = pcap_open_dead(DLT_RAW, 65535);
	if(!ctx.pcap) {
		perror("pcap_open_dead");
		abort();
	}

	const char *filter = getenv("NETINTERCEPT_FILTER");
	if(filter) {
		NETINTERCEPT_STACK_PUSH();
		if(pcap_compile(ctx.pcap, &ctx.filter, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
			pcap_perror(ctx.pcap, "pcap_compile");
			abort();
		}
		NETINTERCEPT_STACK_POP();
	}

	const char *file = getenv("NETINTERCEPT_FILE");
	if(file) {
		time_t start = time(NULL);
		struct utsname utsname;
		memset(&utsname, 0, sizeof(utsname));
		if(uname(&utsname) != 0) {
			perror("uname");
			abort();
		}
		char self[PATH_MAX] = {0};
		ssize_t self_len = readlink("/proc/self/exe", self, sizeof(self));
		if(self_len < 0) {
			perror("readlink");
			abort();
		}
		self[self_len] = '\0';
		char *exe = strrchr(self, '/'), *slash = self;
		if(exe) {
			exe ++;
		} else {
			exe = self;
		}
		while((slash = strchr(slash, '/'))) {
			*slash = '!';
			slash++;
		}
		uid_t uid = getuid();

		size_t i, k, len = strlen(file);
		for(i = 0, k = 0; i < len && k+1 < sizeof(ctx.path); i++) {
			if(file[i] == '%' && i+1 < len) {
				i++;
				switch(file[i]) {
				case '%':
					ctx.path[k++] = file[i];
				break;
				case 'p':
					k += snprintf(ctx.path+k, sizeof(ctx.path)-k, "%d", pid);
				break;
				case 't':
					k += snprintf(ctx.path+k, sizeof(ctx.path)-k, "%ld", start);
				break;
				case 'h':
					k += snprintf(ctx.path+k, sizeof(ctx.path)-k, "%s", utsname.nodename);
				break;
				case 'e':
					k += snprintf(ctx.path+k, sizeof(ctx.path)-k, "%s", exe);
				break;
				case 'E':
					k += snprintf(ctx.path+k, sizeof(ctx.path)-k, "%s", self);
				break;
				case 'u':
					k += snprintf(ctx.path+k, sizeof(ctx.path)-k, "%d", uid);
				break;
				default:
				break;
				}
			} else {
				ctx.path[k++] = file[i];
			}
		}
	} else {
		snprintf(ctx.path, sizeof(ctx.path), "netintercept.pcap");
	}
}

void __attribute__((destructor)) netintercept_fini(void) {
	if(ctx.pcap_dumper) {
		pcap_dump_close(ctx.pcap_dumper);
	}
	pcap_close(ctx.pcap);
}

/*
int socket(int domain, int type, int protocol) {
	int orig_errno = errno;
	if(pthread_rwlock_wrlock(&ctx.rwlock) != 0) {
		perror("pthread_rwlock_wrlock");
		abort();
	}
	lock_counter++;

	errno = orig_errno;
	int sockfd = ctx.socket(domain, type, protocol);
	orig_errno = errno;

	printf("socket(%s, %d, %d)=%d\n",
	       domain_to_string(domain),
	       type,
	       protocol,
	       sockfd
	);

	lock_counter--;
	if(pthread_rwlock_unlock(&ctx.rwlock) != 0) {
		perror("pthread_rwlock_unlock");
		abort();
	}
	errno = orig_errno;
	return sockfd;
}
*/

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();

	NETINTERCEPT_SETUP_HOOK(connect, "connect");
	
	struct stream *stream = netintercept_get_stream(sockfd, NULL, 0);
	if(!stream) {
		fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
		abort();
	}

	stream_lock(stream);

	errno = orig_errno;
	int ret = ctx.connect(sockfd, addr, addrlen);
	orig_errno = errno;
	//printf("connect(%d, %p, %u)=%d\n", sockfd, addr, addrlen, ret);

	if(ret == 0) {
		//printf("connecting socket %d\n", stream->fd);
		if(addr && addrlen) {
			stream_init(stream, sockfd, addr, addrlen);
		}
		stream_connect(stream, netintercept_dump);
	}

	stream_unlock(stream);

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

int shutdown(int sockfd, int how) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();

	NETINTERCEPT_SETUP_HOOK(shutdown, "shutdown");

	struct stream *stream = netintercept_get_stream(sockfd, NULL, 0);
	if(!stream) {
		fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
		abort();
	}

	stream_lock(stream);

	errno = orig_errno;
	int ret = ctx.shutdown(sockfd, how);
	orig_errno = errno;

	//printf("shutdown(%d, %d)=%d\n", sockfd, how, ret);

	stream_unlock(stream);

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

int close(int fd) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(close, "close");

	struct stream *stream = netintercept_get_stream(fd, NULL, 0);
	if(!stream) {
		fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, fd);
		abort();
	}

	stream_lock(stream);

	errno = orig_errno;
	int ret = ctx.close(fd);
	orig_errno = errno;
	//printf("close(%d)=%d\n", fd, ret);

	if(ret == 0 && S_ISSOCK(stream->mode)) {
		//printf("[%d] closing socket %d\n", getpid(), stream->fd);
		stream_close(stream, netintercept_dump);
		stream->fd = -1;
	}

	stream_unlock(stream);

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(read, "read");

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(fd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, fd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.read(fd, buf, count);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(S_ISSOCK(stream->mode) && ret > 0) {
			stream_read(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(write, "write");

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(fd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, fd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.write(fd, buf, count);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(S_ISSOCK(stream->mode) && ret > 0) {
			stream_write(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(recv, __func__);

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.recv(sockfd, buf, len, flags);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			stream_read(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(recvfrom, __func__);

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			if(src_addr && addrlen) {
				stream_init(stream, sockfd, src_addr, *addrlen);
			}
			stream_read(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(recvmsg, __func__);

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.recvmsg(sockfd, msg, flags);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			if(msg->msg_name && msg->msg_namelen) {
				stream_init(stream, sockfd, msg->msg_name, msg->msg_namelen);
			}
			uint8_t *data = malloc(ret);
			size_t i, bytes = (size_t)ret, offset = 0, length;
			for(i = 0; i < msg->msg_iovlen && offset < bytes; i++) {
				if(offset + msg->msg_iov[i].iov_len <= bytes) {
					length = msg->msg_iov[i].iov_len;
				} else {
					length = bytes - offset;
				}
				memcpy(data+offset, msg->msg_iov[i].iov_base, length);
				offset += msg->msg_iov[i].iov_len;
			}
			stream_read(stream, data, bytes, netintercept_dump);
			free(data);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(send, __func__);

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.send(sockfd, buf, len, flags);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			stream_write(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(sendto, __func__);

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			if(dest_addr && addrlen) {
				stream_init(stream, sockfd, dest_addr, addrlen);
			}
			stream_write(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(sendmsg, __func__);

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	ssize_t ret = ctx.sendmsg(sockfd, msg, flags);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			if(stream->type == SOCK_DGRAM && msg->msg_name && msg->msg_namelen) {
				stream_init(stream, sockfd, msg->msg_name, msg->msg_namelen);
			}
			uint8_t *data = malloc(ret);
			size_t i, bytes = (size_t)ret, offset = 0, length;
			for(i = 0; i < msg->msg_iovlen && offset < bytes; i++) {
				if(offset + msg->msg_iov[i].iov_len <= bytes) {
					length = msg->msg_iov[i].iov_len;
				} else {
					length = bytes - offset;
				}
				memcpy(data+offset, msg->msg_iov[i].iov_base, length);
				offset += msg->msg_iov[i].iov_len;
			}
			stream_write(stream, data, bytes, netintercept_dump);
			free(data);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

int __sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(__sendmmsg, __func__);

	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	int ret = ctx.__sendmmsg(sockfd, msgvec, vlen, flags);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0 && (unsigned int)ret <= vlen) {
			int i;
			for(i = 0; i < ret; i++) {
				if(msgvec[i].msg_hdr.msg_iovlen != 1) {
					abort();
				}

				//printf("sendmmsg[%d]: msg_len=%d, msg_hdr.msg_iov[0].iov_len=%zu\n", i, msgvec[i].msg_len, msgvec[i].msg_hdr.msg_iov[0].iov_len);
				stream_write(stream, msgvec[i].msg_hdr.msg_iov[0].iov_base, msgvec[i].msg_len, netintercept_dump);
			}
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

#if OPENSSL_FOUND

int SSL_read(SSL *ssl, void *buf, int num) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(ssl_get_rfd, "SSL_get_rfd");
	NETINTERCEPT_SETUP_HOOK(ssl_read, __func__);

	int sockfd = ctx.ssl_get_rfd(ssl);
	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	//printf("SSL_read: %p, ssl: %p, buf: %p, num: %d\n", orig_SSL_read, ssl, buf, num);
	errno = orig_errno;
	int ret = ctx.ssl_read(ssl, buf, num);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			stream_read(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

int SSL_write(SSL *ssl, const void *buf, int num) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(ssl_get_wfd, "SSL_get_wfd");
	NETINTERCEPT_SETUP_HOOK(ssl_write, __func__);

	int sockfd = ctx.ssl_get_wfd(ssl);
	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	//printf("SSL_write: %p, ssl: %p, buf: %p, num: %d\n", ctx.ssl_write, ssl, buf, num);
	errno = orig_errno;
	int ret = ctx.ssl_write(ssl, buf, num);
	orig_errno = errno;

	if(lock_counter == 1) {
		if(ret > 0) {
			stream_write(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

int BIO_read(BIO *b, void *buf, int len) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(bio_read, __func__);

	errno = orig_errno;
	int ret = ctx.bio_read(b, buf, len);
	orig_errno = errno;

	if(lock_counter == 1 && ret > 0) {
		/*
		int fd = ctx.ssl_get_wfd(ssl);
		struct stream *stream = netintercept_get_stream(fd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "could not find fd:%d\n", fd);
			abort();
		}

		stream_read(stream, buf, ret, netintercept_dump);
		*/
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

int BIO_write(BIO *b, const void *buf, int len) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(bio_write, __func__);

	errno = orig_errno;
	int ret = ctx.bio_write(b, buf, len);
	orig_errno = errno;

	if(lock_counter == 1 && ret > 0) {
		/*
		int fd = ctx.ssl_get_wfd(ssl);
		struct stream *stream = netintercept_get_stream(fd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "could not find fd:%d\n", fd);
			abort();
		}

		stream_write(stream, buf, ret, netintercept_dump);
		*/
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

#endif // OPENSSL_FOUND

#if NSPR_FOUND

PRInt32 tcp_pt_Recv(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();

	errno = orig_errno;
	PRInt32 ret = ctx.tcp_pt_recv(fd, buf, amount, flags, timeout);
	orig_errno = errno;

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

PRInt32 tcp_pt_Send(PRFileDesc *fd, const void *buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();

	errno = orig_errno;
	PRInt32 ret = ctx.tcp_pt_send(fd, buf, amount, flags, timeout);
	orig_errno = errno;

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

const PRIOMethods* PR_GetTCPMethods(void) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	PR_GetTCPMethods_t *pr_gettcpmethods = ctx.pr_gettcpmethods;
	NETINTERCEPT_SETUP_HOOK(pr_gettcpmethods, __func__);

	errno = orig_errno;
	const PRIOMethods* ret = ctx.pr_gettcpmethods();
	orig_errno = errno;

	if(!pr_gettcpmethods) {

		ctx.tcp_pt_recv = ((PRIOMethods*)ret)->recv;
		((PRIOMethods*)ret)->recv = &tcp_pt_Recv;

		ctx.tcp_pt_send = ((PRIOMethods*)ret)->send;
		((PRIOMethods*)ret)->send = &tcp_pt_Send;
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

PRInt32 PR_Read(PRFileDesc *fd, void *buf, PRInt32 amount) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();
	
	NETINTERCEPT_SETUP_HOOK(pr_filedesc2nativehandle, "PR_FileDesc2NativeHandle");
	NETINTERCEPT_SETUP_HOOK(pr_read, __func__);

	int sockfd = ctx.pr_filedesc2nativehandle(fd);
	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	PRInt32 ret = ctx.pr_read(fd, buf, amount);
	orig_errno = errno;


	if(lock_counter == 1) {
		if(S_ISSOCK(stream->mode) && ret > 0) {
			stream_read(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

PRInt32 PR_Write(PRFileDesc *fd,const void *buf,PRInt32 amount) {
	int orig_errno = errno;
	NETINTERCEPT_STACK_PUSH();

	NETINTERCEPT_SETUP_HOOK(pr_filedesc2nativehandle, "PR_FileDesc2NativeHandle");
	NETINTERCEPT_SETUP_HOOK(pr_write, __func__);

	int sockfd = ctx.pr_filedesc2nativehandle(fd);
	struct stream *stream = NULL;
	if(lock_counter == 1) {
		stream = netintercept_get_stream(sockfd, NULL, 0);
		if(!stream) {
			fprintf(stderr, "%s error: could not get stream for file descriptor %d\n", __func__, sockfd);
			abort();
		}
		stream_lock(stream);
	}

	errno = orig_errno;
	PRInt32 ret = ctx.pr_write(fd, buf, amount);
	orig_errno = errno;


	if(lock_counter == 1) {
		if(S_ISSOCK(stream->mode) && ret > 0) {
			stream_write(stream, buf, ret, netintercept_dump);
		}
		stream_unlock(stream);
	}

	NETINTERCEPT_STACK_POP();
	errno = orig_errno;
	return ret;
}

//typedef PRInt32 PR_Writev_t(PRFileDesc *fd, const PRIOVec *iov, PRInt32 iov_size, PRIntervalTime timeout);
#endif // NSPR_FOUND
