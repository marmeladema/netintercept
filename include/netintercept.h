#ifndef _NETINTERCEPT_H_
#define _NETINTERCEPT_H_

#include "config.h"

typedef int socket_t(int domain, int type, int protocol);
typedef int connect_t(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int shutdown_t(int sockfd, int how);
typedef int close_t(int fd);
typedef ssize_t write_t(int fd, const void *buf, size_t count);
typedef ssize_t read_t(int fd, void *buf, size_t count);

typedef ssize_t recv_t(int sockfd, void *buf, size_t len, int flags);
typedef ssize_t recvfrom_t(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
typedef ssize_t recvmsg_t(int sockfd, struct msghdr *msg, int flags);

typedef ssize_t send_t(int sockfd, const void *buf, size_t len, int flags);
typedef ssize_t sendto_t(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
typedef ssize_t sendmsg_t(int sockfd, const struct msghdr *msg, int flags);
typedef int sendmmsg_t(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);

#if OPENSSL_FOUND

#include <openssl/bio.h>
#include <openssl/ssl.h>

typedef int SSL_read_t(SSL *ssl, void *buf, int num);
typedef int SSL_write_t(SSL *ssl, const void *buf, int num);
typedef int SSL_get_fd_t(const SSL *ssl);

typedef int BIO_read_t(BIO *b, void *buf, int len);
typedef int BIO_write_t(BIO *b, const void *buf, int len);
#endif // OPENSSL_FOUND

#if NSPR_FOUND

#include <nspr/prio.h>
#include <nspr/private/pprio.h>

typedef PROsfd PR_FileDesc2NativeHandle_t(PRFileDesc *);
typedef const PRIOMethods* PR_GetTCPMethods_t(void);
typedef const PRIOMethods* PR_GetUDPMethods_t(void);
typedef PRInt32 PR_Read_t(PRFileDesc *fd, void *buf, PRInt32 amount);
typedef PRInt32 PR_Write_t(PRFileDesc *fd,const void *buf,PRInt32 amount);
typedef PRInt32 PR_Writev_t(PRFileDesc *fd, const PRIOVec *iov, PRInt32 iov_size, PRIntervalTime timeout);
#endif // NSPR_FOUND

/* <NSS> */
/*
typedef struct {
	PRFileDesc *fd;
} sslSocket;
typedef int ssl_DefSend_t(sslSocket *ss, const unsigned char *buf, int len, int flags);
typedef int ssl_SecureSend_t(sslSocket *ss, const unsigned char *buf, int len, int flags);
typedef int ssl_DefRecv_t(sslSocket *ss, unsigned char *buf, int len, int flags);
typedef int ssl_SecureRecv_t(sslSocket *ss, unsigned char *buf, int len, int flags);
*/
/* </NSS>*/

#include "stream.h"

struct stream_node {
	struct stream stream;
	struct stream_node *prev;
	struct stream_node *next;
};

struct netintercept_context {
	pcap_t *pcap;
	char path[PATH_MAX];
	pcap_dumper_t *pcap_dumper;
	struct bpf_program filter;

	socket_t *socket;
	connect_t *connect;
	shutdown_t *shutdown;
	close_t *close;
	read_t *read;
	write_t *write;

	recv_t *recv;
	recvfrom_t *recvfrom;
	recvmsg_t *recvmsg;

	send_t *send;
	sendto_t *sendto;
	sendmsg_t *sendmsg;
	sendmmsg_t *__sendmmsg;

#if OPENSSL_FOUND
	SSL_read_t *ssl_read;
	SSL_write_t *ssl_write;
	SSL_get_fd_t *ssl_get_rfd;
	SSL_get_fd_t *ssl_get_wfd;

	BIO_read_t *bio_read;
	BIO_write_t *bio_write;
#endif // OPENSSL_FOUND

#if NSPR_FOUND
	PR_FileDesc2NativeHandle_t *pr_filedesc2nativehandle;
	PR_GetTCPMethods_t *pr_gettcpmethods;
	PRSendFN tcp_pt_send;
	PRRecvFN tcp_pt_recv;
	PR_Read_t *pr_read;
	PR_Write_t *pr_write;
#endif // NSPR_FOUND

/*
	ssl_DefSend_t *ssl_defsend;
	ssl_SecureSend_t *ssl_securesend;
	ssl_DefRecv_t *ssl_defrecv;
	ssl_SecureRecv_t *ssl_securerecv;
*/
	pthread_mutex_t lock;
	struct stream_node *head;
};

#endif // _NETINTERCEPT_H_
