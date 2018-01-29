#ifndef _NETINTERCEPT_STREAM_H_
#define _NETINTERCEPT_STREAM_H_

#include <stdint.h>
#include <stdbool.h>

/* linux includes */
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

enum stream_direction {
	STREAM_DIRECTION_UNKNOWN = 0,
	STREAM_DIRECTION_UPLOAD, // client->server
	STREAM_DIRECTION_DOWNLOAD, // server->client
};

struct stream_peer {

	union {
		struct iphdr ip4;
		struct ipv6hdr ip6;
	};
	union {
		struct tcphdr tcp;
		struct udphdr udp;
	};
};

typedef void stream_dump_t(uint8_t *data, size_t len);

struct stream {
	int fd;
	mode_t mode;
	int family;
	int type;
	int protocol;
	unsigned int seed;
	bool connected;

	struct stream_peer local;
	char local_addr[INET6_ADDRSTRLEN];
	struct stream_peer remote;
	char remote_addr[INET6_ADDRSTRLEN];

	pthread_mutex_t lock;
};

void stream_init(struct stream *stream, int fd, const struct sockaddr *remote_addr, socklen_t remote_addrlen);
int stream_compare(struct stream *stream1, struct stream *stream2);
void stream_lock(struct stream *stream);
void stream_unlock(struct stream *stream);

void stream_connect(struct stream *stream, stream_dump_t *dump);
void stream_write(struct stream *stream, const uint8_t *data, size_t len, stream_dump_t *dump);
void stream_read(struct stream *stream, const uint8_t *data, size_t len, stream_dump_t *dump);
void stream_close(struct stream *stream, stream_dump_t *dump);

#endif // _NETINTERCEPT_STREAM_H_
