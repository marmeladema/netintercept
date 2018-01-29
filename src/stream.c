#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pcap/pcap.h>

#include <arpa/inet.h>

#include "stream.h"

static uint16_t *peer_len(int family, struct stream_peer *peer) {
	if(family == AF_INET) {
		return &peer->ip4.tot_len;
	} else if(family == AF_INET6) {
		return &peer->ip6.payload_len;
	}
	abort();
}

size_t stream_dump(int family, int protocol, struct stream_peer *peer, const uint8_t *data, size_t len, stream_dump_t *dump) {
	uint8_t pkt[1500], *ip_ptr = NULL, *trans_ptr = NULL;
	size_t ip_len = 0, trans_len = 0;

	if(family == AF_INET) {
		ip_ptr = (uint8_t *)&peer->ip4;
		ip_len = sizeof(peer->ip4);
	} else if(family == AF_INET6) {
		ip_ptr = (uint8_t *)&peer->ip6;
		ip_len = sizeof(peer->ip6);
	} else {
		abort();
	}

	if(protocol == IPPROTO_TCP) {
		trans_ptr = (uint8_t *)&peer->tcp;
		trans_len = sizeof(peer->tcp);
	} else if(protocol == IPPROTO_UDP) {
		trans_ptr = (uint8_t *)&peer->udp;
		trans_len = sizeof(peer->udp);
	} else {
		abort();
	}

	if(len) {
		if(ip_len + trans_len + len > sizeof(pkt)) {
			len = sizeof(pkt) - ip_len - trans_len;
		}
		//printf("before: %d\n", ntohs(*peer->len));
		*peer_len(family, peer) = htons(ntohs(*peer_len(family, peer)) + len);
		//printf("after: %d\n", ntohs(*peer->len));
		if(protocol == IPPROTO_UDP) {
			peer->udp.len = htons(ntohs(peer->udp.len) + len);
		}
	}

	memcpy(pkt, ip_ptr, ip_len);
	memcpy(pkt+ip_len, trans_ptr, trans_len);
	memcpy(pkt+ip_len+trans_len, data, len);

	dump(pkt, ip_len + trans_len + len);
	
	if(len) {
		*peer_len(family, peer) = htons(ntohs(*peer_len(family, peer)) - len);
		if(protocol == IPPROTO_UDP) {
			peer->udp.len = htons(ntohs(peer->udp.len) - len);
		}
	}

	return len;
}

void stream_init(struct stream *stream, int fd, const struct sockaddr *remote_addr, socklen_t remote_addrlen) {
	struct sockaddr_storage addr;
	struct sockaddr_in *addr_in;
	struct sockaddr_in6 *addr_in6;
	socklen_t addrlen;
	int optval;
	socklen_t optlen = sizeof(optval);
	struct stat sb;

	//if(stream->protocol == IPPROTO_TCP && stream->connected) {
	//	abort();
	//}

	memset(stream, 0, sizeof(*stream));

	stream->fd = fd;

	if(fstat(stream->fd, &sb) != 0) {
		//perror("fstat");
		return;
	}


	stream->mode = sb.st_mode;

	if(!S_ISSOCK(stream->mode)) {
		return;
	}
/*
	if(pthread_mutex_init(&stream->lock, NULL) != 0) {
		perror("pthread_mutex_init");
		abort();
	}
*/
	if(getsockopt(stream->fd, SOL_SOCKET, SO_PROTOCOL, &optval, &optlen) != 0) {
		perror("getsockopt");
		abort();
	}
	stream->protocol = optval;
	//printf("stream->protocol: %d\n", stream->protocol);

	if(getsockopt(stream->fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) != 0) {
		perror("getsockopt");
		abort();
	}
	stream->type = optval;
	//printf("stream->type: %d\n", stream->type);

	addrlen = sizeof(addr);
	if(getsockname(stream->fd, (struct sockaddr *)&addr, &addrlen) != 0) {
		perror("getsockname");
		return;
	}

	uint16_t local_port, remote_port;

	stream->family = addr.ss_family;
	switch(stream->family) {
	case AF_INET:
		addr_in = (struct sockaddr_in *)&addr;
		
		stream->local.ip4.version = 4;
		stream->local.ip4.ihl = 5;
		stream->local.ip4.ttl = 64;
		stream->local.ip4.saddr = addr_in->sin_addr.s_addr;
		stream->remote.ip4.daddr = addr_in->sin_addr.s_addr;
		stream->local.ip4.protocol = stream->protocol;
		stream->local.ip4.tot_len = htons(sizeof(stream->local.ip4));

		local_port = addr_in->sin_port;

		inet_ntop(addr.ss_family, &addr_in->sin_addr, stream->local_addr, sizeof(stream->local_addr));
		//printf("client ip: %s\n", stream->local_addr);
	break;
	case AF_INET6:
		addr_in6 = (struct sockaddr_in6 *)&addr;

		stream->local.ip6.version = 6;
		stream->local.ip6.hop_limit = 64;
		stream->local.ip6.saddr = addr_in6->sin6_addr;
		stream->remote.ip6.daddr = addr_in6->sin6_addr;
		stream->local.ip6.nexthdr = stream->protocol;
		stream->local.ip6.payload_len = 0;

		local_port = addr_in6->sin6_port;

		inet_ntop(addr.ss_family, &addr_in6->sin6_addr, stream->local_addr, sizeof(stream->local_addr));
		//printf("client ip: %s\n", stream->local_addr);
	break;
	case AF_UNIX:
		return;
	default:
		//fprintf(stderr, "stream_init error: unknown family %d\n", stream->family);
		//abort();
		return;
	}

	addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	if(remote_addr) {
		//printf("stream_init: remote_addr=%p, remote_addrlen=%u\n", remote_addr, remote_addrlen);
		memcpy(&addr, remote_addr, addrlen<remote_addrlen?addrlen:remote_addrlen);
		addrlen = remote_addrlen;
	} else if(getpeername(stream->fd, (struct sockaddr *)&addr, &addrlen) != 0) {
		//perror("getpeername");
		return;
	}

	if(stream->family != addr.ss_family) {
		abort();
	}

	switch(stream->family) {
	case AF_INET:
		addr_in = (struct sockaddr_in *)&addr;

		stream->remote.ip4.version = 4;
		stream->remote.ip4.ihl = 5;
		stream->remote.ip4.ttl = 64;
		stream->local.ip4.daddr = addr_in->sin_addr.s_addr;
		stream->remote.ip4.saddr = addr_in->sin_addr.s_addr;
		stream->remote.ip4.protocol = stream->protocol;
		stream->remote.ip4.tot_len = htons(sizeof(stream->remote.ip4));

		remote_port = addr_in->sin_port;

		inet_ntop(addr.ss_family, &addr_in->sin_addr, stream->remote_addr, sizeof(stream->remote_addr));
		//printf("server ip: %s\n", stream->remote_addr);
	break;
	case AF_INET6:
		addr_in6 = (struct sockaddr_in6 *)&addr;

		stream->remote.ip6.version = 6;
		stream->remote.ip6.hop_limit = 64;
		stream->local.ip6.daddr = addr_in6->sin6_addr;
		stream->remote.ip6.saddr = addr_in6->sin6_addr;
		stream->remote.ip6.nexthdr = stream->protocol;
		stream->remote.ip6.payload_len = 0;

		remote_port = addr_in6->sin6_port;

		inet_ntop(addr.ss_family, &addr_in6->sin6_addr, stream->remote_addr, sizeof(stream->remote_addr));
		//printf("server ip: %s\n", stream->remote_addr);
	break;
	case AF_UNIX:
		return;
	break;
	default:
		//fprintf(stderr, "stream_init error: unknown family %d\n", stream->family);
		//abort();
		return;
	}

	if(stream->protocol == IPPROTO_TCP) {
		stream->local.tcp.source = local_port;
		stream->local.tcp.dest = remote_port;
		stream->local.tcp.doff = 5;
		stream->local.tcp.window = 2;
		//printf("debug1: %d\n", ntohs(*stream->local.len));
		*peer_len(stream->family, &stream->local) = htons(ntohs(*peer_len(stream->family, &stream->local)) + sizeof(stream->local.tcp));
		//printf("debug2: %d\n", ntohs(*stream->local.len));

		stream->remote.tcp.source = remote_port;
		stream->remote.tcp.dest = local_port;
		stream->remote.tcp.doff = 5;
		stream->remote.tcp.window = 2;
		//printf("debug3: %d\n", ntohs(*stream->remote.len));
		*peer_len(stream->family, &stream->remote) = htons(ntohs(*peer_len(stream->family, &stream->remote)) + sizeof(stream->remote.tcp));
		//printf("debug4: %d\n", ntohs(*stream->remote.len));
	} else if(stream->protocol == IPPROTO_UDP) {
		stream->local.udp.source = local_port;
		stream->local.udp.dest = remote_port;
		stream->local.udp.len = htons(8);
		*peer_len(stream->family, &stream->local) = htons(ntohs(*peer_len(stream->family, &stream->local)) + sizeof(stream->local.udp));

		stream->remote.udp.source = remote_port;
		stream->remote.udp.dest = local_port;
		stream->remote.udp.len = htons(8);
		*peer_len(stream->family, &stream->remote) = htons(ntohs(*peer_len(stream->family, &stream->remote)) + sizeof(stream->remote.udp));
	} else {
		fprintf(stderr, "stream_init error: unknown protocol %d\n", stream->protocol);
		//abort();
	}

	stream->seed = time(NULL);
}

void stream_lock(struct stream *stream) {
	if(pthread_mutex_unlock(&stream->lock) != 0) {
		perror("pthread_mutex_unlock");
		abort();
	}
}

void stream_unlock(struct stream *stream) {
	if(pthread_mutex_unlock(&stream->lock) != 0) {
		perror("pthread_mutex_unlock");
		abort();
	}
}

int stream_compare(struct stream *stream1, struct stream *stream2) {
	int cmp;

	cmp = stream1->fd - stream2->fd;

	if(cmp != 0) {
		//printf("fd: %d != %d\n", stream1->fd, stream2->fd);
		return cmp;
	}

	cmp = (stream1->mode&S_IFMT) - (stream2->mode&S_IFMT);

	if(cmp != 0) {
		//printf("mode: %d != %d\n", stream1->mode, stream2->mode);
		return cmp;
	}

	cmp = stream1->family - stream2->family;

	if(cmp != 0) {
		//printf("family: %d != %d\n", stream1->family, stream2->family);
		return cmp;
	}

	cmp = stream1->type - stream2->type;

	if(cmp != 0) {
		//printf("type: %d != %d\n", stream1->type, stream2->type);
		return cmp;
	}

	cmp = stream1->protocol - stream2->protocol;

	if(cmp != 0) {
		//printf("protocol: %d != %d\n", stream1->protocol, stream2->protocol);
		return cmp;
	}

	switch(stream1->family) {
	case AF_INET:
		cmp = memcmp(&stream1->local.ip4.saddr, &stream2->local.ip4.saddr, sizeof(stream1->local.ip4.saddr));
		
		if(cmp != 0) {
			//printf("ip4.saddr: %s != %s\n", stream1->local_addr, stream2->local_addr);
			return cmp;
		}

		cmp = memcmp(&stream1->local.ip4.daddr, &stream2->local.ip4.daddr, sizeof(stream1->local.ip4.daddr));
		
		if(cmp != 0) {
			//printf("ip4.saddr: %s != %s\n", stream1->local_addr, stream2->local_addr);
			return cmp;
		}
	break;
	case AF_INET6:
		cmp = memcmp(&stream1->local.ip6.saddr, &stream2->local.ip6.saddr, sizeof(stream1->local.ip6.saddr));

		if(cmp != 0) {
			//printf("ip6.saddr: %s != %s\n", stream1->local_addr, stream2->local_addr);
			return cmp;
		}

		cmp = memcmp(&stream1->local.ip6.daddr, &stream2->local.ip6.daddr, sizeof(stream1->local.ip6.daddr));

		if(cmp != 0) {
			//printf("ip6.daddr: %s != %s\n", stream1->local_addr, stream2->local_addr);
			return cmp;
		}
	break;
	case AF_UNIX:
		return 0;
	default:
		//fprintf(stderr, "stream_compare error: unknown family %d\n", stream1->family);
		return 0;
	}

	if(stream1->protocol == IPPROTO_TCP) {
		cmp = stream1->local.tcp.source - stream2->local.tcp.source;

		if(cmp != 0) {
			//printf("tcp.source: %d != %d\n", stream1->local.tcp.source, stream2->local.tcp.source);
			return cmp;
		}

		cmp = stream1->local.tcp.dest - stream2->local.tcp.dest;

		if(cmp != 0) {
			//printf("tcp.dest: %d != %d\n", stream1->local.tcp.dest, stream2->local.tcp.dest);
			return cmp;
		}
	} else if(stream1->protocol == IPPROTO_UDP) {
		cmp = stream1->local.udp.source - stream2->local.udp.source;

		if(cmp != 0) {
			//printf("udp.source: %d != %d\n", stream1->local.udp.source, stream2->local.udp.source);
			return cmp;
		}

		cmp = stream1->local.udp.dest - stream2->local.udp.dest;

		if(cmp != 0) {
			//printf("udp.dest: %d != %d\n", stream1->local.udp.dest, stream2->local.udp.dest);
			return cmp;
		}
	} else {
		//fprintf(stderr, "stream_compare error: unknown protocol %d\n", stream1->protocol);
		//abort();
	}

	return 0;
}

void stream_connect(struct stream *stream, stream_dump_t *dump) {
	if(!stream->connected && stream->protocol == IPPROTO_TCP) {

		// SYN
		stream->local.tcp.syn = 1;
		stream->local.tcp.seq = rand_r(&stream->seed);
		stream_dump(stream->family, stream->protocol, &stream->local, NULL, 0, dump);
		stream->local.tcp.seq = htonl(ntohl(stream->local.tcp.seq) + 1);
		stream->local.tcp.syn = 0;

		// SYN+ACK
		stream->remote.tcp.syn = 1;
		stream->remote.tcp.seq = rand_r(&stream->seed);
		stream->remote.tcp.ack = 1;
		stream->remote.tcp.ack_seq = stream->local.tcp.seq;
		stream_dump(stream->family, stream->protocol, &stream->remote, NULL, 0, dump);
		stream->remote.tcp.ack = 0;
		stream->remote.tcp.seq = htonl(ntohl(stream->remote.tcp.seq) + 1);
		stream->remote.tcp.syn = 0;

		// SYN
		stream->local.tcp.ack = 1;
		stream->local.tcp.ack_seq = stream->remote.tcp.seq;
		stream_dump(stream->family, stream->protocol, &stream->local, NULL, 0, dump);
		stream->local.tcp.ack = 0;

	}

	stream->connected = true;
}

void stream_write(struct stream *stream, const uint8_t *data, size_t len, stream_dump_t *dump) {
	size_t dumped = 0;

	stream_connect(stream, dump);

	if(stream->protocol == IPPROTO_TCP) {

		while(len > 0) {
			stream->local.tcp.ack = 1;
			stream->local.tcp.psh = 1;
			dumped = stream_dump(stream->family, stream->protocol, &stream->local, data, len, dump);
			data += dumped;
			len -= dumped;
			stream->local.tcp.seq = htonl(ntohl(stream->local.tcp.seq) + dumped);
			stream->remote.tcp.ack_seq = stream->local.tcp.seq;
			stream->local.tcp.psh = 0;
			stream->local.tcp.ack = 0;

			stream->remote.tcp.ack = 1;
			stream_dump(stream->family, stream->protocol, &stream->remote, NULL, 0, dump);
			stream->remote.tcp.ack = 0;
		}

	} else if(stream->protocol == IPPROTO_UDP) {

		// TODO: handle ip fragmentation
		dumped = stream_dump(stream->family, stream->protocol, &stream->local, data, len, dump);

	} else {

		//fprintf(stderr, "stream_write error: unknown protocol %d\n", stream->protocol);
		//abort();

	}
}

void stream_read(struct stream *stream, const uint8_t *data, size_t len, stream_dump_t *dump) {
	size_t dumped = 0;

	stream_connect(stream, dump);

	if(stream->protocol == IPPROTO_TCP) {

		//printf("[%d] stream_read(%d, %p, %zu)\n", getpid(), stream->fd, data, len);

		while(len) {
			stream->remote.tcp.ack = 1;
			stream->remote.tcp.psh = 1;
			dumped = stream_dump(stream->family, stream->protocol, &stream->remote, data, len, dump);
			data += dumped;
			len -= dumped;
			stream->remote.tcp.seq = htonl(ntohl(stream->remote.tcp.seq) + dumped);
			stream->local.tcp.ack_seq = stream->remote.tcp.seq;
			stream->remote.tcp.psh = 0;
			stream->remote.tcp.ack = 0;

			stream->local.tcp.ack = 1;
			stream_dump(stream->family, stream->protocol, &stream->local, NULL, 0, dump);
			stream->local.tcp.ack = 0;
		}

	} else if(stream->protocol == IPPROTO_UDP) {

		// TODO: handle ip fragmentation
		dumped = stream_dump(stream->family, stream->protocol, &stream->remote, data, len, dump);

	} else {

		//fprintf(stderr, "stream_read error: unknown protocol %d\n", stream->protocol);
		//abort();
	}
}

void stream_close(struct stream *stream, stream_dump_t *dump) {

	if(stream->connected && stream->protocol == IPPROTO_TCP) {

		// FIN
		stream->local.tcp.ack = 1;
		stream->local.tcp.fin = 1;
		stream_dump(stream->family, stream->protocol, &stream->local, NULL, 0, dump);
		stream->local.tcp.seq = htonl(ntohl(stream->local.tcp.seq) + 1);
		stream->remote.tcp.ack_seq = stream->local.tcp.seq;
		stream->local.tcp.fin = 0;
		stream->local.tcp.ack = 0;

		// ACK+FIN
		stream->remote.tcp.ack = 1;
		stream->remote.tcp.fin = 1;
		stream_dump(stream->family, stream->protocol, &stream->remote, NULL, 0, dump);
		stream->remote.tcp.seq = htonl(ntohl(stream->remote.tcp.seq) + 1);
		stream->local.tcp.ack_seq = stream->remote.tcp.seq;
		stream->remote.tcp.fin = 0;
		stream->remote.tcp.ack = 0;

		// ACK
		stream->local.tcp.ack = 1;
		stream_dump(stream->family, stream->protocol, &stream->local, NULL, 0, dump);
		stream->local.tcp.ack = 0;

	}
}