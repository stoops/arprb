/*
export PATH="/tmp/usr/bin:$PATH"
export LD_LIBRARY_PATH=/tmp/usr/lib:/usr/lib:/lib:.
export CPATH=/tmp/usr/include:.
export LIBRARY_PATH="$LD_LIBRARY_PATH"
gcc -Wall -o dhcprb dhcprb.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define HW_ADDR_LEN   6
#define IP_ADDR_LEN   4
#define ETH_HW_TYPE   0x01
#define IP_VER_HEADER 0x45
#define ARP_OP_REQ    1
#define ARP_OP_REPLY  2

#define RELAY_LEN 4
#define TABLE_LEN 277

typedef unsigned char  uchar;
typedef unsigned short ushor;

struct arp_pkt {
	/* eth */
	uchar dest_hw[HW_ADDR_LEN], sorc_hw[HW_ADDR_LEN];
	/* arp */
	ushor frame_type; ushor hw_type;
	ushor proto_type; uchar hw_size;
	uchar proto_size; ushor op_code;
	uchar sndr_hw[HW_ADDR_LEN], sndr_ip[IP_ADDR_LEN];
	uchar rcpt_hw[HW_ADDR_LEN], rcpt_ip[IP_ADDR_LEN];
};

struct dhcp_pkt {
	/* eth */
	uchar dest_hw[HW_ADDR_LEN], sorc_hw[HW_ADDR_LEN];
	/* ipf */
	ushor frame_type;
	uchar ver_ihl, dsc_ecn;
	ushor tot_len, ident, flag_offs;
	uchar ttl, prot;
	ushor check_sum;
	uchar sorc_ip[IP_ADDR_LEN], dest_ip[IP_ADDR_LEN];
	/* udp */
	ushor src_port, dst_port, tos_len, chk_sum;
	/* dhcp */
	uchar op_code, hw_type, hw_size, hops;
	uchar x_id[4];
	ushor secs, flag;
	uchar c_ip[4], y_ip[4], s_ip[4], g_ip[4];
	uchar c_hw[6], chaddr[10];
	uchar bootp[192];
	uchar magic[4], opts[321];
};

struct intf {
	int sock_arp, sock_udp;
	char *ifn;
	char smac[32], sadr[32];
	unsigned char mac[8], adr[4];
	struct sockaddr ssa;
};

struct arps {
	int intf;
	char iadr[32];
};

char hexc(char c) {
	if (('0' <= c) && (c <= '9')) { return (c - '0'); }
	if (('A' <= c) && (c <= 'Z')) { return ((c - 'A') + 10); }
	if (('a' <= c) && (c <= 'z')) { return ((c - 'a') + 10); }
	return 0;
}

int hexd(char d, char e) { return ((hexc(d) << 4) | hexc(e)); }

int strnlcmp(char *a, char *b, int n) {
	if ((a == NULL) || (b == NULL)) { return 1; }
	if (strlen(a) != strlen(b)) { return 2; }
	return strncmp(a, b, n);
}

void I(struct arps *p) {
	for (int i = 0; i < TABLE_LEN; ++i) {
		p[i].intf = -1; p[i].iadr[0] = 0;
	}
}

int K(struct arps *p, char *s) {
	int y = 0, i = 1, l = strlen(s);
	for (int x = 0; x < l; ++x) { i = (((s[x] + x) * (x + i)) % TABLE_LEN); }
	while ((p[i].iadr[0] > 0) && (strnlcmp(p[i].iadr, s, 30) != 0)) {
		i = ((i + 1) % TABLE_LEN); ++y;
		if (y >= TABLE_LEN) { return -1; }
	}
	return i;
}

void hwstr(char *str, unsigned char *buf) {
	int l = strlen(str);
	bzero(buf, HW_ADDR_LEN);
	for (int i = 0, j = 0; (i < l) && (j < HW_ADDR_LEN); ++i) {
		if (str[i] == ':') { ++j; continue; }
		buf[j] = ((buf[j] << 4) | hexc(str[i]));
	}
}

void ipstr(char *str, unsigned char *buf) {
	struct in_addr adr;
	adr.s_addr = inet_addr(str);
	bcopy(&adr, buf, IP_ADDR_LEN);
}

unsigned short calc_sum(unsigned short *buf, int num) {
	unsigned long sum;
	for (sum = 0; num > 0; --num) {
		sum += *buf; ++buf;
	}
	sum = ((sum >> 16) + (sum & 0xffff));
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

void send_ping(char *intf, char *iadr, int show) {
	int sock;
	struct sockaddr_in sain;
	if (show != 0) { printf("arp ping  ** [%s][%s]\n", intf, iadr); }
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) >= 0) {
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, intf, strlen(intf)) >= 0) {
			memset(&sain, 0, sizeof(sain));
			sain.sin_family = AF_INET;
			sain.sin_addr.s_addr = inet_addr(iadr);
			sain.sin_port = htons(1);
			sendto(sock, "76543210", 8, 0, (struct sockaddr *)&sain, sizeof(sain));
		}
		close(sock);
	}
}

void send_arps(struct intf *relay, char *who_adr, uchar *dst_mac, char *dst_adr) {
	int sock = relay->sock_arp;
	unsigned char *src_mac = relay->mac;
	struct sockaddr ssa = relay->ssa;

	unsigned int psiz = sizeof(struct arp_pkt);
	struct arp_pkt pkt;

	printf("arp reply !! [%s][%s] -> [%s][%s]\n", relay->smac, who_adr, relay->ifn, dst_adr);

	pkt.frame_type = htons(ETH_P_ARP);
	pkt.hw_type    = htons(ETH_HW_TYPE);
	pkt.proto_type = htons(ETH_P_IP);
	pkt.hw_size    = HW_ADDR_LEN;
	pkt.proto_size = IP_ADDR_LEN;
	pkt.op_code    = htons(ARP_OP_REPLY);

	bcopy(src_mac, pkt.sorc_hw, HW_ADDR_LEN); /* src mac */
	bcopy(dst_mac, pkt.dest_hw, HW_ADDR_LEN); /* dst mac */

	bcopy(src_mac, pkt.sndr_hw, HW_ADDR_LEN); /* who mac */
	ipstr(who_adr, pkt.sndr_ip);              /* who ip  */

	bcopy(dst_mac, pkt.rcpt_hw, HW_ADDR_LEN); /* dst mac */
	ipstr(dst_adr, pkt.rcpt_ip);              /* dst ip  */

	sendto(sock, &pkt, psiz, 0, &ssa, sizeof(ssa));
}

void send_dhcp(struct intf *relay, struct dhcp_pkt *pkt, int rsiz, char *src_adr, char mode) {
	unsigned short *shobuf = (unsigned short *)pkt;
	unsigned int dsiz = sizeof(struct dhcp_pkt), psiz = (rsiz + 42);

	int src_port = 68, dst_port = 67;
	char *dst_adr = "255.255.255.255";
	char dst_ptr[32];
	unsigned char *t, *dst_mac = (uchar *)"\xff\xff\xff\xff\xff\xff";

	int sock = relay->sock_udp;
	char *srv_adr = relay->sadr;
	unsigned char *src_mac = relay->mac;
	struct sockaddr ssa = relay->ssa;

	if (psiz > dsiz) { psiz = dsiz; }

	if (mode == 'r') {
		dst_mac = pkt->c_hw; dst_adr = dst_ptr;
		src_port = 67; dst_port = 68;
		bzero(dst_ptr, 32); t = pkt->y_ip;
		snprintf(dst_ptr, 30, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);
	}

	printf("dhcp forw .. [%c][%s] -> [%s][%s]\n", mode, src_adr, relay->ifn, dst_adr);

	pkt->frame_type = htons(ETH_P_IP);

	bcopy(src_mac, pkt->sorc_hw, HW_ADDR_LEN);
	bcopy(dst_mac, pkt->dest_hw, HW_ADDR_LEN);

	pkt->ver_ihl   = IP_VER_HEADER;
	pkt->dsc_ecn   = 0;
	pkt->tot_len   = htons(psiz-14);
	pkt->ident     = htons(3210);
	pkt->flag_offs = htons(0);
	pkt->ttl       = 8;
	pkt->prot      = IPPROTO_UDP;
	pkt->check_sum = 0;

	ipstr(src_adr, pkt->sorc_ip);
	ipstr(dst_adr, pkt->dest_ip);

	pkt->src_port = htons(src_port);
	pkt->dst_port = htons(dst_port);
	pkt->tos_len  = htons((psiz-14)-20);
	pkt->chk_sum  = htons(0);

	if ((mode == 'f') && (pkt->g_ip[0] == 0)) {
		ipstr(srv_adr, pkt->g_ip);
	}

	pkt->check_sum = calc_sum(&(shobuf[7]), 10);

	sendto(sock, pkt, psiz, 0, &ssa, sizeof(ssa));
}

void route_mod(char *host, char *dest) {
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct sockaddr_in *addr;
	struct rtentry route;

	bzero(&route, sizeof(route));
	route.rt_flags = (RTF_UP | RTF_HOST);
	route.rt_metric = 0;

	addr = (struct sockaddr_in *)&route.rt_dst;
	addr->sin_family = AF_INET;
	inet_pton(AF_INET, host, &(addr->sin_addr));

	addr = (struct sockaddr_in*)&route.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = 0xffffffff;

	for (int i = 0; i < RELAY_LEN; ++i) { ioctl(fd, SIOCDELRT, &route); }

	addr = (struct sockaddr_in *)&route.rt_gateway;
	addr->sin_family = AF_INET;
	route.rt_dev = dest;

	ioctl(fd, SIOCADDRT, &route);
	close(fd);
}

int read_rout(struct arps *routes, struct intf *relayds) {
	int leng = 0;
	char line[256];
	char *p, *srcif, taadr[32];

	I(routes);

	FILE *fobj = fopen("/proc/net/route", "r");
	if (fobj != NULL) {
		bzero(line, 256);

		while (fgets(line, 250, fobj) != NULL) {
			if ((line[0] < 'a') || ('z' < line[0])) { bzero(line, 256); continue; }
			srcif = line; p = line;

			/* field 1 - interface */
			while ((*p != '\t') && (*p != '\0')) { ++p; } *p = '\0'; ++p;

			/* field 2 - ip address in hex in reverse */
			bzero(taadr, 32);
			snprintf(taadr, 30, "%d.%d.%d.%d", hexd(p[6],p[7]), hexd(p[4],p[5]), hexd(p[2],p[3]), hexd(p[0],p[1]));

			int find = -2;
			for (int i = 0; i < RELAY_LEN; ++i) {
				if (strnlcmp(relayds[i].ifn, srcif, 30) == 0) {
					find = i;
				}
			}

			int j = K(routes, taadr);
			//printf("route table -- [%s][%s](%d) <- (%d)\n", srcif, taadr, find, j);
			if (j >= 0) {
				bzero(routes[j].iadr, 32);
				strncpy(routes[j].iadr, taadr, 30);
				routes[j].intf = find; ++leng;
			}

			bzero(line, 256);
		}

		fclose(fobj);
	}

	return leng;
}

int read_arps(struct arps *clients, struct intf *relayds) {
	int rlen, leng = 0;
	char line[256];
	char *p, *q, *taadr, *flags, *srcif;
	struct arps rout[TABLE_LEN];

	I(clients);
	rlen = read_rout(&(rout[0]), relayds);

	for (int i = 0; i < RELAY_LEN; ++i) {
		if (relayds[i].ifn == NULL) { continue; }
		int j = K(clients, relayds[i].sadr);
		if (j >= 0) {
			bzero(clients[j].iadr, 32);
			strncpy(clients[j].iadr, relayds[i].sadr, 30);
			clients[j].intf = i; ++leng;
		}
	}

	FILE *fobj = fopen("/proc/net/arp", "r");
	if (fobj != NULL) {
		bzero(line, 256);

		while (fgets(line, 250, fobj) != NULL) {
			if ((line[0] < '0') || ('9' < line[0])) { bzero(line, 256); continue; }
			taadr = line; flags = NULL; srcif = NULL; q = NULL; p = line;

			/* field 1 - IP address with trailing space replace with null */
			while ((*p != ' ') && (*p != '\0')) { ++p; }
			if (*p == ' ') { *p = '\0'; ++p; }

			/* field 2 & 3 - ARP type & flags in hex so find the x */
			while ((*p != 'x') && (*p != '\0')) { ++p; }
			if (*p == 'x') {
				++p; while ((*p != 'x') && (*p != '\0')) { ++p; }
				if (*p == 'x') { ++p; if (*p > '0') { flags = p; } }
			}

			/* field NF - Interface name with trailing newline replace with null */
			while ((*p != '\n') && (*p != '\0')) { if (*p == ' ') { q = p; } ++p; }
			if ((q != NULL) && (*p == '\n')) { srcif = (q + 1); *p = '\0'; }

			if ((taadr != NULL) && (flags != NULL) && (srcif != NULL)) {
				int find = -2, ridx = -1, rval;
				for (int i = 0; i < RELAY_LEN; ++i) {
					if (strnlcmp(relayds[i].ifn, srcif, 30) == 0) {
						find = i; ridx = K(rout, taadr);
						rval = ((ridx < 0) ? ridx : rout[ridx].intf);
						//printf("arp table -- [%s][%s] (0x%c)\n", srcif, taadr, flags[0]);
						send_ping(srcif, taadr, 0);
						if (rval != find) {
							printf("route add ++ [%s][%s] -> (%d x %d) <- [%d][%d]\n", taadr, srcif, find, rval, rlen, ridx);
							route_mod(taadr, srcif);
						}
					}
				}
				int j = K(clients, taadr);
				if (j >= 0) {
					bzero(clients[j].iadr, 32);
					strncpy(clients[j].iadr, taadr, 30);
					clients[j].intf = find; ++leng;
				}
			}

			bzero(line, 256);
		}

		fclose(fobj);
	}

	return leng;
}

int main(int argc, char **argv) {
	int rlen, loop, leng = 0, rly_max = -1;
	char *p, *clip;
	char who_adr[32], dst_adr[32], bstr[256];
	struct intf relayds[RELAY_LEN];
	struct arps clients[TABLE_LEN];
	time_t secs = 0, last = 0;

	int sock_arp, sock_udp, sock_max = 0;
	unsigned int ssiz;
	unsigned char *t;
	unsigned char buff[1024];
	struct sockaddr_ll sall;
	struct sockaddr_in sain;
	struct arp_pkt apkt;
	struct dhcp_pkt dhcp;
	fd_set so_set, re_set;

	p = getenv("LOOP");
	if (p == NULL) { p = "0"; }
	loop = atoi(p);
	if (loop < 3) { loop = 9; }

	if (argc < 3) {
		printf("Usage: dhcprb br-if0 br-if1 dhcp-if\n"); return 1;
	}

	/* server sockets */

	sock_arp = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock_arp < 0) {
		printf("sock arp\n"); return 2;
	}
	bzero(&sall, sizeof(struct sockaddr_ll));
	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(ETH_P_ARP);
	sall.sll_pkttype = PACKET_BROADCAST;
	sall.sll_hatype = ARPHRD_ETHER;
	sall.sll_halen = ETH_ALEN;
	if (bind(sock_arp, (struct sockaddr *)(&sall), sizeof(struct sockaddr_ll)) < 0) {
		printf("bind arp\n"); return 3;
	}
	if (sock_arp > sock_max) { sock_max = sock_arp; }

	sock_udp = socket(AF_INET, SOCK_DGRAM, htons(PACKET_HOST));
	if (sock_udp < 0) {
		printf("sock dhcp\n"); return 2;
	}
	ssiz = 1; setsockopt(sock_udp, SOL_SOCKET, SO_REUSEADDR, (const void *)&ssiz, sizeof(int));
	ssiz = 1; setsockopt(sock_udp, SOL_SOCKET, SO_BROADCAST, (const void *)&ssiz, sizeof(int));
	bzero(&sain, sizeof(struct sockaddr_in));
	sain.sin_family = AF_INET;
	sain.sin_addr.s_addr = htonl(INADDR_ANY);
	sain.sin_port = htons(67);
	if (bind(sock_udp, (struct sockaddr *)&sain, sizeof(sain)) < 0) {
		printf("bind dhcp\n"); return 3;
	}
	if (sock_udp > sock_max) { sock_max = sock_udp; }

	FD_ZERO(&so_set); FD_SET(sock_arp, &so_set); FD_SET(sock_udp, &so_set);

	/* relay interfaces */

	bzero(relayds, RELAY_LEN * sizeof(struct intf));
	for (int i = 0; (i < RELAY_LEN) && ((i + 1) < argc); ++i) {
		relayds[i].ifn = argv[i + 1]; p = relayds[i].ifn; rly_max = i;

		bzero(bstr, 256);
		snprintf(bstr, 250, "( ip -4 link show dev '%s' ; ip -4 addr show dev '%s' ) | \
            grep -Ei '(link|inet)[/ ]' | awk '{ print $2 }' | sed -e 's@/.*$@@' > /tmp/i.txt", p, p);
		system(bstr);

		FILE *fobj = fopen("/tmp/i.txt", "r");
		if (fobj != NULL) {
			for (int x = 0; x < 2; ++x) {
				bzero(bstr, 128);
				if (fgets(bstr, 96, fobj) != NULL) {
					p = bstr; while (*p != '\0') { if (*p == '\n') { *p = '\0'; } ++p; }
					if (x == 0) { strncpy(relayds[i].smac, bstr, 30); }
					if (x == 1) { strncpy(relayds[i].sadr, bstr, 30); }
				}
			}
			fclose(fobj);
		}
		hwstr(relayds[i].smac, relayds[i].mac);
		ipstr(relayds[i].sadr, relayds[i].adr);

		relayds[i].sock_arp = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
		if (relayds[i].sock_arp < 0) {
			printf("relay arp [%d][%d]\n", i, relayds[i].sock_arp); return 9;
		}
		relayds[i].sock_udp = socket(AF_INET, SOCK_PACKET, htons(ETH_P_IP));
		if (relayds[i].sock_udp < 0) {
			printf("relay udp [%d][%d]\n", i, relayds[i].sock_udp); return 9;
		}
		bzero(&(relayds[i].ssa), sizeof(struct sockaddr));
		strncpy(relayds[i].ssa.sa_data, relayds[i].ifn, sizeof(relayds[i].ssa.sa_data));

		printf("-> [%s][%s][%s]\n", relayds[i].ifn, relayds[i].smac, relayds[i].sadr);
	}

	/* network loop */

	while (1) {
		memcpy(&re_set, &so_set, sizeof(so_set));
		if (select(sock_max+1, &re_set, NULL, NULL, NULL) < 0) {
			printf("select\n"); return -1;
		}

		secs = time(NULL);
		if ((secs - last) >= loop) {
			printf("read file >> [%ld][%d]\n", secs, leng);
			leng = read_arps(&(clients[0]), &(relayds[0]));
			last = time(NULL);
			printf("read file << [%ld][%d]\n", last, leng);
		}

		if (FD_ISSET(sock_arp, &re_set)) {
			bzero(buff, 256);
			rlen = recv(sock_arp, buff, 128, 0);
			bcopy(buff, &apkt, sizeof(struct arp_pkt));

			if ((rlen > 16) && (apkt.op_code == htons(ARP_OP_REQ))) {
				bzero(who_adr, 32); t = apkt.rcpt_ip;
				snprintf(who_adr, 30, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);
				bzero(dst_adr, 32); t = apkt.sndr_ip;
				snprintf(dst_adr, 30, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);

				int no_go = 0;
				int who_idx = K(clients, who_adr), dst_idx = K(clients, dst_adr);
				if ((who_idx < 0) || (clients[who_idx].intf < -1)) { no_go = 1; }
				if ((dst_idx < 0) || (clients[dst_idx].intf < -1)) { no_go = 1; }

				printf("arp reqs  ?? [%d][%s] <- [%s][%d]\n", rlen, who_adr, dst_adr, no_go);

				if (no_go == 0) {
					int who_int = clients[who_idx].intf, dst_int = clients[dst_idx].intf;
					for (int i = 0; i < RELAY_LEN; ++i) {
						if (relayds[i].ifn == NULL) { continue; }
						if (who_int < 0) {
							send_ping(relayds[i].ifn, who_adr, 1); clients[who_idx].intf = -2;
						}
						if (dst_int < 0) {
							send_ping(relayds[i].ifn, dst_adr, 1); clients[dst_idx].intf = -2;
						}
						if ((who_int >= 0) && (i != who_int)) {
							if ((dst_int < 0) || (i == dst_int)) {
								send_arps(&(relayds[i]), who_adr, apkt.sndr_hw, dst_adr);
							}
						}
					}
				}
			}
		}

		if (FD_ISSET(sock_udp, &re_set)) {
			bzero(&sain, sizeof(struct sockaddr_in)); ssiz = sizeof(sain);
			bzero(buff, 1024); t = (unsigned char *)(&dhcp);
			rlen = recvfrom(sock_udp, buff, 900, 0, (struct sockaddr *)&sain, &ssiz);
			bcopy(buff, &(t[42]), sizeof(struct dhcp_pkt)-42);

			if ((rlen > 42) && (rly_max >= 0)) {
				clip = inet_ntoa(sain.sin_addr);

				printf("dhcp recv .. [%d][%s]\n", rlen, clip);

				if (strcmp(clip, "0.0.0.0") == 0) {
					send_dhcp(&(relayds[rly_max]), &dhcp, rlen, clip, 'f');
				} else {
					for (int i = 0; i < RELAY_LEN; ++i) {
						if ((relayds[i].ifn == NULL) || (i == rly_max)) { continue; }
						send_dhcp(&(relayds[i]), &dhcp, rlen, clip, 'r');
					}
				}
			}
		}
	}

	return 0;
}
