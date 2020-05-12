/*
export PATH="/tmp/usr/bin:$PATH"
export LD_LIBRARY_PATH=/tmp/usr/lib:/usr/lib:/lib:.
export CPATH=/tmp/usr/include:.
export LIBRARY_PATH="$LD_LIBRARY_PATH"
gcc -Wall -o arprb arprb.c
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
#include <net/if.h>
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
#define CACHE_LEN 16
#define TABLE_LEN 277
#define STAT_ERRO -3
#define STAT_IGNO -2
#define STAT_NULL -1
#define STAT_GOOD 0

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

struct intf {
	int sock_req, sock_arp;
	char *ifn;
	char smac[32], sadr[32];
	unsigned char mac[8], adr[4];
	struct sockaddr ssa;
};

struct reqs {
	int stat, trys;
	unsigned long numb;
	char whoa[32], dsta[32];
	unsigned char dstm[8];
};

struct arps {
	int intf, stat;
	char iadr[32];
};

int RREV = 0;

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
		p[i].intf = STAT_NULL; p[i].stat = STAT_NULL; p[i].iadr[0] = 0;
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

void send_ping(char *intf, char *iadr, int show) {
	int sock;
	struct sockaddr_in sain;
	if (intf == NULL) { return; }
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

	if (dest != NULL) {
		addr = (struct sockaddr_in *)&route.rt_gateway;
		addr->sin_family = AF_INET;
		route.rt_dev = dest;
		ioctl(fd, SIOCADDRT, &route);
	}

	close(fd);
}

int read_rout(int *rlist, struct arps *routes, struct intf *relayds) {
	int leng = 0;
	char line[256];
	char *p, *srcif, taadr[32];

	bzero(line, 256);
	I(routes);

	FILE *fobj = fopen("/proc/net/route", "r");
	if (fobj != NULL) {
		while (fgets(line, 250, fobj) != NULL) {
			if ((line[0] < 'a') || ('z' < line[0])) { bzero(line, 256); continue; }
			srcif = line; p = line;

			/* field 1 - interface */
			while ((*p != '\t') && (*p != '\0')) { ++p; } *p = '\0'; ++p;

			/* field 2 - ip address in hex in reverse */
			bzero(taadr, 32);
			if (RREV == 0) {
				snprintf(taadr, 30, "%d.%d.%d.%d", hexd(p[6],p[7]), hexd(p[4],p[5]), hexd(p[2],p[3]), hexd(p[0],p[1])); p += 9;
			} else {
				snprintf(taadr, 30, "%d.%d.%d.%d", hexd(p[0],p[1]), hexd(p[2],p[3]), hexd(p[4],p[5]), hexd(p[6],p[7])); p += 9;
			}

			/* field 3 - skip gateway */
			p += 9;

			/* field 4 - flags */
			p[4] = '\0';

			if (strnlcmp(p, "0005", 4) == 0) {
				for (int i = 0; i < RELAY_LEN; ++i) {
					if (strnlcmp(relayds[i].ifn, srcif, 30) == 0) {
						int j = K(routes, taadr);
						//printf("route table -- [%s][%s](%d) <- (%d)\n", srcif, taadr, i, j);
						if (j >= 0) {
							bzero(routes[j].iadr, 32);
							strncpy(routes[j].iadr, taadr, 30);
							routes[j].intf = i;
							if (leng < TABLE_LEN) { rlist[leng] = j; ++leng; }
						}
						break;
					}
				}
			}

			bzero(line, 256);
		}

		fclose(fobj);
	}

	return leng;
}

int read_arps(struct arps *clients, struct intf *relayds) {
	int leng = 0, rlen, ridx[TABLE_LEN];
	char line[256];
	char *p, *q, *taadr, *flags, *srcif;
	struct arps routes[TABLE_LEN];

	bzero(line, 256);
	I(clients);
	rlen = read_rout(&(ridx[0]), &(routes[0]), relayds);

	for (int i = 0; i < RELAY_LEN; ++i) {
		if (relayds[i].ifn == NULL) { continue; }
		int j = K(clients, relayds[i].sadr);
		/* init with our known interface addresses */
		if (j >= 0) {
			bzero(clients[j].iadr, 32);
			strncpy(clients[j].iadr, relayds[i].sadr, 30);
			clients[j].intf = i;
			clients[j].stat = STAT_GOOD;
			if (leng < TABLE_LEN) { ++leng; }
		}
	}

	FILE *fobj = fopen("/proc/net/arp", "r");
	if (fobj != NULL) {
		while (fgets(line, 250, fobj) != NULL) {
			if ((line[0] < '0') || ('9' < line[0])) { bzero(line, 256); continue; }
			taadr = line; flags = NULL; srcif = NULL; q = NULL; p = line;

			/* field 1 - IP address - with trailing space replace with null */
			while ((*p != ' ') && (*p != '\0')) { ++p; }
			if (*p == ' ') { *p = '\0'; ++p; }

			/* field 2 & 3 - ARP type & flags - in hex so find the x > 0 */
			while ((*p != 'x') && (*p != '\0')) { ++p; }
			if (*p == 'x') {
				++p; while ((*p != 'x') && (*p != '\0')) { ++p; }
				if (*p == 'x') { ++p; if (*p > '0') { flags = p; } }
			}

			/* field NF - Interface name - with trailing newline replace with null */
			while ((*p != '\n') && (*p != '\0')) { if (*p == ' ') { q = p; } ++p; }
			if ((q != NULL) && (*p == '\n')) { srcif = (q + 1); *p = '\0'; }

			if ((taadr != NULL) && (flags != NULL) && (srcif != NULL)) {
				//printf("arp table -- [%s][%s] (0x%c)\n", srcif, taadr, flags[0]);
				int j = K(clients, taadr);
				/* set the known client address and interface */
				if (j >= 0) {
					int intf = STAT_ERRO;
					for (int i = 0; i < RELAY_LEN; ++i) {
						if (strnlcmp(relayds[i].ifn, srcif, 30) == 0) {
							send_ping(relayds[i].ifn, taadr, 0);
							intf = i; break;
						}
					}
					if (intf < STAT_GOOD) { clients[j].stat = STAT_ERRO; }
					/* arp cache can have multiple entries for a host on multiple interfaces */
					if (clients[j].stat == STAT_GOOD) { clients[j].stat = STAT_IGNO; }
					if (clients[j].intf == STAT_NULL) {
						bzero(clients[j].iadr, 32);
						strncpy(clients[j].iadr, taadr, 30);
						clients[j].intf = intf;
						if (clients[j].stat == STAT_NULL) { clients[j].stat = STAT_GOOD; }
						if (leng < TABLE_LEN) { ++leng; }
					}
					int r = K(routes, taadr);
					/* process the client interface route entry */
					if (r >= 0) {
						/* del route to let the os expire multiple arps */
						if (clients[j].stat == STAT_IGNO) { routes[r].stat = STAT_IGNO; }
						/* add route if missing or set route if incorrect */
						else if (routes[r].intf != intf) {
							bzero(routes[r].iadr, 32);
							strncpy(routes[r].iadr, taadr, 30);
							routes[r].intf = intf;
							routes[r].stat = STAT_ERRO;
						}
						/* mark route as good if no other issues */
						else if (routes[r].stat == STAT_NULL) { routes[r].stat = STAT_GOOD; }
						if (rlen < TABLE_LEN) { ridx[rlen] = r; ++rlen; }
					}
				}
			}

			bzero(line, 256);
		}

		fclose(fobj);
	}

	for (int i = 0; i < rlen; ++i) {
		int j = ridx[i];
		if (j >= TABLE_LEN) { continue; }
		int intf = routes[j].intf;
		if (intf < STAT_GOOD) { continue; }
		if (routes[j].stat == STAT_ERRO) {
			printf("route add ++ [%s][%s] [%d] (%d:%d)\n", routes[j].iadr, relayds[intf].ifn, routes[j].stat, j, rlen);
			route_mod(routes[j].iadr, relayds[intf].ifn);
		}
		else if (routes[j].stat != STAT_GOOD) {
			printf("route del -- [%s] [%d] (%d:%d)\n", routes[j].iadr, routes[j].stat, j, rlen);
			route_mod(routes[j].iadr, NULL);
		}
	}

	return leng;
}

int main(int argc, char **argv) {
	int rlen, loop, leng = 0, cidx = 0;
	char *p;
	char bstr[256];
	struct intf relayds[RELAY_LEN];
	struct reqs cacheds[CACHE_LEN];
	struct arps clients[TABLE_LEN];
	time_t secs = 0, last = 0;

	int proc_arp, sock_max = 0;
	unsigned char *t;
	unsigned char buff[1024];
	struct sockaddr_ll sall;
	struct arp_pkt apkt;
	fd_set so_set, re_set;

	p = getenv("LOOP");
	if (p == NULL) { p = "0"; }
	loop = atoi(p);
	if (loop < 3) { loop = 9; }
	p = getenv("RREV");
	if (p != NULL) { RREV = 1; }

	if (argc < 3) {
		printf("Usage: arprb eth0 wlan0\n"); return 1;
	}

	FD_ZERO(&so_set);

	bzero(relayds, RELAY_LEN * sizeof(struct intf));
	for (int i = 0; (i < RELAY_LEN) && ((i + 1) < argc); ++i) {
		relayds[i].ifn = argv[i + 1]; p = relayds[i].ifn;

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

		relayds[i].sock_req = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
		if (relayds[i].sock_req < 0) {
			printf("sock arp\n"); return 2;
		}
		bzero(&sall, sizeof(struct sockaddr_ll));
		sall.sll_family = AF_PACKET;
		sall.sll_protocol = htons(ETH_P_ARP);
		sall.sll_pkttype = PACKET_BROADCAST;
		sall.sll_hatype = ARPHRD_ETHER;
		sall.sll_halen = ETH_ALEN;
		sall.sll_ifindex = if_nametoindex(relayds[i].ifn);
		if (bind(relayds[i].sock_req, (struct sockaddr *)(&sall), sizeof(struct sockaddr_ll)) < 0) {
			printf("bind arp\n"); return 3;
		}
		if (relayds[i].sock_req > sock_max) { sock_max = relayds[i].sock_req; }
		FD_SET(relayds[i].sock_req, &so_set);

		relayds[i].sock_arp = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
		if (relayds[i].sock_arp < 0) {
			printf("relay arp [%d][%d]\n", i, relayds[i].sock_arp); return 9;
		}
		bzero(&(relayds[i].ssa), sizeof(struct sockaddr));
		strncpy(relayds[i].ssa.sa_data, relayds[i].ifn, sizeof(relayds[i].ssa.sa_data));

		printf("-> [%s][%s][%s]\n", relayds[i].ifn, relayds[i].smac, relayds[i].sadr);
	}

	system("./tune.sh");

	for (int j = 0; j < CACHE_LEN; ++j) {
		cacheds[j].stat = -1; cacheds[j].trys = 0; cacheds[j].numb = 0;
	}

	while (1) {
		struct timeval time_out = {2, 0};
		memcpy(&re_set, &so_set, sizeof(so_set));
		if (select(sock_max+1, &re_set, NULL, NULL, &time_out) < 0) {
			printf("select\n"); return -1;
		}

		secs = time(NULL);
		proc_arp = 0;
		if ((secs - last) >= loop) {
			printf("read file >> [%ld][%d]\n", secs, leng);
			leng = read_arps(&(clients[0]), &(relayds[0]));
			last = time(NULL);
			for (int j = 0; j < CACHE_LEN; ++j) { if (cacheds[j].trys > 0) { cacheds[j].trys -= 1; } }
			proc_arp = 1;
			printf("read file << [%ld][%d]\n", last, leng);
		}

		for (int z = 0; z < RELAY_LEN; ++z) {
			if ((relayds[z].ifn == NULL) || (!FD_ISSET(relayds[z].sock_req, &re_set))) { continue; }

			bzero(buff, 256);
			rlen = recv(relayds[z].sock_req, buff, 128, 0);
			bcopy(buff, &apkt, sizeof(struct arp_pkt));

			if ((rlen > 16) && (apkt.op_code == htons(ARP_OP_REQ))) {
				int trys = 0;
				unsigned long numb = 0;
				for (int i = 0; i < 4; ++i) { numb = ((numb + (apkt.rcpt_ip[i] * (i + 1))) * 1999); }
				for (int i = 0; i < 4; ++i) { numb = ((numb + (apkt.sndr_ip[i] * (i + 1))) * 2111); }
				for (int j = 0; j < CACHE_LEN; ++j) {
					if (cacheds[j].numb == numb) { cidx = j; trys = cacheds[j].trys; break; }
				}

				struct reqs *c = &(cacheds[cidx]);
				c->stat = 0; c->trys = trys; c->numb = numb;

				bzero(c->whoa, 32); t = apkt.rcpt_ip;
				snprintf(c->whoa, 30, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);

				bzero(c->dsta, 32); t = apkt.sndr_ip;
				snprintf(c->dsta, 30, "%d.%d.%d.%d", t[0], t[1], t[2], t[3]);

				printf("arp reqs  ?? [%s] <- [%s] (%d:%d:%lu)\n", c->whoa, c->dsta, cidx, c->trys, c->numb);
				bcopy(apkt.sndr_hw, c->dstm, 6);
				cidx = ((cidx + 1) % CACHE_LEN);
				proc_arp = 1;
			}
		}

		if (proc_arp == 1) {
			for (int j = 0; j < CACHE_LEN; ++j) {
				int mark = 0;
				struct reqs *c = &(cacheds[j]);
				if (c->stat < 0) { cidx = j; continue; }

				int no_go = 0;
				int who_idx = K(clients, c->whoa), dst_idx = K(clients, c->dsta);
				if ((who_idx < 0) || (clients[who_idx].stat <= STAT_ERRO)) { no_go = 1; }
				if ((dst_idx < 0) || (clients[dst_idx].stat <= STAT_ERRO)) { no_go = 1; }

				if (no_go == 0) {
					int who_int = clients[who_idx].intf, dst_int = clients[dst_idx].intf;
					int who_sta = clients[who_idx].stat, dst_sta = clients[dst_idx].stat;
					for (int i = 0; i < RELAY_LEN; ++i) {
						if (relayds[i].ifn == NULL) { continue; }
						if ((c->stat == 0) && (c->trys < 1)) {
							if (who_sta == STAT_NULL) {
								send_ping(relayds[i].ifn, c->whoa, 1); clients[who_idx].stat = STAT_IGNO;
							}
							if (dst_sta == STAT_NULL) {
								send_ping(relayds[i].ifn, c->dsta, 1); clients[dst_idx].stat = STAT_IGNO;
							}
						}
						if ((who_sta >= STAT_GOOD) && (i != who_int)) {
							if ((dst_sta < STAT_GOOD) || (i == dst_int)) {
								send_arps(&(relayds[i]), c->whoa, c->dstm, c->dsta); mark = 1;
							}
						}
					}
				} else { mark = 1; }

				if (mark == 1) { c->stat = -1; c->trys = 0; }
				else if (c->stat == 0) {
					c->stat = 1; if (c->trys == 0) { c->trys = 2; }
				}
			}
		}
	}

	return 0;
}
