/*
 *  libnss-winz, Yet another libnss-wins
 *  Copyright (C) 2019 Shinichi Fuchita (@soramimi_jp)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file incorporates some code from these modules:
 *    nss-mdns, (C) 2004 Lennart Poettering.
 *    nss-gw-name, (C) 2010 Joachim Breitner.
 *    nss-openvpn, (C) 2014 Gonéri Le Bouder
 */

#include <algorithm>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <nss.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define stricmp(A, B) strcasecmp(A, B)

/// network interfaces

struct netif_t {
	uint32_t addr;
	uint32_t mask;
};

void get_netif_table(std::vector<netif_t> *out)
{
	out->clear();
	struct ifaddrs *ifa_list;
	if (getifaddrs(&ifa_list) == 0) {
		for (struct ifaddrs *ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr) {
				if (ifa->ifa_addr->sa_family == AF_INET) {
					netif_t netif;
					netif.addr = ntohl(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr);
					netif.mask = ntohl(((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr);
					if (netif.addr == 0) continue;
					if (netif.addr == 0x7f000001) continue;
					if (netif.addr == 0x7f000101) continue;
					out->push_back(netif);
				} else if (ifa->ifa_addr->sa_family == AF_INET6) {
					// not implemented
				}
			}
		}
		freeifaddrs(ifa_list);
	}
}

/// name resolver

void encode_netbios_name(char const *name, std::vector<uint8_t> *out)
{
	out->clear();
	for (int i = 0; i < 16; i++) {
		int c = 0;
		if (i < 15) {
			c = toupper((uint8_t)*name);
			if (c) {
				name++;
			} else {
				c = ' ';
			}
		}
		int a = 'A' + (c >> 4);
		int b = 'A' + (c & 0x0f);
		out->push_back(a);
		out->push_back(b);
	}
}

std::string decode_netbios_name(char const *bytes, int len)
{
	int n = len / 2;
	std::vector<char> vec;
	vec.reserve(n);
	for (int i = 0; i < len; i++) {
		char c = ((bytes[i * 2] - 'A') << 4) | ((bytes[i * 2 + 1] - 'A') & 0x0f);
		if (c == 0 || c == ' ') break;
		vec.push_back(c);
	}
	return vec.empty() ? std::string() : std::string(vec.data(), vec.size());
}

static int getname(char const *buf, char const *end, int pos, std::string *out)
{
	while (buf + pos < end) {
		int n = (uint8_t)buf[pos];
		pos++;
		if (n == 0) break;
		if ((n & 0xc0) == 0xc0) {
			n = (n & 0x3f) | (uint8_t)buf[pos];
			pos++;
			getname(buf, end, n, out);
			break;
		}
		if (!out->empty()) {
			*out += '.';
		}
		*out += std::string(buf + pos, n);
		pos += n;
	}
	return pos;
}

enum Mode {
	DNS,
	MDNS,
	WINS,
	LLMNR,
};

int query_send(Mode mode, std::string const &name, netif_t const *netif)
{
	int sock;
	struct sockaddr_in addr = {};
	struct ip_mreq mreq = {};
	bool multicast = false;
	char buf[2048];
	// AF_INET+SOCK_DGRAMなので、IPv4のUDPソケット
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	// 待ち受けポート番号を137にするためにbind()を行う
	addr.sin_family = AF_INET;
	in_addr_t a = 0;
	if (mode == WINS) {
		if (netif) {
			a = netif->addr | ~netif->mask;
			a = htonl(a);
		} else {
			a = INADDR_ANY;
		}
		int yes = 1;
		addr.sin_port = htons(137);
		addr.sin_addr.s_addr = a;
		setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
	} else if (mode == LLMNR) {
		addr.sin_port = htons(5355);
		addr.sin_addr.s_addr = INADDR_ANY;
		mreq.imr_multiaddr.s_addr = htonl(0xe00000fc); // 224.0.0.252
		multicast = true;
	} else if (mode == MDNS) {
		addr.sin_port = htons(5353);
		addr.sin_addr.s_addr = INADDR_ANY;
		mreq.imr_multiaddr.s_addr = htonl(0xe00000fb); // 224.0.0.251
		multicast = true;
	} else if (mode == DNS) {
		addr.sin_port = htons(53);
		addr.sin_addr.s_addr = htonl(0x08080808); // 8.8.8.8
	}
	bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	// 問い合わせパケットを送信
	{
		size_t pos;
		auto Write16 = [&](uint16_t v){
			buf[pos++] = v >> 8;
			buf[pos++] = v & 255;
		};

		memset(buf, 0, sizeof(buf));

		uint16_t id = 0x0001;

		uint16_t flags = 0x0110;

		uint16_t *p = (uint16_t *)buf;
		p[0] = htons(id); // ID
		p[1] = htons(flags); // flags
		p[2] = htons(1); // QDCOUNT
		p[3] = htons(0); // ANCOUNT
		p[4] = htons(0); // NSCOUNT
		p[5] = htons(0); // ARCOUNT
		pos = 6 * 2;
		{
			std::vector<uint8_t> namebytes;
			if (mode == WINS) {
				encode_netbios_name(name.c_str(), &namebytes);
			} else {
				char const *p = name.c_str();
				namebytes.assign(p, p + name.size());
			}
			uint8_t const *src = namebytes.data();
			uint8_t const *end = src + namebytes.size();
			int n = 0;
			while (1) {
				int c = 0;
				if (src + n < end) {
					c = (unsigned char)src[n];
				}
				if (c == '.' || c == 0) {
					buf[pos++] = n;
					memcpy(buf + pos, src, n);
					pos += n;
					src += n;
					if (c == 0) {
						buf[pos++] = 0;
						break;
					}
					src++;
					n = 0;
				} else {
					n++;
				}
			}
		}
		if (mode == WINS) {
			Write16(0x0020); // Type: NB
		} else {
			Write16(0x0001); // Type: A
		}
		Write16(0x0001); // Class: IN

		if (multicast) {
			addr.sin_addr.s_addr = mreq.imr_multiaddr.s_addr;
		}
		sendto(sock, buf, pos, 0, (struct sockaddr *)&addr, sizeof(addr));
	}

	if (multicast) {
		mreq.imr_interface.s_addr = INADDR_ANY;
		setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq));
	}

	return sock;
}

void query_recv(Mode mode, int sock, std::string name, std::vector<uint32_t> *addrs_out)
{
	{ // set to non blocking
		int yes = 1;
		ioctl(sock, FIONBIO, &yes);
	}
	
	// 応答パケットを受信
	int len = 0;
	uint32_t from = 0;
	char buf[2048];
	socklen_t addrlen;
	struct sockaddr_in senderinfo;
	memset(buf, 0, sizeof(buf));
	// recvfrom()を利用してUDPソケットからデータを受信
	addrlen = sizeof(senderinfo);
	len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&senderinfo, &addrlen);
	from = ntohl(senderinfo.sin_addr.s_addr);

	if (0) {
		// 送信元に関する情報を表示
		char senderstr[16];
		inet_ntop(AF_INET, &senderinfo.sin_addr, senderstr, sizeof(senderstr));
		printf("recvfrom : %s, port=%d, length=%d\n", senderstr, ntohs(senderinfo.sin_port), len);
	}

	if (len > 0) {
		struct Answer {
			std::string name;
			uint32_t addr;
			Answer() = default;
			Answer(std::string const &name, uint32_t addr)
				: name(name)
				, addr(addr)
			{
			}
		};

		std::vector<Answer> answers;
		std::map<std::string, std::string> cnames;
		char const *end = buf + len;
		size_t pos;
		auto Read16 = [&](){
			uint8_t const *p = (uint8_t const *)(buf + pos);
			uint16_t v = (p[0] << 8) | p[1];
			pos += 2;
			return v;
		};
		auto Read32 = [&](){
			uint8_t const *p = (uint8_t const *)(buf + pos);
			uint32_t v = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
			pos += 4;
			return v;
		};
		uint16_t *p = (uint16_t *)buf;
		uint16_t id = ntohs(p[0]); // ID
		uint16_t flags = ntohs(p[1]); // flags
		uint16_t qdcount = ntohs(p[2]); // QDCOUNT
		uint16_t ancount = ntohs(p[3]); // ANCOUNT
		uint16_t nscount = ntohs(p[4]); // NSCOUNT
		uint16_t arcount = ntohs(p[5]); // ARCOUNT
		(void)id;
		(void)flags;
		(void)nscount;
		(void)arcount;
		pos = 6 * 2;
		for (int i = 0; i < qdcount; i++) {
			std::string aname;
			pos = getname(buf, end, pos, &aname);
			Read16();
			Read16();
		}
		for (int a = 0; a < ancount; a++) {
			std::string aname;
			pos = getname(buf, end, pos, &aname);
			if (mode == WINS) {
				aname = decode_netbios_name(aname.c_str(), aname.size());
			}
			uint16_t type = Read16();
			uint16_t clas = Read16();
			uint32_t time = Read32();
			(void)time;
			if (mode == WINS) {
				uint16_t dlen = Read16(); // data length
				int i = 0;
				while (i + 5 < dlen && pos + 5 < (size_t)len) {
					Read16(); // flags
					uint32_t addr = Read32();
					answers.emplace_back(aname, addr);
					i += 6;
				}
			} else if (mode == LLMNR || mode == MDNS || mode == DNS) {
				if (type == 1 && clas == 1) {
					int n = Read16(); // data length
					if (n == 4) {
						uint32_t addr = Read32();
						answers.emplace_back(aname, addr);
					} else {
						pos += n;
					}
				} else if (type == 5 && clas == 1) { // CNAME
					int n = Read16(); // data length
					if (n == 2) {
						std::string cname;
						getname(buf, buf + pos + n, pos, &cname);
						cnames[aname] = cname;
					}
					pos += n;
				}
			}
		}

		auto it = cnames.find(name);
		if (it != cnames.end()) {
			name = it->second;
		}

		if (!answers.empty()) {
			for (size_t i = 0; i < answers.size(); i++) {
				Answer const &ans = answers[i];
				if (stricmp(ans.name.c_str(), name.c_str()) == 0) {
					if (ans.addr == from) {
						addrs_out->insert(addrs_out->begin(), ans.addr);
					} else {
						addrs_out->push_back(ans.addr);
					}
				}
			}
		}
	}
}

void query(std::string name, std::vector<uint32_t> *addrs_out)
{
	addrs_out->clear();

	bool mdns = false;
	bool wins = true;
	bool llmnr = true;

	{
		char const *p = strchr(name.c_str(), '.');
		if (p && strcmp(p, ".local") == 0) {
			mdns = true;
			wins = false;
		} else {
			for (int i = 0; name[i]; i++) {
				if (i >= 15) { // too long
					wins = false;
				}
				int c = (unsigned char)name[i];
				if (isalnum(c)) {
					// ok
				} else if (isspace(c) || strchr(".\\/:+?\"<>|", c)) {
					return; // invalid name
				}
			}
		}
	}


	std::vector<netif_t> netifs;
	get_netif_table(&netifs);

	struct Query {
		Mode mode = Mode::WINS;
		int sock = -1;
		Query() = default;
		Query(Mode mode, int sock)
			: mode(mode)
			, sock(sock)
		{
		}
	};

	std::vector<Query> queries;

	for (int retry = 0; retry < 3; retry++) {
		auto AddQuery = [&](Mode mode, std::string const &name, netif_t const *netif){
			queries.emplace_back(mode, query_send(mode, name, netif));
		};
		if (mdns) {
			AddQuery(Mode::MDNS, name, nullptr);
		}
		if (wins) {
			AddQuery(Mode::WINS, name, nullptr);
			for (netif_t const &netif : netifs) {
				AddQuery(Mode::WINS, name, &netif);
			}
		}
		if (llmnr) {
			AddQuery(Mode::LLMNR, name, nullptr);
		}
		std::sort(queries.begin(), queries.end(), [](Query const &l, Query const &r){ return l.sock < r.sock; });
		int maxfd = queries.back().sock;


		fd_set fds;
		FD_ZERO(&fds);
		for (Query const &q : queries) {
			FD_SET(q.sock, &fds);
		}
		struct timeval timeout = {};
		timeout.tv_sec = 0;
		timeout.tv_usec = 300000;
		select(maxfd + 1, &fds, nullptr, nullptr, &timeout);
		for (Query const &q : queries) {
			if (FD_ISSET(q.sock, &fds)) {
				query_recv(q.mode, q.sock, name, addrs_out);
				break;
			}
		}

		for (Query const &q : queries) {
			close(q.sock);
		}

		if (!addrs_out->empty()) break;
	}
}

/// nsswitch interface

#define ALIGN(idx) do { \
	if (idx % sizeof(void*)) \
	idx += (sizeof(void*) - idx % sizeof(void*)); /* Align on 32 bit boundary */ \
	} while(0)

extern "C" enum nss_status _nss_winz_gethostbyname_r(const char *name, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	size_t idx, astart;

	std::vector<uint32_t> addrs;

	query(name, &addrs);
	if (!addrs.empty()) {
		*(char **)buffer = NULL;
		result->h_aliases = (char **)buffer;
		idx = sizeof(char *);

		strcpy(buffer + idx, name);
		result->h_name = buffer + idx;
		idx += strlen(name) + 1;
		ALIGN(idx);

		result->h_addrtype = AF_INET;
		result->h_length = sizeof(uint32_t);

		uint32_t addr = htonl(addrs.front());

		astart = idx;
		memcpy(buffer + astart, &addr, sizeof(uint32_t));
		idx += sizeof(uint32_t);

		result->h_addr_list = (char **)(buffer + idx);
		result->h_addr_list[0] = buffer + astart;
		result->h_addr_list[1] = NULL;

		return NSS_STATUS_SUCCESS;
	}

	*errnop = EINVAL;
	*h_errnop = NO_RECOVERY;
	return NSS_STATUS_UNAVAIL;

}

extern "C" enum nss_status _nss_winz_gethostbyname2_r(const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	if (af != AF_INET) {
		*errnop = EAGAIN;
		*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	} else {
		return _nss_winz_gethostbyname_r(name, result, buffer, buflen, errnop, h_errnop);
	}
}

