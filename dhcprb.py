import os, sys, socket, select, time
import array, struct

def if_cmd(intf):
	os.system("( ip -4 link show dev '%s' ; ip -4 addr show dev '%s' ) | \
        grep -Ei '(ether|inet) ' | awk '{ print $2 }' | sed -e 's@/.*$@@' > /tmp/i.txt" % (intf, intf))
	f = open("/tmp/i.txt", "r")
	l = f.readlines()
	f.close()
	o = (l[0].strip(), l[1].strip())
	return o

def secs():
	return int(time.time())

def hexs(hstr):
	try:
		return int(hstr, 16)
	except:
		return 0

def read_file(file_name):
	lines = []
	try:
		fobjc = open(file_name, "r")
		lines = fobjc.readlines()
	except:
		pass
	try:
		fobjc.close()
	except:
		pass
	return lines

def get_mac(mac):
	return "".join([chr(hexs(h)) for h in mac.split(":")])

def get_adr(adr):
	try:
		return socket.inet_ntoa(adr)
	except:
		return socket.inet_ntoa("\x00\x00\x00\x00")

def sock_aton(ipstr):
	try:
		return socket.inet_aton(ipstr)
	except:
		return socket.inet_aton("0.0.0.0")

def sock_send(mode, intf, data):
	stypes = {"udp":(socket.AF_INET, socket.SOCK_DGRAM), "raw":(socket.AF_PACKET, socket.SOCK_RAW)}
	try:
		sock = socket.socket(stypes[mode][0], stypes[mode][1])
		if (mode == "udp"):
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, intf+'\0')
			sock.sendto("76543210", (data, 1))
		if (mode == "raw"):
			sock.bind((intf, 0))
			sock.send(data)
	except:
		pass
	try:
		sock.close()
	except:
		pass

def checksum(pkt):
	if len(pkt) % 2 == 1:
		pkt += "\0"
	s = sum(array.array("H", pkt))
	s = ((s >> 16) + (s & 0xffff))
	s += (s >> 16)
	s = ~s
	return ((((s>>8)&0xff)|(s<<8))&0xffff)

class ETH(object):
	def __init__(self, src, dst, mod):
		self.mode = {"udp":socket.ETH_P_IP, "arp":socket.ETH_P_ARP}
		self.sorc = src ; self.dest = dst ; self.type = self.mode[mod]
	def pack(self, pay=""):
		out = struct.pack("!6s6sH", self.dest, self.sorc, self.type)
		return (out + pay)

class IPF(object):
	def __init__(self, src, dst):
		self.prep = 0 ; self.siz = 20
		self.ver_ihl = 0x45 ; self.ip_tos = 0
		self.ip_iden = 3210 ; self.ip_flg = (0x4 << 12)
		self.ip_ttl = 8 ; self.ip_prot = socket.IPPROTO_UDP ; self.ip_chk = 0
		self.ip_src = sock_aton(src) ; self.ip_dst = sock_aton(dst)
	def pack(self, pay=""):
		if (self.prep == 0):
			self.prep = 1
			self.ip_chk = checksum(self.pack(pay))
			self.prep = 2
		self.ip_tol = (self.siz + len(pay))
		out = struct.pack("!BBHHHBBH4s4s",
			self.ver_ihl, self.ip_tos, self.ip_tol,
			self.ip_iden, self.ip_flg,
			self.ip_ttl, self.ip_prot, self.ip_chk,
			self.ip_src, self.ip_dst
		)
		if (self.prep < 2):
			return out
		return (out + pay)

class UDP(object):
	def __init__(self, src, dst):
		self.sport = src ; self.dport = dst ; self.siz = 8 ; self.chk = 0
	def pack(self, pay=""):
		self.tol = (self.siz + len(pay))
		out = struct.pack("!HHHH", self.sport, self.dport, self.tol, self.chk)
		return (out + pay)

class ARP(object):
	def __init__(self, src, dst, who, dip, mod):
		self.mode = {"req":1, "rep":2}
		self.hw_type = 1 ; self.proto_type = socket.ETH_P_IP
		self.hw_size = 6 ; self.proto_size = 4
		self.op = self.mode[mod]
		self.sndr_hw = src ; self.sndr_ip = sock_aton(who)
		self.rcpt_hw = dst ; self.rcpt_ip = sock_aton(dip)
	def pack(self, pay=""):
		out = struct.pack("!HHBBH6s4s6s4s",
			self.hw_type, self.proto_type,
			self.hw_size, self.proto_size,
			self.op,
			self.sndr_hw, self.sndr_ip,
			self.rcpt_hw, self.rcpt_ip
		)
		return (out + pay)

def budp(smac, sprt, dmac, dprt, data, sadr="0.0.0.0", dadr="255.255.255.255"):
	udpd = UDP(sprt, dprt).pack(pay=data)
	ipfd = IPF(sadr, dadr).pack(pay=udpd)
	ethd = ETH(smac, dmac, "udp").pack(pay=ipfd)
	return ethd

def barp(src_mac, dst_mac, who_adr, dst_adr):
	arpd = ARP(src_mac, dst_mac, who_adr, dst_adr, "rep").pack(pay="")
	ethd = ETH(src_mac, dst_mac, "arp").pack(pay=arpd)
	return ethd

def relayd(mode, ints, adrs, data):
	re_udp = data["dhcp"] ; re_arp = data["arpt"]["map"]
	null = [("", 0, 0)] ; d_map = {67:"->", 68:"<-"}

	if (mode[0] == 'd'):
		(s_port, d_port, d_mac, s_adr, y_adr, d_op) = data[mode]["a"]

		for ifna in ints:
			(imac, iadr) = adrs[ifna]
			print("   dhcp:req  %s [%d:%d] {%s:%s}" % (d_map[d_port], len(re_udp), d_op, ifna, y_adr))
			data["dt"]["d"] = re_udp ; data["dy"]["d"] = re_udp
			if (ord(re_udp[24]) == 0): # set the GIADDR (Gateway IP) field
				data["dt"]["d"] = (re_udp[:24] + sock_aton(iadr) + re_udp[28:])
			rpkt = budp(imac, s_port, d_mac, d_port, data[mode]["d"], sadr=s_adr)
			sock_send("raw", ifna, rpkt)

	if (mode[0] == 'a'):
		(req_adr, dst_adr, dst_mac) = data[mode]
		arp_whos = re_arp.get(req_adr, null)
		arp_dsts = re_arp.get(dst_adr, null)
		print("<- arp:req              [%s] ?-> [%s]" % (req_adr, dst_adr))

		for arp_dst in arp_dsts:
			(dst_intf, dst_stat, dst_ping) = arp_dst
			if (dst_stat <= -1):
				continue

			for arp_who in arp_whos:
				(who_intf, who_stat, who_ping) = arp_who
				if (who_stat <= -1):
					continue

				for ifna in ints:
					(imac, iadr) = adrs[ifna]
					if (who_intf == ifna):
						continue

					if ((who_stat >= 1) and ((not dst_intf) or (dst_intf == ifna))):
						print("-> arp:reply    [%s][%s] @-> [%s][%s]" % (who_intf, req_adr, dst_adr, ifna))
						rpkt = barp(imac, dst_mac, req_adr, dst_adr)
						sock_send("raw", ifna, rpkt)

					if ((who_stat == 0) and ((not dst_intf) or (dst_intf != ifna))):
						if (who_ping == 0):
							print("-- arpw:ping -- [%s][%s]" % (ifna, req_adr))
							sock_send("udp", ifna, req_adr)
							re_arp[req_adr] = [(ifna, 0, 1)]

			if ((dst_stat == 0) and (dst_ping == 0)):
				for ifna in ints:
					print("-- arpd:ping -- [%s][%s]" % (ifna, dst_adr))
					sock_send("udp", ifna, dst_adr)
					re_arp[dst_adr] = [(ifna, 0, 1)]

def read_rout():
	routs = {}
	lines = read_file("/proc/net/route")
	for line in lines:
		info = line.strip().split()
		try:
			adrn = int(info[1], 16)
			adrl = [str((adrn >> x) & 0xff) for x in [0, 8, 16, 24]]
			addr = ".".join(adrl)
		except:
			addr = ""
		if (not addr):
			continue
		if (not addr in routs.keys()):
			routs[addr] = []
		routs[addr].append(info[0])
	return routs

def read_arps(objc, ints):
	arps = {} ; leng = 0 ; ping = 0

	allifs = ints.keys()
	for intf in allifs:
		(hmac, iadr) = ints[intf]
		arps[iadr] = [(intf, 1, 0)] ; leng += 1

	route = read_rout()
	lines = read_file("/proc/net/arp")
	for line in lines:
		info = line.strip().split()
		try:
			(addr, flag, intf, stat) = (info[0], info[2], info[-1], -1)
			(adrn, flgn) = (int(addr[0]), hexs(flag))
		except:
			(adrn, flgn) = (0, 0)

		if ((adrn > 0) and (flgn > 0) and (leng < 256)):
			if (intf in allifs):
				stat = 1
			if (not addr in arps.keys()):
				arps[addr] = []
			arps[addr].append((intf, stat, ping)) ; leng += 1

			if (stat == 1):
				sock_send("udp", intf, addr)
				rchk = route.get(addr, [])
				if (not intf in rchk):
					print("route host [%s][%s]" % (addr, intf))
					os.system("ip -4 route replace '%s/32' dev '%s' proto static" % (addr, intf))

	objc["map"] = arps ; objc["len"] = leng


def main():
	lens = len(sys.argv)
	if (lens < 3):
		print("Usage: dhcprb.py [dhcp clients if0] [dhcp clients if1] ... [dhcp server if]")
		return 1

	socket.SO_BINDTODEVICE = 25
	socket.ETH_P_IP = 0x0800
	socket.ETH_P_ARP = 0x0806
	socket.null = "0.0.0.0"
	socket.ffff = "\xff\xff\xff\xff\xff\xff"

	loops = int(os.environ.get("LOOP", 9))
	clifs = sys.argv[1:lens-1]
	srifs = sys.argv[lens-1:]
	alifs = (clifs + srifs)
	iflist = {}

	for ifna in alifs:
		(ifmac, ifadr) = if_cmd(ifna)
		hwmac = get_mac(ifmac)
		iflist[ifna] = (hwmac, ifadr)
	print([iflist[ifkey] for ifkey in clifs], "<-->", [iflist[ifkey] for ifkey in srifs])

	sock_dhcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock_dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock_dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock_dhcp.bind(("", 67))

	sock_opts = socket.htons(socket.ETH_P_ARP)
	sock_arps = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, sock_opts)

	dhcc = {"len":0, "ops":{3:chr(5)}, "map":{}} ; arpt = {"len":0, "sec":0, "map":{}}
	while True:
		csec = secs()
		if ((csec - arpt["sec"]) >= loops):
			print("reads begf [%d]" % (secs()))
			read_arps(arpt, iflist)

			ckeys = dhcc["map"].keys()
			for ckey in ckeys:
				if ((csec - dhcc["map"][ckey][0]) >= (15 * 60)):
					del dhcc["map"][ckey]
			dhcc["len"] = len(dhcc["map"].keys())

			print("reads endf [%d] [%d][%d][%d]" % (secs(), arpt["sec"], arpt["len"], dhcc["len"]))
			arpt["sec"] = csec


		inpt = [sock_dhcp, sock_arps] ; outp = []
		(reads, sends, erros) = select.select(inpt, outp, inpt)
		for sock in reads:
			(buff, addr) = sock.recvfrom(1024)
			data = {"dhcp":buff, "arpt":arpt}

			if (sock == sock_dhcp):
				try:
					op = ord(buff[242]) # get option(53) MESG-TYPE
				except:
					op = 0
				try:
					ochr = dhcc["ops"][op]
					(null, cached) = dhcc["map"][buff[28:34]+ochr]       # use requester mac
					data["dhcp"] = (cached[:4] + buff[4:8] + cached[8:]) # set the XID field
				except:
					cached = ""

				if ((1 <= op) and (op <= 5)):
					d_mac = data["dhcp"][28:34]          # get the CHADDR (Client HW) field
					s_adr = get_adr(data["dhcp"][20:24]) # get the SIADDR (Server IP) field
					y_adr = get_adr(data["dhcp"][16:20]) # get the YIADDR (Assign IP) field
					y_hex = hex(ord(d_mac[0]))

					data["dt"] = {"a":(68, 67, socket.ffff, socket.null, y_hex, op)}
					data["dy"] = {"a":(67, 68, d_mac, s_adr, y_adr, op)}

					if ((addr[0] == socket.null) and (cached == "")):
						relayd('dt', srifs, iflist, data)

					if ((addr[0] != socket.null) or  (cached != "")):
						relayd('dy', clifs, iflist, data)
						if ((not cached) and (dhcc["len"] < 512)):
							print("cache dhcp [%d][%s]" % (op, y_adr))
							dhcc["map"][d_mac+chr(op)] = (secs(), data["dhcp"])
							dhcc["len"] = len(dhcc["map"].keys())

			if (sock == sock_arps):
				try:
					(op, sndr_hw, sndr_ip, rcpt_hw, rcpt_ip) = struct.unpack("!H6s4s6s4s", buff[20:42])
					(req_adr, dst_adr) = (get_adr(rcpt_ip), get_adr(sndr_ip))
				except:
					(op, req_adr, dst_adr) = (-1, "", "")

				if ((op == 1) and (req_adr != socket.null) and (dst_adr != socket.null)):
					data["at"] = (req_adr, dst_adr, sndr_hw)
					relayd('at', alifs, iflist, data)


main()
