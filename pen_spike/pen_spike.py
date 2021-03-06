#!/usr/bin/env python

# pen_spike.py - An attempt to simplify the ever so complicated SPIKE
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

# Report any issues with this script to <mad_dev@linuxmail.org>

# Tested on crunchbang waldorf(openbox)

# 3rd party DISCLAIMER
#
#  *(
#	By pyfunc http://stackoverflow.com/users/432745/pyfunc
#	Posted on http://stackoverflow.com/questions/4289937/how-to-repeat-last-command-in-python-interpreter-shell
#	)*
# EODISCLAIMER


import sys
import os
import readline 
import rlcompleter 
import atexit 

#*( 
readline.parse_and_bind('tab: complete') 
histfile = os.path.join(os.environ['HOME'], '.SpikeHistory') 
try: 
    readline.read_history_file(histfile) 
except IOError: 
    pass 

atexit.register(readline.write_history_file, histfile) 

del histfile, readline, rlcompleter
#)*

class clr:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    YEL = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    MOV = '\033[96m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''
        self.MOV = ''

spike_list = ['ss_spike', 'generic_web_server_fuzz2', 'msrpcfuzz_udp', 'citrix', 'post_spike','post_fuzz', 'generic_send_tcp', 'generic_web_server_fuzz', 'sendmsrpc', 'ntlm_brute', 'generic_send_udp', 'msrpcfuzz', 'gopherd', 'quakeserver', 'pmspike', 'statd_spike', 'ntlm2', 'x11_spike', 'dceoversmb', 'dltest', 'quake', 'generic_chunked', 'do_post', 'line_send_tcp', 'closed_source_web_server_fuzz', 'halflife', 'sunrpcfuzz', 'webfuzz', 'generic_listen_tcp']

def helps():
	print '\nPen_SPIKE 0.1 by Mad_Dev'
	print 'An attempt to simplify the ever so complicated SPIKE by dave@immunitysec.com'
	print '\n-spike_help	View All SPIKE Commands'
	print '-h [tool]	View Tool Help'
	print '[tool]		Launch Tool'
	print clr.YEL
	print 'Example of [tool]:'
	print clr.OKGREEN+'pen_spike$ ss_spike\nss_spike$'+clr.ENDC + '\n'
	
def spike_commands():
	print '\nWELCOME TO SPIKE...THE FUZZER'
	print clr.HEADER
	print 'SPIKE Consists of '
	for tool in spike_list:
		print clr.YEL
		print tool
		print clr.ENDC
		os.system(tool)
	
def run(tool):
	os.system(tool)
	while 1:
		x = raw_input(tool+"$ ")
		os.system('sudo '+tool+' '+x)

if __name__ == "__main__":
	try:
		if len(sys.argv) > 1: SPIKE=sys.argv[1]
		if SPIKE == '-spike_help':
			spike_commands()
		for tool in spike_list:
			if SPIKE == tool:
				try:
					run(tool)
				except KeyboardInterrupt:
					print '\n'
					pass
		if SPIKE == '-help':
			helps()
		if SPIKE == '-h':
			for tool in spike_list:
				if tool in sys.argv[2:]:
					print '\n'+clr.YEL +tool + ' Help'
					print clr.OKGREEN
					os.system(tool)
					print clr.ENDC
	except:
		helps()
	

