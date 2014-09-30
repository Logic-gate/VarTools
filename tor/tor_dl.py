#!/usr/bin/env python


'''# tor_dl -- CLI downloader using TOR...P.S It's not wget'''

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

__author__ = ["A'mmer Almadani:Mad_Dev", "penbang.sysbase.org"]
__email__  = ["mad_dev@linuxmail.org", "mail@sysbase.org"]

import StringIO
import socket
import urllib2
import os
import socks  # SocksiPy module
import stem.process
import argparse
from stem.util import term
import re


def dl(url, path):
  
  name = url.split('/')[-1]
  ur = urllib2.urlopen(url)
  f = open(path+name, 'wb')
  data = ur.info()
  size = int(data.getheader("Content-Length"))
  _type = str(data.getheader("Content-Type"))
  print "Downloading: %s Type: %s Size: %s" % (name, _type, size)
  dl_size = 0
  block = 8192
  while True:
      buffer = ur.read(block)
      if not buffer:
          break
      dl_size += len(buffer)
      f.write(buffer)
      ##http://pastebin.com/DUEpBhXy Thanks for loading bar
      status = r"%10d  [%3.2f%%]" % (dl_size, dl_size * 100. / size)
      status = status + chr(8)*(len(status)+1)
      print status,
  f.close()
def print_bootstrap_lines(line):
  if "Bootstrapped " in line:
    print term.format(line, term.Color.BLUE)

def multi(l):
  if ',' in l:
    j = open('node.exit', 'w') # w | keep it clean
    f = re.split(',', l)
    for i in f:
      inclose = '{'+i+'},'
      j.write(inclose)
    j.close()

    jj = open('node.exit', 'r')
    inclose = jj.read()
    jj.close()
    return inclose

  else:
    inclose = '{' + l + '}'
    return inclose


if __name__=='__main__':

  par = argparse.ArgumentParser(prog='./tor_dl.py', formatter_class=argparse.ArgumentDefaultsHelpFormatter, 
    epilog="Example: tor_dl.py -url http://penbang.sysbase.org/other_projects/simple_xor.pdf -en ru,nz -xn us,ru")
  par.add_argument('-p',  required=False, default=7000, type=int, help="Socks Port", metavar='port')
  par.add_argument('-url', required=True, help="URL to download", metavar='url')
  par.add_argument('-xn', required=False, default='us', help="Only Accepts Country Codes", metavar='exit_node')
  par.add_argument('-en', required=False, default='ru', help="Only Accepts Country Codes ", metavar='entry_node')
  par.add_argument('-d', required=False, default= ' ', help="Download Destination", metavar='destination')
  argv = par.parse_args()

  port = argv.p
  url = argv.url
  exit = argv.xn
  entry = argv.en
  dest = argv.d

  if url:

    SOCKS_PORT = int(port)
    EXIT_NODE = multi(str(exit))
    ENTRY_NODE = multi(str(entry))

    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT)
    socket.socket = socks.socksocket
    print term.format("Starting Tor:\n", term.Attr.BOLD)

    tor_process = stem.process.launch_tor_with_config(
      config = {
        'SocksPort': str(SOCKS_PORT),
        'ExitNodes': str(EXIT_NODE),
        'EntryNodes': str(ENTRY_NODE),
      },
      init_msg_handler = print_bootstrap_lines,
    )
    dl(url, dest)
    print '\n' + term.format("Tor Stoped\n", term.Attr.BOLD)
    tor_process.kill()
