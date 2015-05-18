#!/usr/bin/env python

# Copyright 2014
#
# This file is part of FIWARE project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For those usages not covered by the Apache version 2.0 License please
# contact with opensource@tid.es
#
# Autor: Jose Ignacio Carretero Guarde.
#

#Documentacion:
###https://jon.oberheide.org/blog/2008/08/25/dpkt-tutorial-1-icmp-echo/
####https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/


# This script was quickly and "ugly" and it is shown to be wonderful. Sorry for
# the code of the Script, I'll do it better... someday

import dpkt, pcap
import sys
import datetime, time

from dpkt.udp import UDP
from dpkt.tcp import TCP
from dpkt.ip6 import IP6
from dpkt.arp import ARP


class InterestingData:
   def __init__(self, ip, level):
      self.level=level
      self.ip=ip
      self.n_tcp_bytes=0
      self.n_udp_bytes=0
      self.n_tcp_packets=0
      self.n_udp_packets=0
      self.n_tcp_syns=0

      self.ssh_packets=0
      self.ssh_bytes=0
      self.ssh_syns=0
      self.http_packets=0
      self.http_bytes=0
      self.http_syns=0
      self.https_packets=0
      self.https_bytes=0
      self.https_syns=0
      self.other_packets=0
      self.other_bytes=0
      self.other_syns=0
      self.dns_packets=0
      self.dns_bytes=0
      self.other_udp_bytes=0
      self.other_udp_packets=0

   def inc(self, sync, n_bytes, udp):
      if udp:
         self.n_udp_packets+=1
         self.n_udp_bytes+=n_bytes
      else:
         self.n_tcp_packets+=1
         self.n_tcp_bytes+=n_bytes
         self.n_tcp_syns+=sync

   def  inc_tcp(self, flags, n_bytes, src_port, dst_port):
      if (flags&2)==2:
         syns=1
      else:
         syns=0

      self.inc(syns, n_bytes, False)

 #     print "%d %d %d %d" % (flags, n_bytes, src_port, dst_port)
      if src_port==22 or dst_port==22:
         self.ssh_packets+=1
         self.ssh_bytes+=n_bytes
         self.ssh_syns+=syns
      elif src_port==80 or dst_port==80:
         self.http_packets+=1
         self.http_bytes+=n_bytes
         self.http_syns+=syns
      elif src_port==443 or dst_port==443:
         self.https_packets+=1
         self.https_bytes+=n_bytes
         self.https_syns+=syns
      else:
         self.other_packets+=1
         self.other_bytes+=n_bytes
         self.other_syns+=1

   def  inc_udp(self, flags, n_bytes, src_port, dst_port):
      self.inc(0, n_bytes, True)

      if src_port==53 or dst_port==53:
         self.dns_packets+=1
         self.dns_bytes+=n_bytes
      else:
         self.other_udp_bytes+=n_bytes
         self.other_udp_packets+=1

   def resume(self):
      if self.level>=1:
         print " ...[%15s] (tcp= %6d %10d %6d) (udp= %6d %10d)" % (self.ip,
            self.n_tcp_packets, self.n_tcp_bytes, self.n_tcp_syns,
            self.n_udp_packets, self.n_udp_bytes)
      if self.level>=2:
         print " ...TCP. 22 %5d %8d %5d ;   80 %5d %8d %5d ;  443 %5d %8d %5d ;  XX %5d %8d %5d ;" % (
            self.ssh_packets, self.ssh_bytes, self.ssh_syns,
            self.http_packets, self.http_bytes, self.http_syns,
            self.https_packets, self.https_bytes, self.https_syns,
            self.other_packets, self.other_bytes, self.other_syns
   	 )
         print " ...UDP. 53 %5d %8d  ;   XX %5d %8d " % (
            self.dns_packets, self.dns_bytes,
            self.other_udp_packets, self.other_udp_bytes
         	 )

class TotalData:
   def __init__(self, txt, level):
      self.level=level
      self.n_packets=0
      self.n_bytes=0
      self.n_udp=0
      self.n_tcp=0
      self.p_udp=0
      self.p_tcp=0
      self.txt=txt
      self.wheres={}

   def get_where(self, ip):
      if not ip in self.wheres:
          self.wheres[ip]=InterestingData(ip, self.level)
      return self.wheres[ip]

   def inc(self, flags, n_bytes, where):
      self.n_packets+=1
      self.n_bytes+=n_bytes

   def inc_udp(self, flags, n_bytes, where, src_port, dst_port ):
      self.p_udp+=1
      self.n_udp+=n_bytes
      self.inc(flags, n_bytes, where)
      ipdata=self.get_where(where)
      ipdata.inc_udp(flags, n_bytes, src_port, dst_port)
      
   def inc_tcp(self, flags, n_bytes, where, src_port, dst_port, ):
      self.p_tcp+=1
      self.n_tcp+=n_bytes
      self.inc(flags, n_bytes, where)
      ipdata=self.get_where(where)
      ipdata.inc_tcp(flags, n_bytes, src_port, dst_port)

   def explain_data(self, total, secs):
      for a in self.wheres:
         self.wheres[a].resume()

   def resume_data(self, total, secs):
      if total.n_packets>0:
         pnp=1.0*self.n_packets/total.n_packets
      else:
         pnp=-1
      if total.n_bytes:
         pnb=1.0*self.n_bytes/total.n_bytes
      else:
         pnb=-1
      kbps=self.n_bytes/(1000.0*secs)
      s="[%15s] %8d %12d %8.2f %8.2f %8d %12d %8d %12d %8.2f %4d" % (self.txt, self.n_packets, self.n_bytes,pnp,pnb,
           self.p_tcp, self.n_tcp, self.p_udp, self.n_udp, kbps, len(self.wheres))
      return s

class CaptureData:
   def __init__(self, interface, filter, level):
      self.level=level
      self.pc=pcap.pcap(interface)
      self.pc.setfilter(filter)
      self.tf=time.time()
      self.reset()
      print "End init..."

   def reset(self):
      self.hosts={}
      self.tos={}
      self.data=TotalData("TOTAL", self.level)
      self.n=0
      self.lng=0
      self.t0=self.tf

   def nip2str(self,ip):
       res="%d.%d.%d.%d" % (ord(ip[0]), ord(ip[1]), ord(ip[2]), ord(ip[3]))
       return res
   
   def recieved(self, ip, src, src_port, dst_port, flags, lng):
      pass

   def sent_tcp(self, ip, dst, src_port, dst_port, flags, lng):
      if not ip in self.tos:
          self.tos[ip]=TotalData(ip, self.level)
      self.tos[ip].inc_tcp(flags, lng, dst, src_port, dst_port)

   def sent_udp(self, ip, dst, src_port, dst_port, flags, lng):
      if not ip in self.tos:
          self.tos[ip]=TotalData(ip, self.level)
      self.tos[ip].inc_udp(flags, lng, dst,src_port, dst_port)

   def dump_ts(self):
      ts = time.time()
      self.tf=ts
      st = datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M%S')
      print "New Dump: ", (self.tf-self.t0), st
      self.dump()
   
   def dump(self):
       print "[%15s] %8s %12s %8s %8s %8s %12s %8s %12s" % ("IP", "Packets", "Bytes", "% Pckts",
             "%Bytes", "p_tcp", "n_tcp", "p_udp", "n_udp")
       secs= (self.tf-self.t0)
       s=sorted(self.tos.items(), key=lambda v: v[1].n_bytes)
       #for a in self.tos:
       for a in s:
          print a[1].resume_data(self.data, secs)
	  a[1].explain_data(self.data, secs)
       print self.data.resume_data(self.data, secs)
       self.reset()
       print "[%15s] %8s %12s %8s %8s %8s %12s %8s %12s %8s %4s" % ("IP", "Packets", "Bytes", "%Pckts",
             "%Bytes", "p_tcp", "n_tcp", "p_udp", "n_udp", "kbps", "wher")
   
   def captured_tcp(self, tcp):
      pass
       
   def capture(self):
       MASK=0b00010111
       print "Starting capture...."
       while True:
        try:
           for ts, pkt in self.pc:
               eth=dpkt.ethernet.Ethernet(pkt)
               ip=eth.data
               tcp_udp=ip.data
               
	       if type(ip)==IP6 or type(ip.data)==ARP:
	          continue

	       if type(ip.data)==TCP:
	          tcp=tcp_udp
		  src=self.nip2str(dpkt.ethernet.Ethernet(pkt).data.src)
		  dst=self.nip2str(dpkt.ethernet.Ethernet(pkt).data.dst)
                  
                  flags=tcp.flags&MASK
                  
                  self.data.inc_tcp(flags,ip.len, dst, tcp.sport, tcp.dport)
    	          self.sent_tcp(src, dst, tcp.sport, tcp.dport, flags, ip.len)
	       elif type(ip.data)==UDP:
                  udp=tcp_udp
                  src=self.nip2str(dpkt.ethernet.Ethernet(pkt).data.src)
                  dst=self.nip2str(dpkt.ethernet.Ethernet(pkt).data.dst)

                  flags=0
                 
                  self.data.inc_udp(flags, ip.len, dst, udp.sport, udp.dport)
    	          self.sent_udp(src, dst, udp.sport, udp.dport, flags, ip.len)
	       else:
	          continue
	       
               self.n+=1
	       self.lng+=ip.len

	       if self.n>100000:
	          self.dump_ts()
               # print "%s:%d ==> %s:%d (%d ; %d)" % (src,tcp.sport,dst,tcp.dport, ip.len, flags)
               #print `tcp`
        except KeyboardInterrupt:
	    #self.dump()
	    #self.dump_resumed()
	    self.dump_ts()

   def stop_caputre(self):
       pass

def uso():
   print '''
usage: caputre2.py <interface> <verbosity> <pcap_filter>

<interface>   ::= Device where you want to capture data
<verbosity>   ::= 0|1|2
                 0 - Prints from_IP stats
                 1 - Prints From IP stats and to IP stats
 	         2 - Prints from IP stats and to IP stats separated in UDP/TCP
<pcap_filter> ::= a libpcap valid filter -- An example migh be
    'not net 172.30.1.0/24 and not host 1.2.8.1 and not host 10.0.0.1'
'''

if __name__ == "__main__":
   if len(sys.argv)<3:
       uso()
       exit(1)
   program=sys.argv.pop(0)
   interface=sys.argv.pop(0)
   debug=int(sys.argv.pop(0))
   filter=' '.join([str(x) for x in sys.argv])

   x=CaptureData(interface, filter, debug)
   x.capture()
