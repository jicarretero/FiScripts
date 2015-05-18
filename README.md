# FiScripts
I'll drop here some useful scripts to do things.

Before running some of the Scripts, you must set the openstack variables, or exec your own "keystonerc" file:

    export OS_AUTH_URL=xxx
    export OS_USERNAME=xxx
    export OS_PASSWORD=xxx
    export OS_TENANT_NAME=xxx
    export OS_REGION_NAME=xxx


vview
------
This script needs the Openstack environment variables set, it's only purpose is to connect to the remote virtual host:
     view <vm_id>

It only works in linux :(

capture2.py
------------
Usefull script detailing the traffic every some packets --- Sorry for the crappy code, it was done quickly as a proof
of concept... but it was so useful. Someday I'll rewrite it.

    usage: caputre2.py <interface> <verbosity> <pcap_filter>
    
    <interface>   ::= Device where you want to capture data
    <verbosity>   ::= 0|1|2
        0 - Prints from_IP stats
        1 - Prints From IP stats and to IP stats
        2 - Prints from IP stats and to IP stats separated in UDP/TCP
            <pcap_filter> ::= a libpcap valid filter -- An example migh be
            'not net 172.30.1.0/24 and not host 1.2.8.1 and not host 10.0.0.1'

