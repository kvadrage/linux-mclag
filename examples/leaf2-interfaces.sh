#!/bin/bash

# bridge
ip link add name bridge type bridge vlan_filtering 1 mcast_snooping 0

# Make sure the bridge uses the MAC address of the local port and not
# that of the VXLAN's device
ip link set dev bridge address 7c:fe:91:fd:ce:51
ip link set dev bridge up

# peerlink
teamd -t peerlink -d -c '{"runner": {"name": "lacp"}}'
ip link set dev swp16 master peerlink
ip link set dev peerlink master bridge
ip link set dev peerlink up
ip link add link peerlink name peerlink.4094 up type vlan id 4000
ip addr add 169.254.1.2/30 dev peerlink.4094

# server1
teamd -t server1 -d -c '{"runner": {"name": "lacp", "hwaddr_policy":"no_change", "system_id":"44:38:39:ff:00:01"}}'
ip link set dev swp1 master server1
sleep 1
ip link set dev server1 master bridge
ip link set dev server1 up

# server2
teamd -t server2 -d -c '{"runner": {"name": "lacp", "hwaddr_policy":"no_change", "system_id":"44:38:39:ff:00:02"}}'
ip link set dev swp2 master server2
sleep 1
ip link set dev server2 master bridge
ip link set dev server2 up

# SVI
ip address add 10.1.1.253/24 dev bridge
ip link add link bridge name bridge-v up address 00:00:5e:00:01:01 type macvlan mode private
ip address add 10.1.2.1/24 dev bridge-v metric 1024
bridge fdb add 00:00:5e:00:01:01 dev bridge self local

# Disable rp_filter and enable arp_ignore to make sure ARPs for the
# anycast IP are answered with the anycast MAC
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.bridge-v.rp_filter=0
sysctl -w net.ipv4.conf.all.arp_ignore=1