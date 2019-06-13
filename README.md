# linux-mclag
Experiments with MCLAG for Linux

## MC-LAG
MC-LAG or MLAG or Multi-chassis Link Aggregation Group - is a technology, that extends 
capabilities of standard IEEE 802.3ad Link Aggregation (LAG) protocol to enable a client
to form a logical LAG connection between two MC-LAG devices.

More details here: https://en.wikipedia.org/wiki/MC-LAG

## MC-LAG implementation for Linux
Unfortunately, no exising open-source implementation of MC-LAG is available for Linux.
However, recently MC-LAG feature was accepted to [SONiC](https://azure.github.io/SONiC/) [roadmap](https://github.com/Azure/SONiC/wiki/Sonic-Roadmap-Planning).

MC-LAG for SONiC was taken by Nephos team.

## MC-LAG for SONiC
MC-LAG feature is currently under development by Nephos team with the following progress already available:
- High-level design document: https://github.com/shine4chen/SONiC/blob/mclag/doc/Sonic-mclag-hld-v0.6.md
- iccpd code: https://github.com/shine4chen/sonic-buildimage/tree/master/src/iccpd 
- mlagsyncd code: https://github.com/shine4chen/sonic-swss/tree/mclagsyncd/mclagsyncd
- Multiple fixes in SONiC itself needed by MCLAG
- Pull Request to SONiC official repo: https://github.com/Azure/sonic-buildimage/pull/2514

### MC-LAG for SONiC architecture
MC-LAG feature for SONiC is based of two primary components:
- **iccpd** - a generic daemon implementing [ICCP](https://tools.ietf.org/html/rfc7275) protocol
- **mclagsyncd** - a glue layer implementing SONiC-specific APIs

### ICCPD
iccpd is implementing a [Lite version of ICCP protocol](https://github.com/shine4chen/SONiC/blob/mclag/doc/Sonic-mclag-hld-v0.6.md#51-use-cases-supported-by-iccp-lite) including:
- ICCP state machine
- Role election
- Synchronisation between peers
- Heartbeat and sonsistence checks

Also it **natively** communicates with standard Linux kernel networking stack using [rtnetlink](http://man7.org/linux/man-pages/man7/rtnetlink.7.html) in order to sync with underlying kernel interfaces and tables:
- Tracking interfaces state (bond/team/bridge status and enslavement)
- Syncing ARP table
- Isolating kernel BUM traffic using ebtables

ICCPD does not use or depend on any SONiC-related features or APIs. 
It talks only standard Linux API with Linux kernel and also communicates with **mclagsyncd** using custom protocol for syncing.

### mclagsyncd
This daemon implements a shim layer between generic ICCPD and SONiC APP_DB API to take care of specific actions, that can't be done with Linux kernel interfaces in SONiC:
- Flush FDB table
- Manage MAC learning on peerlink interface
- Sync and update MAC address table
- Isolate peerlink interface
- Set L3 interface MAC address
More information: https://github.com/shine4chen/SONiC/blob/mclag/doc/Sonic-mclag-hld-v0.6.md#92-add-mclagsyncd-process 

## MC-LAG for Linux
In order to support MC-LAG feature in Linux, original ICCPD implementation from SONiC can be used almost as is (with some minor changes).
To implement SONiC-specific interfaces in native Linux, mclagsyncd was rewritten to achieve the same functionality using Linux APIs.

### ICCPD
ICCPD code in this repo was taken from here: https://github.com/shine4chen/sonic-buildimage/tree/master/src/iccpd.
Also some minor changes were done to make it working on standard Linux (see commits).

### mclagsyncd.py
This is initial implementation of sync shim layer for ICCPD using standard Linux APIs. Currently it uses tools from **iproute2** package for this.
It implements the same custom protocol to communicate with ICCPD, as used by the original mclagsyncd for SONiC.

The following features are currently supported as part of **protocol version 1**:
- Flush FDB table
- Manage MAC learning on peerlink interface
- Sync and update MAC address table
- Isolate peerlink interface

### Tested OS
**ICCPD** with **mclagsyncd.py** were tested together on Debian Stretch VMs in a virtual environment.

### ToDo
- Prepare automated test setup for MC-LAG in Vagrant
- Prepare Dockerfiles to build and tun ICCPD and mclagsyncd.py
- Test MC-LAG on real HW switches running Linux with [switchdev](https://github.com/mellanox/mlxsw/wiki)

## Credits
- jianjun, grace Li from nephos
- https://github.com/shine4chen