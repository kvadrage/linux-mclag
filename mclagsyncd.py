#!/usr/bin/python
#
# MCLAG/ICCPD Sync backend for Linux
# 

import json
import ctypes
import logging
import itertools
import asyncore, socket
import subprocess
from collections import defaultdict

MLAG_SYNCD_HOST = "127.0.0.1"
MLAG_SYNCD_PORT = 2626

MCLAG_PROTO_VERSION = 1

MCLAG_MAX_MSG_LEN = 4096
MCLAG_MAX_SEND_MSG_LEN = 4096
MSG_BATCH_SIZE = 256

class CStruct(ctypes.Structure):
    @classmethod
    def from_bytes(cls, bytes):
        obj = cls()
        fit = min(len(bytes), ctypes.sizeof(obj))
        ctypes.memmove(ctypes.addressof(obj), bytes, fit)
        return obj

class mclag_msg_hdr_t_(CStruct):
    _fields_ = [("version", ctypes.c_uint8),
                ("msg_type", ctypes.c_uint8),
                ("msg_len", ctypes.c_uint16)]
MCLAG_MSG_HDR_LEN = ctypes.sizeof(mclag_msg_hdr_t_)

# syncd send msg type to iccpd
MCLAG_SYNCD_MSG_TYPE_NONE = 0
MCLAG_SYNCD_MSG_TYPE_FDB_OPERATION = 1

# iccpd send msg type to syncd
MCLAG_MSG_TYPE_NONE = 0
MCLAG_MSG_TYPE_PORT_ISOLATE = 1
MCLAG_MSG_TYPE_PORT_MAC_LEARN_MODE = 2
MCLAG_MSG_TYPE_FLUSH_FDB = 3
MCLAG_MSG_TYPE_SET_INTF_MAC = 4
MCLAG_MSG_TYPE_SET_FDB = 5
MCLAG_MSG_TYPE_FLUSH_FDB_BY_PORT = 6
MCLAG_MSG_TYPE_GET_FDB_CHANGES = 20

class mclag_sub_option_hdr_t_(CStruct):
    _fields_ = [("op_type", ctypes.c_uint8),
                ("op_len", ctypes.c_uint16)]
MCLAG_SUB_OPTION_HDR_LEN = ctypes.sizeof(mclag_sub_option_hdr_t_)

MCLAG_SUB_OPTION_TYPE_NONE = 0
MCLAG_SUB_OPTION_TYPE_ISOLATE_SRC = 1
MCLAG_SUB_OPTION_TYPE_ISOLATE_DST = 2
MCLAG_SUB_OPTION_TYPE_MAC_LEARN_ENABLE = 3
MCLAG_SUB_OPTION_TYPE_MAC_LEARN_DISABLE = 4
MCLAG_SUB_OPTION_TYPE_SET_MAC_SRC = 5
MCLAG_SUB_OPTION_TYPE_SET_MAC_DST = 6

class mclag_fdb_info(CStruct):
    _fields_ = [("mac", ctypes.c_char * 32),
                ("vid", ctypes.c_uint),
                ("port_name", ctypes.c_char * 32),
                ("type", ctypes.c_short), # dynamic or static
                ("op_type", ctypes.c_short)] # add or del
MCLAG_FDB_INFO_LEN = ctypes.sizeof(mclag_fdb_info)

MCLAG_FDB_OPER_ADD = 1
MCLAG_FDB_OPER_DEL = 2

MCLAG_FDB_TYPE_UNKNOWN = 0
MCLAG_FDB_TYPE_STATIC = 1
MCLAG_FDB_TYPE_DYNAMIC = 2

class FDBEntry(object):
    def __init__(self, mac, vid, port_name, fdb_type, master=None, extern_learn=False):
        self.mac = mac
        self.vid = vid
        self.port_name = port_name
        self.fdb_type = fdb_type
        self.master = master
        self.extern_learn = extern_learn
    
    def __str__(self):
        if self.fdb_type == MCLAG_FDB_TYPE_STATIC:
            fdb_type = "static"
        elif self.fdb_type == MCLAG_FDB_TYPE_DYNAMIC:
            fdb_type = "dynamic"
        else:
            fdb_type = "unknown"
        master = ", master:%s" % self.master if self.master else ""
        extern_learn = ", extern_learn" if self.extern_learn else ""
        return "%s (port_name:%s, vid:%d, type:%s%s%s)" % (self.mac, self.port_name, 
                                    self.vid, fdb_type, master, extern_learn)

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash((self.mac, self.vid, self.port_name, self.fdb_type, self.master, self.extern_learn))

    def __eq__(self, other):
        if isinstance(other, FDBEntry):
            return (self.mac, self.vid, self.port_name, self.fdb_type, self.master, self.extern_learn) == \
                    (self.mac, self.vid, self.port_name, self.fdb_type, self.master, self.extern_learn)
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

class FDBTable(defaultdict):
    def __init__(self, *args, **kwargs):
        super(FDBTable, self).__init__(*args, **kwargs)
        self.default_factory = set
    def dump(self):
        table = set()
        for group in self.values():
            table.update(group)
        return table

    def find(self, mac, vid=None, port_name=None, fdb_type=None, master=None, extern_learn=None):
        found = set()
        for fdb in self.dump():
            if fdb.mac != mac:
                continue
            if vid is not None and fdb.vid != vid:
                continue
            if port_name is not None and fdb.port_name != port_name:
                continue
            if fdb_type is not None and fdb.fdb_type != fdb_type:
                continue
            if master is not None and fdb.master != master:
                continue
            if extern_learn is not None and fdb.extern_learn != extern_learn:
                continue
            found.add(fdb)
        return found

    def remove(self, fdb):
        group = self.get(fdb.mac, None)
        if group:
            group.remove(fdb)
        if not group:
            self.pop(fdb.mac)


logger = logging.getLogger(__file__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def shell_cmd(command, log_error=True):
    logger.debug("Cmd: %s", command)
    try:
        out = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as e:
        if log_error: 
            logger.error("Cmd: %s, Error: %s", command, e)
        return None
    out_text = out.decode('utf-8')
    return out_text

def mclag_get_fdb_table():
    fdb_table = FDBTable()
    res = json.loads(shell_cmd("bridge -j -s fdb show"))
    for entry in res:
        # process only dynamic and static entries
        if not entry["state"] in ("", "static"):
            continue
        mac = entry["mac"]
        vid = int(entry.get("vid", "1"))
        port = entry["ifname"]
        if entry["state"] == "":
            fdb_type = MCLAG_FDB_TYPE_DYNAMIC
        elif entry["state"] == "static":
            fdb_type = MCLAG_FDB_TYPE_DYNAMIC
        else:
            fdb_type = MCLAG_FDB_TYPE_UNKNOWN
        master = entry["master"]
        extern_learn = "extern_learn" in entry["flags"]
        fdb = FDBEntry(mac, vid, port, fdb_type, master, extern_learn)
        fdb_table[mac].add(fdb)
    return fdb_table

def mclag_port_slaves(ports):
    slaves = []
    for port in ports:
        res = json.loads(shell_cmd("ip -j link show master %s" % port))
        slaves.extend([x["ifname"] for x in res])
    return slaves

def mclag_set_port_isolate(src_ports, dst_ports, remove=False):
    if not dst_ports:
        return
    # remove port isolation
    if remove:
        for dst in dst_ports:
            logger.debug("Remove port isolation from dst port: %s", dst)
            shell_cmd("tc filter del dev %s egress protocol all pref 1 flower" % dst)
        return
    # get all ports that already have clsact qdisc
    res = json.loads(shell_cmd("tc -j qdisc show"))
    has_clsact_qdisc = {x["dev"] for x in res if x["kind"] == "clsact"}
    # otherwise - add port isolation
    for src, dst in itertools.product(src_ports, dst_ports):
        if not dst in has_clsact_qdisc:
            shell_cmd("tc qdisc replace dev %s clsact" % dst)
        logger.debug("Set port isolation, src port: %s, dst port: %s", src, dst)
        shell_cmd("tc filter add dev %s egress protocol all pref 1 flower indev %s action drop" % (dst, src), log_error=False)
    # add LAG members to src port list as well       
    for src_slave, dst in itertools.product(mclag_port_slaves(src_ports), dst_ports):
        # if dst not in has_clsact_qdisc:
        #     shell_cmd("tc qdisc replace dev %s clsact" % dst)
        logger.debug("Set port isolation, src LAG member port: %s, dst port: %s", src_slave, dst)
        shell_cmd("tc filter add dev %s egress protocol all pref 1 flower indev %s action drop" % (dst, src_slave), log_error=False)

def mclag_set_port_mac_learn_mode(ports, learning_enabled):
    learning = "on" if learning_enabled else "off"
    for port in ports:
        logger.debug("Set port learning, port: %s, enabled: %s", port, learning_enabled)
        shell_cmd("ip link set dev %s type bridge_slave learning %s" % (port, learning))

def mclag_set_fdb_flush():
    logger.debug("FDB flush command")
    # flush dynamic FDB entries for all bridges in the system
    res = json.loads(shell_cmd("ip -j link show type bridge"))
    bridges = [x["ifname"] for x in res]
    for bridge in bridges:
        logger.debug("Running FDB flush for %s", bridge)
        shell_cmd("ip link set dev %s type bridge fdb_flush" % (bridge))

def mclag_set_fdb_flush_by_port(port):
    logger.debug("FDB flush by port %s", port)
    shell_cmd("ip link set dev %s type bridge_slave fdb_flush" % (port))

def mclag_set_intf_mac(intf_name, mac_addr):
    info_kind = ""
    info_slave_kind = ""
    logger.debug("Set interface mac address: intf=%s, mac=%s", intf_name, mac_addr)
    res = json.loads(shell_cmd("ip -j -d link sh %s" % (intf_name)))

    if res.get("linkinfo", None):
        info_kind = res["linkinfo"]
        info_slave_kind = res["info_slave_kind"]

    # intf is a portchannel enslaved to a bridge device (L2)
    if info_kind in ("team", "bond") and info_slave_kind == "bridge":
        # disable ipv6 link-local autoconfig
        if res.get("inet6_addr_gen_mode") != "none":
            shell_cmd("ip link set dev %s addrgenmode none" % (intf_name))
        # flush all IP addresses
        shell_cmd("ip addr flush dev %s" % (intf_name))
        shell_cmd("ip link set dev %s address %s" % (intf_name, mac_addr))
    else:
        logger.warning("Setting MAC address is not supported on %s (kind: %s, slave_kind: %s)", intf_name, info_kind, info_slave_kind)

def mclag_set_fdb_entry(fdb, delete=False):
    action = "del" if delete else "add"
    logger.debug("FDB entry %s: %s", action, fdb)
    action = "del" if delete else "replace"
    if fdb.fdb_type == MCLAG_FDB_TYPE_STATIC:
        fdb_type = "static"
    else:
        fdb_type = "dynamic"
    master = "master" if fdb.master else ""
    extern_learn = "extern_learn" if fdb.extern_learn else ""
    shell_cmd("bridge fdb %s %s dev %s %s %s %s vlan %d" % (
        action,
        fdb.mac,
        fdb.port_name,
        master,
        extern_learn,
        fdb_type,
        fdb.vid
        ))

class MCLAGSyncHandler(asyncore.dispatcher_with_send):
    def __init__(self, sock, map=None):
        asyncore.dispatcher_with_send.__init__(self, sock, map)
        self.read_buf_size = MCLAG_MAX_MSG_LEN * MSG_BATCH_SIZE
        self.write_buf_size = MCLAG_MAX_SEND_MSG_LEN
        self.old_fdb_table = FDBTable()
        self.isolated_ports = defaultdict(list)

    def handle_read(self):
        msg = self.recv(self.read_buf_size)
        if not msg:
            return
        logger.debug("Message received (%d): %s", len(msg), msg)
        self.mclag_process_msg(msg)
    
    def handle_close(self):
        logger.info("Client connection closed %s", self.addr)
        self.close()

    def mclag_decode_msg_hdr(self, msg):
        return mclag_msg_hdr_t_.from_bytes(msg)

    def mclag_msg_len(self, hdr):
        return hdr.msg_len

    def mclag_msg_data_len(self, hdr):
        return self.mclag_msg_len(hdr) - MCLAG_MSG_HDR_LEN


    def mclag_msg_hdr_ok (self, hdr):
        """Returns TRUE if a message header looks well-formed."""
        if (hdr.msg_type == MCLAG_MSG_TYPE_NONE):
            return False

        msg_len = self.mclag_msg_len(hdr)

        if (msg_len < MCLAG_MSG_HDR_LEN or msg_len > MCLAG_MAX_MSG_LEN):
            return False

        return True

    def mclag_msg_ok (self, hdr, len):
        """
        Returns TRUE if a message looks well-formed.
        @param len The length in bytes from 'hdr' to the end of the buffer.
        """
        if (len < MCLAG_MSG_HDR_LEN):
            return False

        if (not self.mclag_msg_hdr_ok(hdr)):
            return False

        if (self.mclag_msg_len(hdr) > len):
            return False

        return True

    def mclag_process_msg(self, msg):
        while msg:
            hdr = self.mclag_decode_msg_hdr(msg)
            logger.debug("Message version:%s, type:%s, len: %s", hdr.version, hdr.msg_type, hdr.msg_len)
            
            if hdr.version != MCLAG_PROTO_VERSION:
                logger.error("Unsupported protocol version: %d", hdr.version)
                return

            msg_len = self.mclag_msg_len(hdr)
            if not self.mclag_msg_ok(hdr, msg_len):
                logger.error("Bad message: %s", msg)
                return

            msg = msg[MCLAG_MSG_HDR_LEN:]

            if hdr.msg_type == MCLAG_MSG_TYPE_PORT_ISOLATE:
                msg = self.mclag_msg_port_isolate(msg)
            elif hdr.msg_type == MCLAG_MSG_TYPE_PORT_MAC_LEARN_MODE:
                msg = self.mclag_msg_port_mac_learn_mode(msg)
            elif hdr.msg_type == MCLAG_MSG_TYPE_FLUSH_FDB:
                self.mclag_msg_fdb_flush()
            elif hdr.msg_type == MCLAG_MSG_TYPE_FLUSH_FDB_BY_PORT:
                msg = self.mclag_msg_fdb_flush_by_port(msg)
            elif hdr.msg_type == MCLAG_MSG_TYPE_SET_INTF_MAC:
                msg = mclag_msg_intf_mac(msg)
            elif hdr.msg_type == MCLAG_MSG_TYPE_SET_FDB:
                msg = self.mclag_msg_set_fdb_entry(msg, msg_len-MCLAG_MSG_HDR_LEN)
            elif hdr.msg_type == MCLAG_MSG_TYPE_GET_FDB_CHANGES:
                self.mclag_msg_get_fdb_changes()
            else:
                logger.warning('Unknown message type: %d', hdr.msg_type)
                continue
        

    def mclag_msg_port_isolate(self, msg):
        # get isolate src port information
        op_hdr_src = mclag_sub_option_hdr_t_.from_bytes(msg)
        if op_hdr_src.op_type != MCLAG_SUB_OPTION_TYPE_ISOLATE_SRC:
            logger.debug("Invalid op header for MCLAG_SUB_OPTION_TYPE_ISOLATE_SRC: op_type=%d, op_len=%d", op_hdr_src.op_type, op_hdr_src.op_len)
            return None

        if op_hdr_src.op_len == 0:
            logger.debug("No source port data: op_type=%d, op_len=%d", op_hdr_src.op_type, op_hdr_src.op_len)
            return None
        
        msg = msg[MCLAG_SUB_OPTION_HDR_LEN:]
        src_ports = msg[:op_hdr_src.op_len].decode('utf-8').split(",")
        msg = msg[op_hdr_src.op_len:]

        # get isolate dst ports information
        op_hdr_dst = mclag_sub_option_hdr_t_.from_bytes(msg)
        if op_hdr_dst.op_type != MCLAG_SUB_OPTION_TYPE_ISOLATE_DST:
            logger.debug("Invalid op header for MCLAG_SUB_OPTION_TYPE_ISOLATE_DST: op_type=%d, op_len=%d", op_hdr_dst.op_type, op_hdr_dst.op_len)
            return None
        if op_hdr_dst.op_len == 0:
            logger.debug("No source port data: op_type=%d, op_len=%d", op_hdr_src.op_type, op_hdr_src.op_len)
            return None
        # If dst port is NULL, remove the isolation
        # dst_ports = self.isolated_ports.get(tuple(src_ports))
        # if dst_ports:
        #     mclag_set_port_isolate(src_ports, dst_ports, remove=True)
        #     self.isolated_ports.pop(tuple(src_ports))
        # return msg
        msg = msg[MCLAG_SUB_OPTION_HDR_LEN:]
        dst_ports = msg[:op_hdr_dst.op_len].decode('utf-8').split(",")
        dst_add_ports = [ port for port in dst_ports if port[0] != '!'] 
        dst_del_ports = [ port[1:] for port in dst_ports if port[0] == '!'] 
        #self.isolated_ports[tuple(src_ports)] = dst_ports
        mclag_set_port_isolate(src_ports, dst_add_ports)
        mclag_set_port_isolate(src_ports, dst_del_ports, remove=True)
        return msg[op_hdr_dst.op_len:]

    def mclag_msg_port_mac_learn_mode(self, msg):
        # get port information
        op_hdr = mclag_sub_option_hdr_t_.from_bytes(msg)
        learning_enabled = (op_hdr.op_type == MCLAG_SUB_OPTION_TYPE_MAC_LEARN_ENABLE)
        if op_hdr.op_len == 0:
            logger.debug("No port data: op_type=%d, op_len=%d", op_hdr.op_type, op_hdr.op_len)
            return None
        msg = msg[MCLAG_SUB_OPTION_HDR_LEN:]
        ports = msg[:op_hdr.op_len].decode('utf-8').split(",")
        mclag_set_port_mac_learn_mode(ports, learning_enabled)
        return msg[op_hdr.op_len:]

    def mclag_msg_fdb_flush_by_port(self, msg):
        # get port information
        op_hdr = mclag_sub_option_hdr_t_.from_bytes(msg)
        if op_hdr.op_len == 0:
            logger.debug("No port data: op_type=%d, op_len=%d", op_hdr.op_type, op_hdr.op_len)
            return None
        msg = msg[MCLAG_SUB_OPTION_HDR_LEN:]
        port = msg[:op_hdr.op_len].decode('utf-8')
        mclag_set_fdb_flush_by_port(port)
        return msg[op_hdr.op_len:]

    def mclag_msg_intf_mac(self, msg):
        # get interface name
        op_hdr_intf = mclag_sub_option_hdr_t_.from_bytes(msg)
        if op_hdr_intf.op_len == 0:
            logger.debug("No interface name data: op_type=%d, op_len=%d", op_hdr_intf.op_type, op_hdr_intf.op_len)
            return None
        msg = msg[MCLAG_SUB_OPTION_HDR_LEN:]
        intf_name = msg[:op_hdr_intf.op_len].decode('utf-8')
        msg = msg[op_hdr_intf.op_len:]

        # get mac address
        op_hdr_mac = mclag_sub_option_hdr_t_.from_bytes(msg)
        msg = msg[MCLAG_SUB_OPTION_HDR_LEN:]
        if op_hdr_intf.op_len == 0:
            logger.debug("No mac address data: op_type=%d, op_len=%d", op_hdr_mac.op_type, op_hdr_mac.op_len)
            return None
        mac_addr = msg[:op_hdr_mac.op_len].decode('utf-8')
        mclag_set_intf_mac(intf_name, mac_addr)
        return msg[op_hdr_mac.op_len:]

    def mclag_msg_fdb_flush(self):
        mclag_set_fdb_flush()

    def mclag_msg_get_fdb_changes(self):
        send_buf = bytearray()
        send_msg_len = 0
        new_fdb_table = mclag_get_fdb_table()
        new_fdb_table_dump = new_fdb_table.dump()
        old_fdb_table_dump = self.old_fdb_table.dump()

        add_fdb = new_fdb_table_dump - old_fdb_table_dump
        del_fdb = old_fdb_table_dump - new_fdb_table_dump
        self.old_fdb_table = new_fdb_table

        for fdb in del_fdb:
            if (MCLAG_MAX_SEND_MSG_LEN - MCLAG_MSG_HDR_LEN - len(send_buf) < MCLAG_FDB_INFO_LEN):
                # send complete message
                msg_head = mclag_msg_hdr_t_()
                msg_head.version = 1
                msg_head.msg_len = send_msg_len + MCLAG_MSG_HDR_LEN
                msg_head.msg_type = MCLAG_SYNCD_MSG_TYPE_FDB_OPERATION
                send_buf = bytes(msg_head) + send_buf
                logger.debug("Deleted FDB entries")
                self.send(send_buf)
                send_msg_len = 0
                send_buf = bytearray()
            fdb_info = mclag_fdb_info()
            fdb_info.mac = fdb.mac.encode("utf-8")
            fdb_info.vid = ctypes.c_uint(fdb.vid)
            fdb_info.port_name = fdb.port_name.encode("utf-8")
            fdb_info.type = ctypes.c_short(fdb.fdb_type)
            fdb_info.op_type = MCLAG_FDB_OPER_DEL
            send_buf += bytes(fdb_info)
            send_msg_len += MCLAG_FDB_INFO_LEN
            

        for fdb in add_fdb:
            if (MCLAG_MAX_SEND_MSG_LEN - MCLAG_MSG_HDR_LEN - len(send_buf) < MCLAG_FDB_INFO_LEN):
                # send complete message
                msg_head = mclag_msg_hdr_t_()
                msg_head.version = 1
                msg_head.msg_len = send_msg_len + MCLAG_MSG_HDR_LEN
                msg_head.msg_type = MCLAG_SYNCD_MSG_TYPE_FDB_OPERATION
                send_buf = bytes(msg_head) + send_buf
                logger.debug("New FDB entries")
                self.send(send_buf)
                send_msg_len = 0
                send_buf = bytearray()
            fdb_info = mclag_fdb_info()
            fdb_info.mac = fdb.mac.encode("utf-8")
            fdb_info.vid = ctypes.c_uint(fdb.vid)
            fdb_info.port_name = fdb.port_name.encode("utf-8")
            fdb_info.type = ctypes.c_short(fdb.fdb_type)
            fdb_info.op_type = MCLAG_FDB_OPER_ADD
            send_buf += bytes(fdb_info)
            send_msg_len += MCLAG_FDB_INFO_LEN
                  

        if len(send_buf) == 0: #no fdb entry need notifying iccpd*/ 
            return 1

        msg_head = mclag_msg_hdr_t_()
        msg_head.version = 1
        msg_head.msg_len = send_msg_len + MCLAG_MSG_HDR_LEN
        msg_head.msg_type = MCLAG_SYNCD_MSG_TYPE_FDB_OPERATION 
        send_buf = bytes(msg_head) + send_buf       
        logger.debug("All FDB entries")
        self.send(send_buf)
        return

    def mclag_msg_set_fdb_entry(self, msg, msg_len):
        fdb_msg = msg[:msg_len]
        msg = msg[msg_len:]
        while fdb_msg:
            fdb_info = mclag_fdb_info.from_bytes(fdb_msg[:MCLAG_FDB_INFO_LEN])
            fdb_msg = fdb_msg[MCLAG_FDB_INFO_LEN:]
            mac = fdb_info.mac.decode("utf-8")
            vid = fdb_info.vid
            port_name = fdb_info.port_name.decode("utf-8")
            fdb_type = fdb_info.type
            fdb = FDBEntry(mac, vid, port_name, fdb_type, master="unknown", extern_learn=False)

            if fdb_info.op_type == MCLAG_FDB_OPER_ADD:
                exist = self.old_fdb_table.find(fdb)
                if exist:
                    for old in exist:
                        self.old_fdb_table.remove(old)
                self.old_fdb_table[mac].add(fdb)
                mclag_set_fdb_entry(fdb)
            elif fdb_info.op_type == MCLAG_FDB_OPER_DEL:
                exist = self.old_fdb_table.find(fdb)
                if exist:
                    for old in exist:
                        self.old_fdb_table.remove(old)
                else:
                    logger.debug("Non-existent FDB entry in local cache to remove: %s", fdb)   
                mclag_set_fdb_entry(fdb, delete=True)             
            else:
                logger.debug("Unknown FDB operation: %d", fdb_info.op_type)
        return msg

class MCLAGSyncServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(1)
        logger.info('Listening on %s:%s', host, port)

    def handle_accept(self):
        socket, address = self.accept()
        logger.info("Client connected %s", address)
        MCLAGSyncHandler(socket)


if __name__ == "__main__":
    serv = MCLAGSyncServer(MLAG_SYNCD_HOST, MLAG_SYNCD_PORT)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        serv.close()