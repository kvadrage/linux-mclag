/*
* iccp_ifm.c
*
* Copyright(c) 2016-2019 Nephos/Estinet.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*
* You should have received a copy of the GNU General Public License along with
* this program; if not, see <http://www.gnu.org/licenses/>.
*
* The full GNU General Public License is included in this distribution in
* the file called "COPYING".
*
*  Maintainer: jianjun, grace Li from nephos
*/

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>

#include "../include/system.h"
#include "../include/iccp_cli.h"
#include "../include/logger.h"
#include "../include/mlacp_sync_update.h"
#include "../include/mlacp_link_handler.h"
#include "../include/port.h"
#include "../include/iccp_netlink.h"

#define fwd_neigh_state_valid(state) (state & (NUD_REACHABLE|NUD_STALE|NUD_DELAY|NUD_PROBE|NUD_PERMANENT))

#ifndef MAX_BUFSIZE
    #define MAX_BUFSIZE 4096
#endif

#ifndef NDA_RTA
#define NDA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

static int iccp_valid_handler(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    unsigned int event = 0;
    if (nlh->nlmsg_type != RTM_NEWLINK)
    	return 0;
    
    if (nl_msg_parse(msg, &iccp_event_handler_obj_input_newlink, &event) < 0)
    	ICCPD_LOG_ERR(__FUNCTION__, "Unknown message type.");
    	
    return 0;
}

/*Get kernel interfaces and ports during initialization*/
int iccp_sys_local_if_list_get_init()
{
    struct System *sys = NULL;
    struct nl_cb *cb;
    struct nl_cb *orig_cb;
    struct rtgenmsg rt_hdr = {
        .rtgen_family = AF_UNSPEC,
    };
    int ret;
    int retry = 1;
    
    if (!(sys = system_get_instance()))
    return -1;
    
    while (retry) 
    {
        retry = 0;
        ret = nl_send_simple(sys->route_sock, RTM_GETLINK, NLM_F_DUMP,
                                           &rt_hdr, sizeof(rt_hdr));
        if (ret < 0) 
        {
            ICCPD_LOG_ERR(__FUNCTION__, "send netlink msg error.");
            return ret;
        }
        
        orig_cb = nl_socket_get_cb(sys->route_sock);
        cb = nl_cb_clone(orig_cb);
        nl_cb_put(orig_cb);
        if (!cb) 
        {
            ICCPD_LOG_ERR(__FUNCTION__, "nl cb clone error.");
            return -ENOMEM;
        }
        
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, iccp_valid_handler, sys);
        
        ret = nl_recvmsgs(sys->route_sock, cb);
        nl_cb_put(cb);
        if (ret < 0) 
        {
            ICCPD_LOG_ERR(__FUNCTION__, "receive netlink msg error. ret = %d  errno = %d ",ret, errno);
            if (ret != -NLE_DUMP_INTR)
                return ret;
            retry = 1;
        }
    }
    
    return ret;
}

/*Handle arp received from kernel*/
static int iccp_arp_valid_handler(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    
    do_one_neigh_request(nlh);
    
    return 0;
}

/*Get kernel arp information during initialization*/
int iccp_arp_get_init()
{
    struct System *sys = NULL;
    struct nl_cb *cb;
    struct nl_cb *orig_cb;
    struct rtgenmsg rt_hdr = {
    	.rtgen_family = AF_UNSPEC,
    };
    int ret;
    int retry = 1;
    
    if (!(sys = system_get_instance()))
        return -1;
    
    while (retry) 
    {
        retry = 0;
        ret = nl_send_simple(sys->route_sock, RTM_GETNEIGH, NLM_F_DUMP,
        &rt_hdr, sizeof(rt_hdr));
        if (ret < 0) 
        {
            ICCPD_LOG_ERR(__FUNCTION__, "send netlink msg error.");
            return ret;
        }
        
        orig_cb = nl_socket_get_cb(sys->route_sock);
        cb = nl_cb_clone(orig_cb);
        nl_cb_put(orig_cb);
        if (!cb) 
        {
            ICCPD_LOG_ERR(__FUNCTION__, "nl cb clone error.");
            return -ENOMEM;
        }
        
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, iccp_arp_valid_handler, sys);
        
        ret = nl_recvmsgs(sys->route_sock, cb);
        nl_cb_put(cb);
        if (ret < 0) 
        {
            ICCPD_LOG_ERR(__FUNCTION__, "receive netlink msg error.");
            if (ret != -NLE_DUMP_INTR)
                return ret;
                
            retry = 1;
        }
    }

    return ret;
}

/*When received ARP packets from kernel, update arp information*/
void do_arp_update (unsigned int ifindex, unsigned int addr, uint8_t mac_addr[ETHER_ADDR_LEN])
{
    struct System *sys = NULL;
    struct CSM *csm = NULL;
    struct Msg *msg = NULL;
    struct ARPMsg *arp_msg = NULL, *arp_info = NULL;
    struct VLAN_ID *vlan_id_list = NULL;
    struct Msg *msg_send = NULL;
    
    char buf[MAX_BUFSIZE];
    size_t msg_len = 0;
    
    struct LocalInterface *lif_po = NULL, *arp_lif = NULL;
    uint8_t mac[ETHER_ADDR_LEN];
    
    struct in_addr in_addr;
    int verify_arp = 0;
    int arp_update = 0;
    
    if (!(sys = system_get_instance()))
        return;
    
    /* Find local itf*/
    if (!(arp_lif = local_if_find_by_ifindex(ifindex)))
        return;
    
    /* create ARP msg*/
    memset(buf, 0, MAX_BUFSIZE);
    msg_len = sizeof(struct ARPMsg);
    arp_msg = (struct ARPMsg*) &buf;
    arp_msg->op_type = ARP_SYNC_LIF;
    sprintf(arp_msg->ifname, "%s", arp_lif->name);
    memcpy(&arp_msg->ipv4_addr, &addr, 4);
    memcpy(arp_msg->mac_addr, mac_addr, 6);

    /*Debug*/
    #if 1
    /* dump receive kernel ARP req*/
    fprintf(stderr, "\n======== Kernel ARP Update==========\n");
    fprintf(stderr, "  Type    = (New=%d)\n", RTM_NEWNEIGH);
    fprintf(stderr, "  ifindex = [%d] (%s)\n", ifindex, arp_lif->name);
    fprintf(stderr, "  IP      = [%s]\n", show_ip_str(arp_msg->ipv4_addr));
    fprintf(stderr, "  MAC     = [%02X:%02X:%02X:%02X:%02X:%02X]\n",
            arp_msg->mac_addr[0],arp_msg->mac_addr[1],arp_msg->mac_addr[2],arp_msg->mac_addr[3],
            arp_msg->mac_addr[4],arp_msg->mac_addr[5]);
    fprintf(stderr, "==============================\n");
    #endif
    
    /* Find MLACP itf, member of port-channel*/
    LIST_FOREACH(csm, &(sys->csm_list), next)
    {
        LIST_FOREACH(lif_po, &(MLACP(csm).lif_list), mlacp_next)
        {
            if (lif_po->type != IF_T_PORT_CHANNEL)
                continue;
            
            if (!local_if_is_l3_mode(lif_po)) 
            {
                /* Is the L2 MLAG itf belong to a vlan?*/
                LIST_FOREACH(vlan_id_list, &(lif_po->vlan_list), port_next)
                {
                    if ( !(vlan_id_list->vlan_itf
                        && vlan_id_list->vlan_itf->ifindex == ifindex))
                        continue;
                    break;
                }
                
                if (!vlan_id_list) continue;
                ICCPD_LOG_DEBUG(__FUNCTION__, "ARP is from itf (%s) of vlan (%s)", 
                                lif_po->name, vlan_id_list->vlan_itf->name);
            }
            else 
            {
                /* Is the ARP belong to a L3 mode MLAG itf?*/
                if (ifindex != lif_po->ifindex) continue;
                ICCPD_LOG_DEBUG(__FUNCTION__, "ARP is from itf (%s)",
                                lif_po->name);
            }
            
            verify_arp = 1;
            
            break;
        }
        
        if (lif_po) break;
    }
    
    if (!(csm && lif_po)) return;
    if (!verify_arp) return;
        
    /* update lif ARP*/
    TAILQ_FOREACH(msg, &MLACP(csm).arp_list, tail)
    {
        arp_info = (struct ARPMsg*) msg->buf;
        if (arp_info->ipv4_addr != arp_msg->ipv4_addr)
            continue;
        
        /* update ARP*/
        if(arp_info->op_type != arp_msg->op_type
            || strcmp(arp_info->ifname, arp_msg->ifname)!=0
            || strncmp(arp_info->mac_addr, arp_msg->mac_addr,
                        ETHER_ADDR_LEN) != 0)
        {
            arp_update = 1;
            arp_info->op_type = arp_msg->op_type;
            sprintf(arp_info->ifname, "%s", arp_msg->ifname);
            memcpy(arp_info->mac_addr, arp_msg->mac_addr, ETHER_ADDR_LEN);
            ICCPD_LOG_DEBUG(__FUNCTION__, "Update ARP for %s",
                            show_ip_str(arp_msg->ipv4_addr));
        }
        time(&arp_info->update_time);
        
        break;
    }
    
    /* enquene lif_msg (add)*/
    if (!msg) 
    {
        arp_msg->op_type = ARP_SYNC_LIF;
        if (iccp_csm_init_msg(&msg, (char*)arp_msg, msg_len)==0) 
        {
            mlacp_enqueue_arp(csm, msg);
            ICCPD_LOG_DEBUG(__FUNCTION__, "ARP-list enqueue: %s, add %s", 
                            arp_msg->ifname,
                            show_ip_str(arp_msg->ipv4_addr));
        }
        else
            ICCPD_LOG_DEBUG(__FUNCTION__, "Failed to enqueue ARP-list: %s, add %s", 
                            arp_msg->ifname,
                            show_ip_str(arp_msg->ipv4_addr));
    }
    
    /* enqueue iccp_msg (add)*/
    if (MLACP(csm).current_state == MLACP_STATE_EXCHANGE) 
    {
        arp_msg->op_type = ARP_SYNC_ADD;
        if (iccp_csm_init_msg(&msg_send, (char*)arp_msg, msg_len) == 0) 
        {
            TAILQ_INSERT_TAIL(&(MLACP(csm).arp_msg_list), msg_send, tail);
            ICCPD_LOG_DEBUG(__FUNCTION__, "Enqueue ARP[ADD] for %s",
                            show_ip_str(arp_msg->ipv4_addr));
        }
        else 
            ICCPD_LOG_DEBUG(__FUNCTION__, "Failed to enqueue ARP[ADD] for %s",
                            show_ip_str(arp_msg->ipv4_addr));
    }
    
    return;
}

static void do_arp_request (struct ndmsg *ndm, struct rtattr *tb[], int msgtype)
{
    struct System *sys = NULL;
    struct CSM *csm = NULL;
    struct Msg *msg = NULL;
    struct ARPMsg *arp_msg = NULL, *arp_info = NULL;
    struct VLAN_ID *vlan_id_list = NULL;
    struct Msg *msg_send = NULL;
    
    char buf[MAX_BUFSIZE];
    size_t msg_len = 0;
    
    struct LocalInterface *lif_po = NULL, *arp_lif = NULL;
    uint8_t mac[ETHER_ADDR_LEN];
    
    int verify_arp = 0;
    int arp_update = 0;
    
    if (!(sys = system_get_instance()))
        return;
    
    /* Find local itf*/
    if (!(arp_lif = local_if_find_by_ifindex(ndm->ndm_ifindex)))
        return;
    
    /* create ARP msg*/
    memset(buf, 0, MAX_BUFSIZE);
    msg_len = sizeof(struct ARPMsg);
    arp_msg = (struct ARPMsg*) &buf;
    arp_msg->op_type = ARP_SYNC_LIF;
    sprintf(arp_msg->ifname, "%s", arp_lif->name);
    if(tb[NDA_DST])
        memcpy(&arp_msg->ipv4_addr, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));
    if (tb[NDA_LLADDR])
        memcpy(arp_msg->mac_addr, RTA_DATA(tb[NDA_LLADDR]), RTA_PAYLOAD(tb[NDA_LLADDR]));

        
    ICCPD_LOG_DEBUG(__FUNCTION__, "arp msg type %d , state  (%04X)(%d)  ifindex   [%d] (%s) ip %s  , mac   [%02X:%02X:%02X:%02X:%02X:%02X] ",
                                      msgtype, ndm->ndm_state, fwd_neigh_state_valid(ndm->ndm_state),
                                      ndm->ndm_ifindex, arp_lif->name,
                                      show_ip_str(arp_msg->ipv4_addr),
                                      arp_msg->mac_addr[0],arp_msg->mac_addr[1],arp_msg->mac_addr[2],arp_msg->mac_addr[3],arp_msg->mac_addr[4],arp_msg->mac_addr[5]);    

    /*Debug*/
    #if 1
    /* dump receive kernel ARP req*/
    fprintf(stderr, "\n======== Kernel ARP ==========\n");
    fprintf(stderr, "  Type    = [%d] (New=%d, Del=%d)\n", msgtype, RTM_NEWNEIGH, RTM_DELNEIGH);
    fprintf(stderr, "  State   = (%04X)(%d)\n", ndm->ndm_state, fwd_neigh_state_valid(ndm->ndm_state));
    fprintf(stderr, "  ifindex = [%d] (%s)\n", ndm->ndm_ifindex, arp_msg->ifname);
    fprintf(stderr, "  IP      = [%s]\n", show_ip_str(arp_msg->ipv4_addr));
    fprintf(stderr, "  MAC     = [%02X:%02X:%02X:%02X:%02X:%02X]\n",
            arp_msg->mac_addr[0],arp_msg->mac_addr[1],arp_msg->mac_addr[2],arp_msg->mac_addr[3],
            arp_msg->mac_addr[4],arp_msg->mac_addr[5]);
    fprintf(stderr, "==============================\n");
    #endif
    
    /* Find MLACP itf, member of port-channel*/
    LIST_FOREACH(csm, &(sys->csm_list), next)
    {
        LIST_FOREACH(lif_po, &(MLACP(csm).lif_list), mlacp_next)
        {
            if (lif_po->type != IF_T_PORT_CHANNEL)
                continue;
            
            if (!local_if_is_l3_mode(lif_po)) 
            {
                /* Is the L2 MLAG itf belong to a vlan?*/
                LIST_FOREACH(vlan_id_list, &(lif_po->vlan_list), port_next)
                {
                    if ( !(vlan_id_list->vlan_itf
                        && vlan_id_list->vlan_itf->ifindex == ndm->ndm_ifindex))
                        continue;
                    break;
                }
                
                if (!vlan_id_list) continue;
                
                ICCPD_LOG_DEBUG(__FUNCTION__, "ARP is from itf (%s) of vlan (%s)", 
                                lif_po->name, vlan_id_list->vlan_itf->name);
            }
            else 
            {
                /* Is the ARP belong to a L3 mode MLAG itf?*/
                if (ndm->ndm_ifindex != lif_po->ifindex) continue;
                
                ICCPD_LOG_DEBUG(__FUNCTION__, "ARP is from itf (%s)",
                                lif_po->name);
            }
            
            verify_arp = 1;
            
            break;
        }
        
        if (lif_po) break;
    }
    
    if (!(csm && lif_po)) return;
    if (!verify_arp) return;
        
    /* update lif ARP*/
    TAILQ_FOREACH(msg, &MLACP(csm).arp_list, tail)
    {
        arp_info = (struct ARPMsg*) msg->buf;
        if (arp_info->ipv4_addr != arp_msg->ipv4_addr)
            continue;
        
        if (msgtype == RTM_DELNEIGH) 
        {
            /* delete ARP*/
            TAILQ_REMOVE(&MLACP(csm).arp_list, msg, tail);
            free(msg->buf); free(msg); msg = NULL;
            ICCPD_LOG_DEBUG(__FUNCTION__, "Delete ARP %s",
                            show_ip_str(arp_msg->ipv4_addr));
        }
        else 
        {
            /* update ARP*/
            if(arp_info->op_type != arp_msg->op_type
                || strcmp(arp_info->ifname, arp_msg->ifname)!=0
                || strncmp(arp_info->mac_addr, arp_msg->mac_addr,
                            ETHER_ADDR_LEN) != 0)
            {
                arp_update = 1;
                arp_info->op_type = arp_msg->op_type;
                sprintf(arp_info->ifname, "%s", arp_msg->ifname);
                memcpy(arp_info->mac_addr, arp_msg->mac_addr, ETHER_ADDR_LEN);
                ICCPD_LOG_DEBUG(__FUNCTION__, "Update ARP for %s",
                                show_ip_str(arp_msg->ipv4_addr));
            }
            time(&arp_info->update_time);
        }
        break;
    }
    
    if (msg && !arp_update)
        return;
    
    if (msgtype != RTM_DELNEIGH) 
    {
        /* enquene lif_msg (add)*/
        if (!msg) 
        {
            arp_msg->op_type = ARP_SYNC_LIF;
            if (iccp_csm_init_msg(&msg, (char*)arp_msg, msg_len)==0) 
            {
                mlacp_enqueue_arp(csm, msg);
                ICCPD_LOG_DEBUG(__FUNCTION__, "ARP-list enqueue: %s, add %s", 
                                arp_msg->ifname,
                                show_ip_str(arp_msg->ipv4_addr));
            }
            else
                ICCPD_LOG_DEBUG(__FUNCTION__, "Failed to enqueue ARP-list: %s, add %s", 
                                arp_msg->ifname,
                                show_ip_str(arp_msg->ipv4_addr));
        }
        
        /* enqueue iccp_msg (add)*/
        if (MLACP(csm).current_state == MLACP_STATE_EXCHANGE) 
        {
            arp_msg->op_type = ARP_SYNC_ADD;
            if (iccp_csm_init_msg(&msg_send, (char*)arp_msg, msg_len) == 0) 
            {
                TAILQ_INSERT_TAIL(&(MLACP(csm).arp_msg_list), msg_send, tail);
                ICCPD_LOG_DEBUG(__FUNCTION__, "Enqueue ARP[ADD] for %s",
                                show_ip_str(arp_msg->ipv4_addr));
            }
            else 
                ICCPD_LOG_DEBUG(__FUNCTION__, "Failed to enqueue ARP[ADD] for %s",
                                show_ip_str(arp_msg->ipv4_addr));
            
        }
    }
    else 
    {
        /* enqueue iccp_msg (delete)*/
        if (MLACP(csm).current_state == MLACP_STATE_EXCHANGE) 
        {
            arp_msg->op_type = ARP_SYNC_DEL;
            if (iccp_csm_init_msg(&msg_send, (char*)arp_msg, msg_len) == 0) 
            {
                TAILQ_INSERT_TAIL(&(MLACP(csm).arp_msg_list), msg_send, tail);
                ICCPD_LOG_DEBUG(__FUNCTION__, "Enqueue ARP[DEL] for %s",
                                show_ip_str(arp_msg->ipv4_addr));
            }
            else
                ICCPD_LOG_DEBUG(__FUNCTION__, "Failed to enqueue ARP[DEL] for %s",
                                show_ip_str(arp_msg->ipv4_addr));
                
        }
    }
    
    /*Debug: dump for dequeue ARP Info*/
    #if 1
    fprintf(stderr, "\n======== ARP Info List ========\n");
    TAILQ_FOREACH(msg, &MLACP(csm).arp_list, tail)
    {
        arp_msg = (struct ARPMsg*) msg->buf;
        fprintf(stderr, "type %d,ifname %s , ip %s\n", arp_msg->op_type, arp_msg->ifname, show_ip_str(arp_msg->ipv4_addr));
    }
    fprintf(stderr, "==============================\n");
    #endif
    
    /*TEST dump for dequeue ARP message*/
    #if 0
    while (MLACP(csm).arp_updated && !TAILQ_EMPTY(&(MLACP(csm).arp_msg_list)))
    {
        msg = TAILQ_FIRST(&(MLACP(csm).arp_msg_list));
        TAILQ_REMOVE(&(MLACP(csm).arp_msg_list), msg, tail);
        arp_msg = (struct ARPMsg *)msg->buf;
        fprintf(stderr, "\n======== Dequeue ARP ========\n");
        fprintf(stderr, "  Type    = [%d]\n", arp_msg->op_type);
        fprintf(stderr, "  State   = (%04X)(%d)\n", ndm->ndm_state, fwd_neigh_state_valid(ndm->ndm_state));
        fprintf(stderr, "  ifname  = [%s]\n", arp_msg->ifname);
        fprintf(stderr, "  IP      = [%s]\n", show_ip_str(arp_msg->ipv4_addr));
        fprintf(stderr, "  MAC     = [%02X:%02X:%02X:%02X:%02X:%02X]\n",
                arp_msg->mac_addr[0],arp_msg->mac_addr[1],arp_msg->mac_addr[2],arp_msg->mac_addr[3],
                arp_msg->mac_addr[4],arp_msg->mac_addr[5]);
        fprintf(stderr, "==============================\n");
        free(msg->buf);
        free(msg);
    }
    MLACP(csm).arp_updated = 0;
    #endif
        
    return;
}

void ifm_parse_rtattr (struct rtattr **tb, int max, struct rtattr *rta, int len)
{
    while (RTA_OK (rta, len))
    {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT (rta, len);
    }
}

int do_one_neigh_request (struct nlmsghdr *n)
{
    struct ndmsg *ndm = NLMSG_DATA(n);
    int len = n->nlmsg_len;
    struct rtattr * tb[NDA_MAX+1];

    if (n->nlmsg_type == NLMSG_DONE) 
    {
        return 0;
    }

    /* process msg_type RTM_NEWNEIGH, RTM_GETNEIGH, RTM_DELNEIGH */
    if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type  != RTM_DELNEIGH )
        return(0);

    len -= NLMSG_LENGTH(sizeof(*ndm));
    if (len < 0)
        return -1;

    ifm_parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), len);

    if (ndm->ndm_state == NUD_INCOMPLETE
        || ndm->ndm_state == NUD_FAILED
        || ndm->ndm_state == NUD_NOARP
        || ndm->ndm_state == NUD_PERMANENT
        || ndm->ndm_state == NUD_NONE)
    {
        return(0);
    }

    if (!tb[NDA_DST] || ndm->ndm_type != RTN_UNICAST) 
    {
        return(0);
    }

    if (ndm->ndm_family == AF_INET) 
    {
        do_arp_request(ndm, tb, n->nlmsg_type); 
    }
    
    return(0);
}

/*When received MAC add and del packets from mclagsyncd, update mac information*/
void do_mac_update_from_syncd (char mac_str[32], uint16_t vid, char *ifname, uint8_t fdb_type, uint8_t op_type)
{
    struct System *sys = NULL;
    struct CSM *csm = NULL;
    struct Msg *msg = NULL;
    struct MACMsg *mac_msg = NULL, *mac_info = NULL;
    uint8_t mac_exist = 0;
    
    char buf[MAX_BUFSIZE];
    size_t msg_len = 0;
    
    struct LocalInterface *lif_po = NULL, *mac_lif = NULL;
    
    if (!(sys = system_get_instance()))
        return;
    
    /* Find local itf*/
    if (!(mac_lif = local_if_find_by_name(ifname)))
        return;
    
    /* create MAC msg*/
    memset(buf, 0, MAX_BUFSIZE);
    msg_len = sizeof(struct MACMsg);
    mac_msg = (struct MACMsg*) &buf;
    mac_msg->op_type = op_type;
    mac_msg->fdb_type = fdb_type;
    sprintf(mac_msg->mac_str, "%s", mac_str);
    mac_msg->vid = vid;
    sprintf(mac_msg->ifname, "%s", mac_lif->name);
    sprintf(mac_msg->origin_ifname, "%s", mac_lif->name);
    mac_msg->age_flag = 0;

    /*Debug*/
    #if 1
    /* dump receive MAC info*/
    fprintf(stderr, "\n======== MAC Update==========\n");
    fprintf(stderr, "  MAC    =  %s\n", mac_str);
    fprintf(stderr, "  ifname = %s\n", mac_lif->name);
    fprintf(stderr, "  vlan id = %d\n", vid);
    fprintf(stderr, "  fdb type = %s\n", fdb_type==MAC_TYPE_STATIC?"static":"dynamic");
    fprintf(stderr, "  op type = %s\n", op_type==MAC_SYNC_ADD?"add":"del");
    fprintf(stderr, "==============================\n");
    #endif
    
    /* Find MLACP itf, must be mclag enabled port-channel*/
    LIST_FOREACH(csm, &(sys->csm_list), next)
    {
        uint8_t find = 0;

        /*If MAC is from peer-link, break; peer-link is not in MLACP(csm).lif_list*/
        if (strcmp(ifname, csm->peer_itf_name) == 0) break;
            
        LIST_FOREACH(lif_po, &(MLACP(csm).lif_list), mlacp_next)
        {
            if (lif_po->type != IF_T_PORT_CHANNEL)
                continue;

            if(strcmp(lif_po->name, ifname) == 0)
            {
                find = 1;
                break;
            }
        }
        
        if(find == 1)
            break;
    }

    if (!csm) return;
    
    /* find lif MAC+vid*/
    TAILQ_FOREACH(msg, &MLACP(csm).mac_list, tail)
    {
        mac_info = (struct MACMsg*) msg->buf;

        /*MAC and vid are equal*/
        if (strcmp(mac_info->mac_str, mac_str) == 0 && mac_info->vid== vid)
        {
            mac_exist = 1;
            break;
        }
    }

    /*handle mac add*/
    if(op_type == MAC_SYNC_ADD)
    {
        /*same MAC exist*/
        if(mac_exist)
        {
            /*If the recv mac port is peer-link, that is add from iccpd, no need to handle*/
            if(strcmp(csm->peer_itf_name, mac_msg->ifname) == 0)
            {
                return;
            }
                            
            /*If the current mac port is peer-link, it will handle by port up event*/
            if(strcmp(csm->peer_itf_name, mac_info->ifname) == 0)
            {
                return;
            }
            
            /* update MAC*/
            if(mac_info->fdb_type != mac_msg->fdb_type
                || strcmp(mac_info->ifname, mac_msg->ifname) != 0
                || strcmp(mac_info->origin_ifname, mac_msg->ifname) != 0)
            {
                mac_info->fdb_type = mac_msg->fdb_type;
                sprintf(mac_info->ifname, "%s", mac_msg->ifname);
                sprintf(mac_info->origin_ifname, "%s", mac_msg->ifname);

                /*Remove MAC_AGE_LOCAL flag*/
                mac_info->age_flag = set_mac_local_age_flag(csm, mac_info, 0);
                
                ICCPD_LOG_DEBUG(__FUNCTION__, "Update MAC for %s, ifname %s", mac_msg->mac_str, mac_msg->ifname);
            }
            else
            {
                /*All info are the same, Remove MAC_AGE_LOCAL flag, then return*/
                /*In theory, this will be happened that mac age and then learn*/
                mac_info->age_flag = set_mac_local_age_flag(csm, mac_info, 0);
                
                return;
            }
        }
        else/*same MAC not exist*/
        {
            /*If the portchannel the mac learn is change to down before the mac 
               sync to iccp, this mac must be deleted */
            if(mac_lif->state == PORT_STATE_DOWN)
            {
                del_mac_from_chip(mac_msg);
                
                return;
            }
            
            /*set MAC_AGE_PEER flag before send this item to peer*/
            mac_msg->age_flag |= MAC_AGE_PEER;
            ICCPD_LOG_DEBUG(__FUNCTION__, "Add peer age flag: %s, add %s vlan-id %d, age_flag %d", 
                                mac_msg->ifname,mac_msg->mac_str, mac_msg->vid, mac_msg->age_flag);
            mac_msg->op_type = MAC_SYNC_ADD;
            
            if (MLACP(csm).current_state == MLACP_STATE_EXCHANGE)
            {
                struct Msg *msg_send = NULL;    
                if (iccp_csm_init_msg(&msg_send, (char*)mac_msg, msg_len)==0) 
                {
                    mac_msg->age_flag &= ~MAC_AGE_PEER;
                    TAILQ_INSERT_TAIL(&(MLACP(csm).mac_msg_list), msg_send, tail);

                    ICCPD_LOG_DEBUG(__FUNCTION__, "MAC-msg-list enqueue: %s, add %s vlan-id %d, age_flag %d", 
                            mac_msg->ifname,mac_msg->mac_str, mac_msg->vid, mac_msg->age_flag);
                }
            }

            /*enqueue mac to mac-list*/
            if (iccp_csm_init_msg(&msg, (char*)mac_msg, msg_len)==0) 
            {
                TAILQ_INSERT_TAIL(&(MLACP(csm).mac_list), msg, tail);

                ICCPD_LOG_DEBUG(__FUNCTION__, "MAC-list enqueue: %s, add %s vlan-id %d", 
                                mac_msg->ifname,mac_msg->mac_str, mac_msg->vid);
            }
            else
                ICCPD_LOG_DEBUG(__FUNCTION__, "Failed to enqueue MAC %s, add %s vlan-id %d", 
                                mac_msg->ifname,mac_msg->mac_str, mac_msg->vid);
        }
    }
    else/*handle mac del*/
    {
        /*same MAC exist*/
        if(mac_exist)
        {
            if(strcmp(mac_info->ifname, csm->peer_itf_name) == 0)
            {
                /*peer-link learn mac is control by iccpd, ignore the chip del info*/
                add_mac_to_chip(mac_info, MAC_TYPE_DYNAMIC);

                ICCPD_LOG_DEBUG(__FUNCTION__, "Recv MAC del msg: %s(peer-link), del %s vlan-id %d", 
                                mac_info->ifname,mac_info->mac_str, mac_info->vid);
                return;
            }

            /*Add MAC_AGE_LOCAL flag*/
            mac_info->age_flag = set_mac_local_age_flag(csm, mac_info, 1);

            if(mac_info->age_flag == (MAC_AGE_LOCAL|MAC_AGE_PEER))
            {
                ICCPD_LOG_DEBUG(__FUNCTION__, "Recv MAC del msg: %s, del %s vlan-id %d", 
                                mac_info->ifname,mac_info->mac_str, mac_info->vid);
                                
                /*send mac del message to mclagsyncd.*/
                /*del_mac_from_chip(mac_info);*/
                
                /*If local and peer both aged, del the mac*/
                TAILQ_REMOVE(&(MLACP(csm).mac_list), msg, tail);
                free(msg->buf);
                free(msg);
            }
            else
            {
                ICCPD_LOG_DEBUG(__FUNCTION__, "Recv MAC del msg: %s, del %s vlan-id %d, peer is not age", 
                                mac_info->ifname,mac_info->mac_str, mac_info->vid);

                if(lif_po && lif_po->state == PORT_STATE_DOWN)
                {
                    /*If local if is down, redirect the mac to peer-link*/
                    memcpy(&mac_info->ifname, csm->peer_itf_name, IFNAMSIZ);
                    ICCPD_LOG_DEBUG(__FUNCTION__, "Recv MAC del msg: %s(down), del %s vlan-id %d, redirect to peer-link", 
                                mac_info->ifname,mac_info->mac_str, mac_info->vid);
                }
                
                /*If local is aged but peer is not aged, Send mac add message to mclagsyncd*/
                mac_info->fdb_type = MAC_TYPE_DYNAMIC;
                
                add_mac_to_chip(mac_info, MAC_TYPE_DYNAMIC);
            }
        }
    }
    
    return;
}

void iccp_from_netlink_portchannel_state_handler( char * ifname, int state)
{
    struct CSM *csm = NULL;
    struct LocalInterface *lif_po = NULL;
    struct System *sys;
    int po_is_active = 0;
    
    if((sys = system_get_instance()) == NULL)
    {
        ICCPD_LOG_WARN(__FUNCTION__, "Failed to obtain System instance.");
        return;
    }

    po_is_active = (state == PORT_STATE_UP);
    
    /* traverse all CSM */
    LIST_FOREACH(csm, &(sys->csm_list), next)
    {
        LIST_FOREACH(lif_po, &(MLACP(csm).lif_list), mlacp_next)
        {
            if(lif_po->type == IF_T_PORT_CHANNEL && strncmp(lif_po->name, ifname, MAX_L_PORT_NAME) == 0) 
            {
                mlacp_portchannel_state_handler(csm,lif_po,po_is_active);
            }
        }
    }
    /*peerlink state is sync by heardbeat, do not need to response */

    return;
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	
	while (RTA_OK(rta, len)) 
	{
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	
	return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

void iccp_get_if_vlan_info_from_netlink()
{
    struct LocalInterface *lif = NULL;
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
        /* attribute has to be NLMSG aligned */
        struct rtattr ext_req __attribute__ ((aligned(NLMSG_ALIGNTO)));
        __u32 ext_filter_mask;
    } req;

    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    char * buf = malloc(10000000);
    struct nl_sock *sk ;
    int fd;

    struct System *sys;

    if((sys = system_get_instance()) == NULL)
    {
        ICCPD_LOG_WARN(__FUNCTION__, "Failed to obtain System instance.");
        free(buf);
        return;
    }
    fd = nl_socket_get_fd(sys->route_sock);

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
    req.nlh.nlmsg_pid = 0;
    req.nlh.nlmsg_seq = 0;
    req.ifm.ifi_family = PF_BRIDGE;

    req.ext_req.rta_type = IFLA_EXT_MASK;
    req.ext_req.rta_len = RTA_LENGTH(sizeof(__u32));
    req.ext_filter_mask = RTEXT_FILTER_BRVLAN;

    send(fd, (void*)&req, sizeof(req), 0);

    iov.iov_base = buf;
    while (1) 
    {
        int status;
        int msglen = 0;

        iov.iov_len = 10000000;
        
        status = recvmsg(fd, &msg, 0);

        if (status < 0 ||status == 0) 
        {
            ICCPD_LOG_WARN(__FUNCTION__, "netlink receive error  (%d) status %d %d ", fd, status,errno);
            free(buf);
            return ;
        }

        struct nlmsghdr *n = (struct nlmsghdr*)buf;

        msglen = status;

        while (NLMSG_OK(n, msglen)) 
        {

            struct ifinfomsg *ifm = NLMSG_DATA(n);
            int len = n->nlmsg_len;
            struct rtattr * tb[IFLA_MAX+1];

            if (n->nlmsg_type != RTM_NEWLINK) 
            {
    	         free(buf);
                return ;
            }

            len -= NLMSG_LENGTH(sizeof(*ifm));
            if (len < 0) 
            {
                ICCPD_LOG_WARN(__FUNCTION__, "BUG: wrong nlmsg len %d\n", len);
                free(buf);
                return ;
            }

            if (ifm->ifi_family != AF_BRIDGE)
            {
                free(buf);               
                return ;
            }

            if (lif = local_if_find_by_ifindex(ifm->ifi_index))
            {
                parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifm), len);

                /* if AF_SPEC isn't there, vlan table is not preset for this port */
                if (!tb[IFLA_AF_SPEC]) 
                {
                    ICCPD_LOG_WARN(__FUNCTION__, "%d   None\n", (ifm->ifi_index));
                    free(buf);
                    return ;
                } 
                else 
                {
                    struct rtattr *i, *list = tb[IFLA_AF_SPEC];
                    int rem = RTA_PAYLOAD(list);
                    struct VLAN_ID *vlan = NULL;

                    /*set vlan flag is removed*/
                    LIST_FOREACH(vlan, &(lif->vlan_list), port_next)
                    {
                        vlan->vlan_removed = 1;
                    }
                    
                    for (i = RTA_DATA(list); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) 
                    {
                        struct bridge_vlan_info *vinfo;

                        if (i->rta_type != IFLA_BRIDGE_VLAN_INFO)
                            continue;

                        vinfo = RTA_DATA(i);

                        local_if_add_vlan(lif, vinfo->vid);

                        /*ICCPD_LOG_DEBUG(__FUNCTION__, "get vlan netlink msg lif index %d vinfo->flag %d, vid %d",ifm->ifi_index, vinfo->flags, vinfo->vid );  */
                    }

                    /*After update vlan list, remove unused item*/
                    LIST_FOREACH(vlan, &(lif->vlan_list), port_next)
                    {
                        if(vlan->vlan_removed == 1)
                        {
                            ICCPD_LOG_DEBUG(__FUNCTION__, "Delete VLAN ID = %d from %s", vlan->vid, lif->name);
                            
                            LIST_REMOVE(vlan, port_next);
                            free(vlan);
                        }
                    }
                }
            }

            n = NLMSG_NEXT(n, msglen);
        }
    }
    free(buf);
}

