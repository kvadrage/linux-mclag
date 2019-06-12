/********************************************************************************
* mlacp_sync_update.c
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
* 
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include <sys/queue.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>

#include "../include/system.h"
#include "../include/logger.h"
#include "../include/mlacp_tlv.h"
#include "../include/mlacp_link_handler.h"

/*****************************************
* Port-Conf Update
*
* ***************************************/
int mlacp_fsm_update_system_conf(struct CSM* csm, mLACPSysConfigTLV*sysconf)
{    
    /*NOTE
     a little tricky, we change the NodeID local side if collision happened first time*/
    if(sysconf->node_id == MLACP(csm).node_id)
        MLACP(csm).node_id++;
    
    memcpy(MLACP(csm).remote_system.system_id, sysconf->sys_id, ETHER_ADDR_LEN);
    MLACP(csm).remote_system.system_priority = sysconf->sys_priority;
    MLACP(csm).remote_system.node_id = sysconf->node_id;
    
    update_system_id(csm);
    
    ICCPD_LOG_DEBUG(__FUNCTION__, "   SystemID [%02X:%02X:%02X:%02X:%02X:%02X]. SystemPriority [%d], Remote NodeID [%d], NodeID [%d]",
                    MLACP(csm).remote_system.system_id[0],MLACP(csm).remote_system.system_id[1],MLACP(csm).remote_system.system_id[2],
                    MLACP(csm).remote_system.system_id[3],MLACP(csm).remote_system.system_id[4],MLACP(csm).remote_system.system_id[5],
                    MLACP(csm).remote_system.system_priority,
                    MLACP(csm).remote_system.node_id,
                    MLACP(csm).node_id);
                    
    return 0;
}

/*****************************************
* Port-Conf Update
*
* ***************************************/
int mlacp_fsm_update_Agg_conf(struct CSM* csm, mLACPAggConfigTLV* portconf)
{
    struct PeerInterface* pif = NULL;
    uint8_t po_active;
    uint8_t new_create = 0;

    ICCPD_LOG_DEBUG(__FUNCTION__, "    Port name  %s, po id %d  flag %d MAC[%02x:%02x:%02x:%02x:%02x:%02x] ",
    portconf->agg_name,portconf->agg_id, portconf->flags,portconf->mac_addr[0], portconf->mac_addr[1], portconf->mac_addr[2],
                   portconf->mac_addr[3], portconf->mac_addr[4], portconf->mac_addr[5] );
                   
    /* Looking for the peer port instance, is any peer if exist?*/
    pif = peer_if_find_by_name(csm, portconf->agg_name);
    
    /* Process purge*/
    if (portconf->flags & 0x02) 
    {
        /*Purge*/
        if (pif != NULL )
            peer_if_destroy(pif);
        else
            MLACP(csm).need_to_sync = 1;
        /*ICCPD_LOG_INFO("mlacp_fsm",
            "    Peer port %s is removed from port-channel member.",portconf->port_name);*/
            
        return 0;
    }

    if(pif == NULL && portconf->flags & 0x01)
    {
        pif = peer_if_create(csm, portconf->agg_id, IF_T_PORT_CHANNEL);
        if(pif == NULL) return -1;

        new_create= 1;
    }
    
    pif->po_id = portconf->agg_id;
    memcpy(pif->name, portconf->agg_name, portconf->agg_name_len);
    memcpy(pif->mac_addr, portconf->mac_addr, ETHER_ADDR_LEN);
    
    po_active = (pif->state == PORT_STATE_UP);
    update_stp_peer_link(csm, pif, po_active, new_create);
    update_peerlink_isolate_from_pif(csm, pif, po_active, new_create);    
    pif->po_active = po_active;
    
    return 0;
}

/*****************************************
* Agg Port-State Update
*
* ***************************************/
int mlacp_fsm_update_Aggport_state(struct CSM* csm, mLACPAggPortStateTLV* tlv)
{
    struct PeerInterface* peer_if = NULL;
    uint8_t po_active;
    
    if(csm == NULL || tlv == NULL)
        return -255;
    ICCPD_LOG_DEBUG(__FUNCTION__, "  po id %d  state %d  ",tlv->agg_id, tlv->agg_state);

    po_active = (tlv->agg_state == PORT_STATE_UP);
    
    LIST_FOREACH(peer_if, &(MLACP(csm).pif_list), mlacp_next)
    {
        if (peer_if->type != IF_T_PORT_CHANNEL)
            continue;
        
        if (peer_if->po_id != tlv->agg_id)
            continue;

        peer_if->state = tlv->agg_state;

        update_stp_peer_link(csm, peer_if, po_active, 0);
        update_peerlink_isolate_from_pif(csm, peer_if, po_active, 0);

        peer_if->po_active = po_active;
        break;
    }
    
    return 0;
}

 /* Delete an entry from the ARP cache. */
int mlacp_fsm_arp_del(char *ifname, uint32_t ip)
{
     struct arpreq arpreq;
     struct sockaddr_in *sin;
     struct in_addr ina;
     int rc;
     int sock_fd = 0; 
 
     ICCPD_LOG_DEBUG(__FUNCTION__,"%s: Del arp entry for IP : %s\n", __FUNCTION__, show_ip_str(ip));

     if(ifname == NULL || ip == 0)  
    {  
        return -1;  
    }  
    
     /*you must add this becasue some system will return "Invlid argument"
        because some argument isn't zero */
     memset(&arpreq, 0, sizeof(struct arpreq));
 
     sin = (struct sockaddr_in *) &arpreq.arp_pa;
     memset(sin, 0, sizeof(struct sockaddr_in));
     sin->sin_family = AF_INET;
     ina.s_addr = ip;
     memcpy(&sin->sin_addr, (char *) &ina, sizeof(struct in_addr));
 
     strncpy(arpreq.arp_dev, ifname, 15);

     sock_fd = socket(AF_INET, SOCK_DGRAM, 0);  
     if(sock_fd < 0)  
     {  
         return -1;  
     }  
    
     rc = ioctl(sock_fd, SIOCDARP, &arpreq);
     if (rc < 0)
     {
         close(sock_fd);  
         return -1;
     }

     close(sock_fd);  
     
     return 0;
 }

 int getHwAddr(char *buff, char *mac)  
 {	
     int i = 0;  
     unsigned int p[6];  
 
    if( buff == NULL || mac == NULL )  
    {  
	   return -1;  
    }  
   
    if(sscanf(mac, "%x:%x:%x:%x:%x:%x", &p[0], &p[1], &p[2], &p[3], &p[4], &p[5]) < 6)  
    {	
	 return -1;  
    }	
 
    for(i = 0; i < 6; i ++)  
    {	
	 buff[i] = p[i];  
    }	
   
     return 0;	
 }	

 /*****************************************
 * Recv from peer, MAC-Info Update
 * ***************************************/
 int mlacp_fsm_update_mac_info_from_peer(struct CSM* csm, struct mLACPMACInfoTLV* tlv) 
 {
    struct Msg* msg = NULL;
    struct Msg* msg_send = NULL; 
    struct MACMsg *mac_msg = NULL, mac_data;
    struct LocalInterface* local_if = NULL;

    if (!csm || !tlv)
        return -255;

#if 1
    ICCPD_LOG_INFO(__FUNCTION__,
                "Received MAC Info, itf=[%s] vid[%d] MAC[%s]  type %d ",
                tlv->ifname, tlv->vid, tlv->mac_str, tlv->type);
#endif

    /*Find the interface*/
    LIST_FOREACH(local_if, &(MLACP(csm).lif_list), mlacp_next)
    {
        if (local_if->type == IF_T_PORT_CHANNEL && strcmp(local_if->name, tlv->ifname) == 0)
        {
            break;
        }
    }

    if(!local_if)
    {
        /*If the interface is not exist, return*/
        return -255;
    }

    /* update MAC list*/
    TAILQ_FOREACH(msg, &(MLACP(csm).mac_list), tail)
    {
        mac_msg = (struct MACMsg*) msg->buf;
        if (strcmp(mac_msg->mac_str, tlv->mac_str) == 0 && mac_msg->vid == tlv->vid) 
        {
            if(tlv->type == MAC_SYNC_ADD)
            {
                mac_msg->age_flag &= ~MAC_AGE_PEER;
                ICCPD_LOG_DEBUG(__FUNCTION__, "Recv ADD, Remove peer age flag:%d ifname  %s, add %s vlan-id %d, op_type %d", 
                                mac_msg->age_flag,mac_msg->ifname,mac_msg->mac_str, mac_msg->vid, mac_msg->op_type);
                
                /*mac_msg->fdb_type = tlv->fdb_type;*/
                if(strcmp(mac_msg->ifname, tlv->ifname) != 0 || strcmp(mac_msg->origin_ifname, tlv->ifname) != 0)
                {
                    if(mac_msg->fdb_type != MAC_TYPE_STATIC)
                    {
                        memcpy(&mac_msg->ifname, tlv->ifname, MAX_L_PORT_NAME);
                        memcpy(&mac_msg->origin_ifname, tlv->ifname, MAX_L_PORT_NAME);
                    }

                    if(local_if->state == PORT_STATE_DOWN && strcmp(mac_msg->ifname, csm->peer_itf_name) != 0)
                    {
                        /*First del the old item*/
                        /*del_mac_from_chip(mac_msg);*/
                        
                        /*If local if is down, redirect the mac to peer-link*/
                        memcpy(&mac_msg->ifname, csm->peer_itf_name, IFNAMSIZ);

                        /*sleep 10ms, avoid orchagent mix the del event*/
                        /*usleep(100000);*/
                        
                        /*Send mac add message to mclagsyncd*/
                        add_mac_to_chip(mac_msg, MAC_TYPE_DYNAMIC);
                    }
                }

                #if 0
                mac_msg->op_type = MAC_SYNC_ACK;
                if (iccp_csm_init_msg(&msg_send, (char*)mac_msg, sizeof(struct MACMsg)) == 0) 
                {
                    /*Reply mac ack message to peer, peer will clean MAC_AGE_PEER flag*/
                    TAILQ_INSERT_TAIL(&(MLACP(csm).mac_msg_list), msg_send, tail);
                    ICCPD_LOG_DEBUG(__FUNCTION__, "Recv ADD, MAC-msg-list enqueue: %s, add %s vlan-id %d, op_type %d", 
                                    mac_msg->ifname,mac_msg->mac_str, mac_msg->vid, mac_msg->op_type);
                }
                #endif
            }
            else if(tlv->type == MAC_SYNC_ACK)
            {
                /*Clean the MAC_AGE_PEER flag*/
                mac_msg->age_flag &= ~MAC_AGE_PEER;
                ICCPD_LOG_DEBUG(__FUNCTION__, "Recv ACK, Remove peer age flag:%d ifname  %s, add %s vlan-id %d, op_type %d", 
                                mac_msg->age_flag,mac_msg->ifname,mac_msg->mac_str, mac_msg->vid, mac_msg->op_type);
            }

            break;
        }
    }

    /* delete/add MAC list*/
    if (msg && tlv->type == MAC_SYNC_DEL) 
    {
        mac_msg->age_flag |= MAC_AGE_PEER;
        ICCPD_LOG_DEBUG(__FUNCTION__, "Add peer age flag: %d   ifname %s, add %s vlan-id %d, op_type %d", 
                                mac_msg->age_flag,mac_msg->ifname,mac_msg->mac_str, mac_msg->vid, mac_msg->op_type);
        
        if(mac_msg->age_flag == (MAC_AGE_LOCAL|MAC_AGE_PEER))
        {
            /*send mac del message to mclagsyncd.*/
            del_mac_from_chip(mac_msg);

            /*If local and peer both aged, del the mac*/
            TAILQ_REMOVE(&(MLACP(csm).mac_list), msg, tail);
            free(msg->buf);
            free(msg);
        }
        else
        {
            return 0;
        }
    }
    else if (!msg && tlv->type == MAC_SYNC_ADD) 
    {
        mac_msg = (struct MACMsg*) &mac_data;
        mac_msg->fdb_type = MAC_TYPE_DYNAMIC;
        mac_msg->vid = tlv->vid;
        sprintf(mac_msg->mac_str, "%s", tlv->mac_str);
        sprintf(mac_msg->ifname, "%s", tlv->ifname);
        sprintf(mac_msg->origin_ifname, "%s", tlv->ifname);
        mac_msg->age_flag = 0;

        if(local_if->state == PORT_STATE_DOWN)
        {
            /*If local if is down, redirect the mac to peer-link*/
            memcpy(&mac_msg->ifname, csm->peer_itf_name, IFNAMSIZ);
        }
        
        if (iccp_csm_init_msg(&msg, (char*)mac_msg, sizeof(struct MACMsg)) == 0) 
        {
            TAILQ_INSERT_TAIL(&(MLACP(csm).mac_list), msg, tail);
            /*ICCPD_LOG_INFO(__FUNCTION__, "add mac queue successfully");*/

            /*Send mac add message to mclagsyncd*/
            add_mac_to_chip(mac_msg, mac_msg->fdb_type);

            #if 0
            mac_msg->op_type = MAC_SYNC_ACK;
            if (iccp_csm_init_msg(&msg_send, (char*)mac_msg, sizeof(struct MACMsg)) == 0) 
            {
                /*Reply mac ack message to peer, peer will clean MAC_AGE_PEER flag*/
                TAILQ_INSERT_TAIL(&(MLACP(csm).mac_msg_list), msg_send, tail);
                ICCPD_LOG_DEBUG(__FUNCTION__, "MAC-msg-list enqueue: %s, add %s vlan-id %d, op_type %d", 
                                mac_msg->ifname,mac_msg->mac_str, mac_msg->vid, mac_msg->op_type);
            }
            #endif
        }
    }

    return 0;
 }

 /* Set an entry in the ARP cache. */
int mlacp_fsm_arp_set(char *ifname, uint32_t ip, char *mac)
{
     struct arpreq arpreq;
     struct sockaddr_in *sin;
     struct in_addr ina;
     int flags;
     int rc;
     int sock_fd = 0;
 
     ICCPD_LOG_DEBUG(__FUNCTION__, "Set arp entry for IP:%s  MAC:%s  ifname:%s\n", show_ip_str(ip), mac,ifname);

     if(ifname == NULL || ip == 0 || mac == NULL)  
     {  
         return -1;  
     }  
    
     /*you must add this becasue some system will return "Invlid argument"
        because some argument isn't zero */
     memset(&arpreq, 0, sizeof(struct arpreq));
     sin = (struct sockaddr_in *) &arpreq.arp_pa;
     memset(sin, 0, sizeof(struct sockaddr_in));
     sin->sin_family = AF_INET;
     ina.s_addr = ip;
     memcpy(&sin->sin_addr, (char *) &ina, sizeof(struct in_addr));
 
     if(getHwAddr((char *)arpreq.arp_ha.sa_data, mac) < 0)  
     {  
        return -1;  
     }  
    
     strncpy(arpreq.arp_dev, ifname, 15);
 
     flags = ATF_COM; //note, must set flag, if not,you will get error
 
     arpreq.arp_flags = flags;

     sock_fd = socket(AF_INET, SOCK_DGRAM, 0);  
    if(sock_fd < 0)  
     {  
         return -1;  
     }  
    
     rc = ioctl(sock_fd, SIOCSARP, &arpreq);
     if (rc < 0)
     {
         close(sock_fd);  
         return -1;
     } 

     close(sock_fd);  
     
     return 0;
}

/*****************************************
* Tool : Add ARP Info into ARP list
*
****************************************/
void mlacp_enqueue_arp(struct CSM* csm, struct Msg* msg)
{
    struct ARPMsg *arp_msg = NULL;
    
    if (!csm) 
    {
        if (msg)
            free(msg);
        return;
    }
    if (!msg)
        return;
    
    arp_msg = (struct ARPMsg*) msg->buf;
    if (arp_msg->op_type != ARP_SYNC_DEL)
    {
        time(&arp_msg->update_time);
        TAILQ_INSERT_TAIL(&(MLACP(csm).arp_list), msg, tail);
    }

    return;
}

/*****************************************
* ARP-Info Update
* ***************************************/
int mlacp_fsm_update_arp_info(struct CSM* csm, struct mLACPARPInfoTLV* tlv) 
{
    struct Msg* msg = NULL;
    struct ARPMsg *arp_msg = NULL, arp_data;
    struct LocalInterface* local_if;
    struct LocalInterface *peer_link_if = NULL;
    struct VLAN_ID *vlan_id_list=NULL;
    int set_arp_flag=0;
    char mac_str[18] = "";
    
    if (!csm || !tlv)
        return -255;
    
    #if 1
    ICCPD_LOG_INFO(__FUNCTION__,
                   "%s: Received ARP Info,"
                   "itf=[%s] ARP IP[%s],MAC[%02x:%02x:%02x:%02x:%02x:%02x]",
                   __FUNCTION__,
                   tlv->ifname, show_ip_str(tlv->ipv4_addr),
                   tlv->mac_addr[0], tlv->mac_addr[1], tlv->mac_addr[2],
                   tlv->mac_addr[3], tlv->mac_addr[4], tlv->mac_addr[5]);
    #endif

    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", tlv->mac_addr[0], tlv->mac_addr[1], tlv->mac_addr[2],
                   tlv->mac_addr[3], tlv->mac_addr[4], tlv->mac_addr[5]);

    if(strncmp(tlv->ifname,"Vlan",4) == 0)
    {
        peer_link_if = local_if_find_by_name(csm->peer_itf_name);
        
        if(!local_if_is_l3_mode(peer_link_if)) 
        {
            /* Is peer-linlk itf belong to a vlan the same as peer?*/
            LIST_FOREACH(vlan_id_list, &(peer_link_if->vlan_list), port_next)
            {
                if(!vlan_id_list->vlan_itf)
                    continue;
                if(strcmp(vlan_id_list->vlan_itf->name, tlv->ifname)!=0)
                    continue;
                if(!local_if_is_l3_mode(vlan_id_list->vlan_itf))
                    continue;
                
                ICCPD_LOG_DEBUG(__FUNCTION__,
                                "%s:  ==> Find ARP itf on L3 bridge, peer-link %s of %s",
                                __FUNCTION__,
                                peer_link_if->name, vlan_id_list->vlan_itf->name);

                /* Peer-link belong to L3 vlan is alive, set the ARP info*/
                set_arp_flag=1;
                
                break;
            }
        }
    }

    if(set_arp_flag == 0)
    {
        LIST_FOREACH(local_if, &(MLACP(csm).lif_list), mlacp_next)
        {
            if (local_if->type == IF_T_PORT_CHANNEL)
            {
                if(!local_if_is_l3_mode(local_if)) 
                {
                    /* Is the L2 MLAG itf belong to a vlan the same as peer?*/
                    LIST_FOREACH(vlan_id_list, &(local_if->vlan_list), port_next)
                    {
                        if(!vlan_id_list->vlan_itf)
                            continue;
                        if(strcmp(vlan_id_list->vlan_itf->name, tlv->ifname)!=0)
                            continue;
                        if(!local_if_is_l3_mode(vlan_id_list->vlan_itf))
                            continue;
                        
                        ICCPD_LOG_DEBUG(__FUNCTION__,
                                        "%s:  ==> Find ARP itf on L3 bridge, %s of %s",
                                        __FUNCTION__,
                                        local_if->name, vlan_id_list->vlan_itf->name);
                        break;
                    }
                    
                    if(vlan_id_list && local_if->po_active==1)
                    {
                        /* Any po of L3 vlan is alive, set the ARP info*/
                        set_arp_flag=1;
                        break;
                    }    
                }
                else 
                {
                    /* Is the ARP belong to a L3 mode MLAG itf?*/
                    if(strcmp(local_if->name, tlv->ifname)==0)
                    {
                        ICCPD_LOG_DEBUG(__FUNCTION__,
                                        "%s:  ==> Find ARP itf on L3 port-channel, %s",
                                        __FUNCTION__,
                                        local_if->name);
                        if(local_if->po_active==1) 
                        {
                            /* po is alive, set the ARP info*/
                            set_arp_flag=1;
                            break;
                        }
                    }
                    else 
                    {
                        continue;
                    }
                }
            }
        }
    }
    
    /* set dynamic ARP*/
    if (set_arp_flag == 1) 
    {
        if (tlv->type == ARP_SYNC_ADD) 
        {
            if(mlacp_fsm_arp_set(tlv->ifname, tlv->ipv4_addr, mac_str) < 0)
            {
                ICCPD_LOG_DEBUG(__FUNCTION__,"%s: ARP set for %s %s %s",
                        __FUNCTION__, tlv->ifname, show_ip_str(tlv->ipv4_addr), mac_str);
                return -1;
            }
        }
        else 
        {
            if(mlacp_fsm_arp_del(tlv->ifname, tlv->ipv4_addr) < 0)
            {
                ICCPD_LOG_DEBUG(__FUNCTION__,"%s: ARP delete for %s %s %s",
                        __FUNCTION__, tlv->ifname, show_ip_str(tlv->ipv4_addr), mac_str);
                return -1;
            }
        }
        
        ICCPD_LOG_DEBUG(__FUNCTION__,"%s: ARP update for %s %s %s",
                        __FUNCTION__, tlv->ifname, show_ip_str(tlv->ipv4_addr), mac_str);
    }
    else 
    {
       ICCPD_LOG_DEBUG(__FUNCTION__, "%s:  ==> port-channel is not alive",
                       __FUNCTION__);
        /*TODO Set static route through peer-link or just skip it?*/
    }
    
    /* update ARP list*/
    TAILQ_FOREACH(msg, &(MLACP(csm).arp_list), tail)
    {
        arp_msg = (struct ARPMsg*) msg->buf;
        if (arp_msg->ipv4_addr == tlv->ipv4_addr) 
        {
            /*arp_msg->op_type = tlv->type;*/
            sprintf(arp_msg->ifname, "%s", tlv->ifname);
            memcpy(arp_msg->mac_addr, tlv->mac_addr, ETHER_ADDR_LEN);
            break;
        }
    }
    
    /* delete/add ARP list*/
    if (msg && tlv->type == ARP_SYNC_DEL) 
    {
        TAILQ_REMOVE(&(MLACP(csm).arp_list), msg, tail);
        free(msg->buf); free(msg);
        ICCPD_LOG_INFO(__FUNCTION__, "%s: del arp queue successfully",
                       __FUNCTION__);
    }
    else if (!msg && tlv->type == ARP_SYNC_ADD) 
    {
        arp_msg = (struct ARPMsg*) &arp_data;
        sprintf(arp_msg->ifname, "%s", tlv->ifname);
        arp_msg->ipv4_addr = tlv->ipv4_addr;
        arp_msg->op_type = tlv->type;
        memcpy(arp_msg->mac_addr, tlv->mac_addr, ETHER_ADDR_LEN);
        if (iccp_csm_init_msg(&msg, (char*)arp_msg, sizeof(struct ARPMsg)) == 0) 
        {
            mlacp_enqueue_arp(csm, msg);
            ICCPD_LOG_INFO(__FUNCTION__, "%s: add arp queue successfully",
                           __FUNCTION__);
        }
    }
    
    /* remove all ARP msg queue, when receive peer's ARP list at the same time*/
    TAILQ_FOREACH(msg, &(MLACP(csm).arp_msg_list), tail)
    {
        arp_msg = (struct ARPMsg*) msg->buf;
        if (arp_msg->ipv4_addr == tlv->ipv4_addr) break;
    }
    
    while (msg) 
    {
        arp_msg = (struct ARPMsg*) msg->buf;
        TAILQ_REMOVE(&(MLACP(csm).arp_msg_list), msg, tail);
        free(msg->buf); 
        free(msg);
        TAILQ_FOREACH(msg, &(MLACP(csm).arp_msg_list), tail)
        {
            arp_msg = (struct ARPMsg*) msg->buf;
            if (arp_msg->ipv4_addr == tlv->ipv4_addr) break;
        }    
    }
        
    return 0;
}

/*****************************************
* Port-Channel-Info Update
* ***************************************/
int mlacp_fsm_update_port_channel_info(struct CSM* csm,
                                       struct mLACPPortChannelInfoTLV* tlv)
{
    struct PeerInterface* peer_if = NULL;
    struct LocalInterface* local_if = NULL;
    struct VLAN_ID* peer_vlan_id = NULL;
    int i = 0;
    
    if (csm == NULL || tlv == NULL )
        return -1;
    
    LIST_FOREACH(peer_if, &(MLACP(csm).pif_list), mlacp_next)
    {
        if (peer_if->type != IF_T_PORT_CHANNEL)
            continue;
        
        if (peer_if->po_id != tlv->agg_id)
            continue;

         LIST_FOREACH(peer_vlan_id, &(peer_if->vlan_list), port_next)
        {
            peer_vlan_id->vlan_removed = 1;
        }
        
        /* Record peer info*/
        peer_if->ipv4_addr = ntohl(tlv->ipv4_addr);
        peer_if->l3_mode = tlv->l3_mode;

        for (i = 0; i < tlv->num_of_vlan_id; i++)
        {
            peer_if_add_vlan(peer_if,tlv->vlanData[i].vlan_id);
        }
        
        peer_if_clean_unused_vlan(peer_if);

        iccp_consistency_check(peer_if->name);   
        
        ICCPD_LOG_DEBUG(__FUNCTION__, "port channel info  ip %s l3 mode  %d", show_ip_str( peer_if->ipv4_addr), peer_if->l3_mode);
        break;
    }    
       
    return 0;
}

/*****************************************
* Peerlink port Update
* ***************************************/
int mlacp_fsm_update_peerlink_info(struct CSM* csm,
                                       struct mLACPPeerLinkInfoTLV* tlv)
{    
    if (csm == NULL || tlv == NULL )
        return -1;
    ICCPD_LOG_DEBUG(__FUNCTION__, "peerlink port info from peer");    
    
    if(csm->peer_link_if->type != tlv->port_type)
        ICCPD_LOG_DEBUG(__FUNCTION__, "peerlink port type of peer %d is not same as local %d !", tlv->port_type, csm->peer_link_if->type);

    /*if(tlv->port_type == IF_T_VXLAN && strncmp(csm->peer_itf_name, tlv->if_name, strlen(csm->peer_itf_name)))        
        ICCPD_LOG_DEBUG(__FUNCTION__, "peerlink port is vxlan port and peerlink port at peer %s is  not same as local peerlink port %s  !",tlv->if_name, csm->peer_itf_name);*/
       
    return 0;
}

/*****************************************
* Heartbeat Update
*****************************************/
int mlacp_fsm_update_heartbeat(struct CSM* csm, struct mLACPHeartbeatTLV* tlv)
{
    if (!csm || !tlv)
        return -255;
    
    time(&csm->heartbeat_update_time);
    
    return 0;
}


