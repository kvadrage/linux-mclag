/*
* MLACP Sync Infomation Preparation
* mlacp_sync_prepare.c

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
*/

#include <stdio.h>
#include <stdlib.h>

#include <sys/queue.h>

#include "../include/system.h"
#include "../include/logger.h"
#include "../include/mlacp_fsm.h"
#include "../include/mlacp_tlv.h"
#include "../include/mlacp_link_handler.h"
#include "../include/iccp_ifm.h"

#define SET_MAC_STR(buf, macArray) \
            snprintf(buf, 64, "%02x:%02x:%02x:%02x:%02x:%02x",\
            macArray[0],macArray[1],macArray[2], \
            macArray[3],macArray[4],macArray[5]);

#define SYSID_UPDATE_INT  3 /*3 secs*/

void update_system_id(struct CSM* csm)
{
    char macaddr[64];
    char ori_macaddr[64];
    struct LocalInterface* lif_po = NULL;
    uint8_t null_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    char cmd[256];
    int ret = 0;
    static int bridge_mac_set = 0;
    struct VLAN_ID *vlan = NULL;
    
    if (!csm)
        return;
        
    if(memcmp(MLACP(csm).system_id, null_mac, ETHER_ADDR_LEN)==0)
        return;

    if(memcmp(MLACP(csm).remote_system.system_id, null_mac, ETHER_ADDR_LEN)==0)
        return;
    
    /* don't change mac continously, it needs a little time to process mac*/
    if ((time(NULL)-csm->sysid_update_time) < SYSID_UPDATE_INT)
        return;
    
    time(&csm->sysid_update_time);
    LIST_FOREACH(lif_po, &(MLACP(csm).lif_list), mlacp_next)
    {
        if(lif_po->type != IF_T_PORT_CHANNEL)
            continue;
        
        /* backup old sysmac*/
        memcpy(lif_po->mac_addr_ori, lif_po->mac_addr,
               ETHER_ADDR_LEN);
        
        /* set new mac*/
        memset(macaddr, 0, 64);
        memset(ori_macaddr, 0, 64);

        SET_MAC_STR(ori_macaddr, lif_po->mac_addr);
        
        if (csm->role_type == STP_ROLE_STANDBY) 
        {
            SET_MAC_STR(macaddr, MLACP(csm).remote_system.system_id);
        }
        else 
        {
            SET_MAC_STR(macaddr, MLACP(csm).system_id);
        }

        if(strcmp(macaddr, ori_macaddr)!= 0)
        {
            ICCPD_LOG_INFO(__FUNCTION__,
                "%s Change the system-id of po%d from %s to %s.",
                (csm->role_type == STP_ROLE_STANDBY)?"Standby":"Active",
                lif_po->po_id, ori_macaddr, macaddr);
            
            snprintf(cmd, sizeof cmd,
                     "ip link set dev %s  address %s > /dev/null 2>&1",
                     lif_po->name,  macaddr);
            ret = system(cmd);
            if (ret != 0)
            {
                ICCPD_LOG_ERR(__FUNCTION__, "%s: Execute command (%s) ret = %d",
                               __FUNCTION__, cmd, ret);
            }
           
            if(local_if_is_l3_mode(lif_po))
                iccp_set_portchannel_ipadd_mac(lif_po, macaddr );
            else
            {
                LIST_FOREACH(vlan, &(lif_po->vlan_list), port_next)
                {
                    if(!vlan->vlan_itf)
                        continue;

                    /* If the po is under a vlan, update vlan mac*/
                    if(local_if_is_l3_mode(vlan->vlan_itf))
                    {
                        snprintf(cmd, sizeof cmd,
                                 "ip link set dev %s  address %s > /dev/null 2>&1",
                                 vlan->vlan_itf->name,  macaddr);   
                        ret = system(cmd);
                        
                        iccp_set_portchannel_ipadd_mac(vlan->vlan_itf, macaddr );
                    }
                }
            }

            /*Set bridge mac, prevent bridge mac changed follow portchannel mac*/
            if(bridge_mac_set == 0)
            {
                bridge_mac_set = 1;
                
                snprintf(cmd, sizeof cmd,
                         "ip link set dev Bridge  address %s > /dev/null 2>&1",
                         ori_macaddr);

                ret = system(cmd);
                if (ret != 0)
                {
                    ICCPD_LOG_ERR(__FUNCTION__, "%s: Execute command (%s) ret = %d",
                                   __FUNCTION__, cmd, ret);
                }
           }
        }
    }

    return;
}

/*****************************************
* Static Function
*
* ***************************************/
static int mlacp_fill_icc_header(struct CSM* csm, ICCHdr* icc_hdr, size_t msg_len);

/*****************************************
* Sync portchannel state and MAC with kernel
*
* ***************************************/
int mlacp_sync_with_kernel_callback()
{
    struct System* sys = NULL;
    struct CSM* csm = NULL;
    struct LocalInterface* local_if = NULL;

    if((sys = system_get_instance()) == NULL)
    {
        ICCPD_LOG_WARN(__FUNCTION__, "Failed to obtain System instance.");
        goto out;
    }

    /* traverse all CSM */
    LIST_FOREACH(csm, &(sys->csm_list), next)
    {
        /* Sync MLAG po state with kernel*/
        LIST_FOREACH(local_if, &(MLACP(csm).lif_list), mlacp_next)
        {
            if(local_if->type == IF_T_PORT_CHANNEL) 
            {
                /* sync system info from one port-channel device*/
                if(memcmp(MLACP(csm).system_id, local_if->mac_addr, ETHER_ADDR_LEN) != 0)
                {
                	memcpy(MLACP(csm).system_id, local_if->mac_addr, ETHER_ADDR_LEN);
                	MLACP(csm).system_config_changed = 1;

                	update_system_id(csm);

                	break;
                }
            }
        }
    }
    
out:
    return 0;
}


/*****************************************
* Create Sync Request TLV
*
* ***************************************/
int mlacp_prepare_for_sync_request_tlv(struct CSM* csm, char* buf, size_t max_buf_size)
{
    struct System* sys = NULL;
    ICCHdr* icc_hdr = NULL;
    mLACPSyncReqTLV* tlv = NULL;
    size_t msg_len = sizeof(ICCHdr) + sizeof(mLACPSyncReqTLV);
    
    if(csm == NULL)
        return -1;
    
    if(buf == NULL)
        return -1;
    
    if(msg_len > max_buf_size)
        return -1;
    
    if((sys = system_get_instance()) == NULL)
        return -1;
    
    /* Prepare for sync request */
    memset(buf, 0, max_buf_size);
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (mLACPSyncReqTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* mLACP Synchronization Request TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = sizeof(mLACPSyncReqTLV) - sizeof(ICCParameter);
    tlv->icc_parameter.type = TLV_T_MLACP_SYNC_REQUEST;
    
    tlv->req_num = 0;
    MLACP(csm).sync_req_num = tlv->req_num;
    tlv->c_bit = 1;
    tlv->s_bit = 1;
    tlv->req_type = 0x3FFF;
    tlv->port_num_agg_id = 0;
    tlv->actor_key = 0;
    
    return msg_len;
}

/*****************************************
* Prprare Sync Data TLV
*
* ***************************************/
int mlacp_prepare_for_sync_data_tlv(struct CSM* csm, char* buf, size_t max_buf_size, int end)
{
    struct System* sys = NULL;
    ICCHdr* icc_hdr = (ICCHdr*) buf;
    mLACPSyncDataTLV* tlv = (mLACPSyncDataTLV*) &buf[sizeof(ICCHdr)];
    size_t msg_len = sizeof(ICCHdr) + sizeof(mLACPSyncDataTLV);
    
    if(csm == NULL)
        return -1;
    
    if(buf == NULL)
        return -1;
    
    if(msg_len > max_buf_size)
        return -1;
    
    if((sys = system_get_instance()) == NULL)
        return -1;
    
    /* Prepare for sync request */
    memset(buf, 0, max_buf_size);
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (mLACPSyncDataTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* mLACP Synchronization Data TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = sizeof(mLACPSyncDataTLV) - sizeof(ICCParameter);
    tlv->icc_parameter.type = TLV_T_MLACP_SYNC_DATA;
    
    tlv->req_num = MLACP(csm).sync_req_num;
    if(end == 0)
        tlv->flags = 0x00;
    else
        tlv->flags = 0x01;
    
    return msg_len;
}

/*****************************************
* Prprare Sync System-Config TLV
*
* ***************************************/
int mlacp_prepare_for_sys_config(struct CSM* csm,char* buf, size_t max_buf_size)
{
    struct System* sys = NULL;
    ICCHdr* icc_hdr = (ICCHdr*) buf;
    mLACPSysConfigTLV* tlv = (mLACPSysConfigTLV*) &buf[sizeof(ICCHdr)];
    size_t msg_len = sizeof(ICCHdr) + sizeof(mLACPSysConfigTLV);
    
    if(csm == NULL)
        return -1;
    
    if(buf == NULL)
        return -1;
    
    if(msg_len > max_buf_size)
        return -1;
    
    if((sys = system_get_instance()) == NULL)
        return -1;
    
    /* Prepare for sync request */
    memset(buf, 0, max_buf_size);
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (mLACPSysConfigTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* System Config TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = sizeof(mLACPSysConfigTLV) - sizeof(ICCParameter);
    tlv->icc_parameter.type = TLV_T_MLACP_SYSTEM_CONFIG;
    
    memcpy(tlv->sys_id, MLACP(csm).system_id, ETHER_ADDR_LEN);
    tlv->sys_priority = MLACP(csm).system_priority;
    tlv->node_id = MLACP(csm).node_id;
    return msg_len;
}

/*Prprare Sync AggPort-State TLV */
int mlacp_prepare_for_Aggport_state(struct CSM* csm,char* buf, size_t max_buf_size, struct LocalInterface* local_if)
{
    struct System* sys = NULL;
    ICCHdr* icc_hdr = (ICCHdr*) buf;
    mLACPAggPortStateTLV* tlv = (mLACPAggPortStateTLV*) &buf[sizeof(ICCHdr)];
    size_t msg_len = sizeof(ICCHdr) + sizeof(mLACPAggPortStateTLV);
    
    if(csm == NULL)
        return -1;
    
    if(buf == NULL)
        return -1;
    
    if(local_if == NULL)
        return -1;
    
    if(local_if->type != IF_T_PORT_CHANNEL)
        return -1;
    
    if(msg_len > max_buf_size)
        return -1;
    
    if((sys = system_get_instance()) == NULL)
        return -1;
    
    /* Prepare for sync request */
    memset(buf, 0, max_buf_size);
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (mLACPAggPortStateTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* Port State TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = sizeof(mLACPAggPortStateTLV) - sizeof(ICCParameter);
    tlv->icc_parameter.type = TLV_T_MLACP_AGGREGATOR_STATE;
    
    tlv->partner_sys_priority = 0;
    tlv->partner_key = 0;
    tlv->agg_id = local_if->po_id;
    tlv->actor_key = 0;
    tlv->agg_state = local_if->state;
    
    return msg_len;
}

/*****************************************
* Prprare Sync Purge Port
*
* ***************************************/
int mlacp_prepare_for_Aggport_config(struct CSM* csm,
                                 char* buf, size_t max_buf_size,
                                 struct LocalInterface* lif, int purge_flag)
{
    ICCHdr* icc_hdr = (ICCHdr*) buf;
    mLACPAggConfigTLV* tlv = (mLACPAggConfigTLV*) &buf[sizeof(ICCHdr)];
    size_t msg_len = sizeof(ICCHdr) + sizeof(mLACPAggConfigTLV);
    
    if(csm == NULL)
        return -1;
    
    if(buf == NULL)
        return -1;
    
    if(msg_len > max_buf_size)
        return -1;
    
    /* Prepare for sync request */
    memset(buf, 0, max_buf_size);
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (mLACPAggConfigTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* Port Config TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = sizeof(mLACPAggConfigTLV) - sizeof(ICCParameter);
    tlv->icc_parameter.type = TLV_T_MLACP_AGGREGATOR_CONFIG;
    
    tlv->agg_id = lif->po_id;
    if(purge_flag == 1)
    tlv->flags = 0x02; /*purge*/
    else
    tlv->flags = 0x1;
    tlv->agg_name_len = strlen(lif->name);
    memcpy(tlv->agg_name, lif->name, MAX_L_PORT_NAME);
    memcpy(tlv->mac_addr, lif->mac_addr, ETHER_ADDR_LEN);
    
    return msg_len;
}

/*****************************************
* Preprare Sync MAC-Info TLV
* 
* ***************************************/
int mlacp_prepare_for_mac_info_to_peer(struct CSM* csm, char* buf, size_t max_buf_size, struct MACMsg* mac_msg) 
{
    struct mLACPMACInfoTLV* tlv = NULL;
    size_t msg_len = 0;
    size_t tlv_len = 0;
    ICCHdr* icc_hdr = NULL;
    
    if (!csm)
        return -1;
    if (!buf)
        return -1;
    
    tlv_len = sizeof(struct mLACPMACInfoTLV);
    
    if ((msg_len = sizeof(ICCHdr) + tlv_len) > max_buf_size)
        return -1;
    
    /* ICC header */
    memset(buf, 0, max_buf_size);
    icc_hdr = (ICCHdr*) buf;
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* Prepare for ARP information TLV */
    tlv = (struct mLACPMACInfoTLV*) malloc(tlv_len);
    memset(tlv, 0, tlv_len);
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.type = TLV_T_MLACP_MAC_INFO;
    tlv->icc_parameter.len = tlv_len - sizeof(ICCParameter);
    tlv->type = mac_msg->op_type;
    sprintf(tlv->mac_str, "%s", mac_msg->mac_str);
    sprintf(tlv->ifname, "%s", mac_msg->origin_ifname);
    tlv->vid = mac_msg->vid;
    
    /* Fill MAC Information TLV */
    memcpy(&buf[sizeof(ICCHdr)], tlv, tlv_len);
    free(tlv);
    
    #if 1
    ICCPD_LOG_DEBUG(__FUNCTION__, "Prepare Msg type = TLV_T_MLACP_MAC_INFO");
    ICCPD_LOG_DEBUG(__FUNCTION__, "Prepare Msg if name %s  mac  = %s, vid = %d, type = %d", mac_msg->origin_ifname,  mac_msg->mac_str, mac_msg->vid, mac_msg->op_type);
    #endif
    
    return msg_len;
}

/*****************************************
* Preprare Sync ARP-Info TLV
* 
* ***************************************/
int mlacp_prepare_for_arp_info(struct CSM* csm, char* buf, size_t max_buf_size, struct ARPMsg* arp_msg) 
{
    struct mLACPARPInfoTLV* tlv = NULL;
    size_t msg_len = 0;
    size_t tlv_len = 0;
    ICCHdr* icc_hdr = NULL;
    
    if (!csm)
        return -1;
    if (!buf)
        return -1;
    
    tlv_len = sizeof(struct mLACPARPInfoTLV);
    
    if ((msg_len = sizeof(ICCHdr) + tlv_len) > max_buf_size)
        return -1;
    
    /* ICC header */
    memset(buf, 0, max_buf_size);
    icc_hdr = (ICCHdr*) buf;
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* Prepare for ARP information TLV */
    tlv = (struct mLACPARPInfoTLV*) malloc(tlv_len);
    memset(tlv, 0, tlv_len);
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.type = TLV_T_MLACP_ARP_INFO;
    tlv->icc_parameter.len = tlv_len - sizeof(ICCParameter);
    tlv->type = arp_msg->op_type;
    sprintf(tlv->ifname, "%s", arp_msg->ifname);
    tlv->ipv4_addr = arp_msg->ipv4_addr;
    memcpy(tlv->mac_addr, arp_msg->mac_addr, ETHER_ADDR_LEN);
    
    /* Fill ARP Information TLV */
    memcpy(&buf[sizeof(ICCHdr)], tlv, tlv_len);
    free(tlv);
    
    ICCPD_LOG_DEBUG(__FUNCTION__, "Prepare Msg if name %s  msg ifname %s  mac  =%02x:%02x:%02x:%02x:%02x:%02x ", tlv->ifname, arp_msg->ifname,  tlv->mac_addr[0], tlv->mac_addr[1], tlv->mac_addr[2],
            tlv->mac_addr[3], tlv->mac_addr[4], tlv->mac_addr[5]);
    ICCPD_LOG_DEBUG(__FUNCTION__, "    IP Addr = %s ",show_ip_str( tlv->ipv4_addr));
    
    return msg_len;
}

/*****************************************
* Prprare Send portchannel info
*
* ***************************************/
int mlacp_prepare_for_port_channel_info(struct CSM* csm, char* buf,
                                        size_t max_buf_size,
                                        struct LocalInterface* port_channel)
{
    struct System* sys = NULL;
    ICCHdr* icc_hdr = NULL;
    struct mLACPPortChannelInfoTLV* tlv = NULL;
    size_t msg_len;
    size_t tlv_len;    
    size_t name_len = MAX_L_PORT_NAME;
    struct VLAN_ID* vlan_id = NULL;
    int num_of_vlan_id = 0;
    
    if (csm == NULL )
        return -1;
    if (buf == NULL )
        return -1;
    if (port_channel == NULL )
        return -1;
    if (port_channel->type == IF_T_PORT)
        return -1;
    if ((sys = system_get_instance()) == NULL )
        return -1;

    /* Calculate VLAN ID Length */
    LIST_FOREACH(vlan_id, &(port_channel->vlan_list), port_next)
        if (vlan_id != NULL) num_of_vlan_id++;
    
    tlv_len = sizeof(struct mLACPPortChannelInfoTLV) + sizeof(struct VLAN_ID) * num_of_vlan_id;
    
    if ((msg_len = sizeof(ICCHdr) + tlv_len) > max_buf_size)
        return -1;
    
    /* Prepare for port channel info */
    memset(buf, 0, max_buf_size);
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (struct mLACPPortChannelInfoTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* Port Channel Info TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = sizeof(struct mLACPPortChannelInfoTLV) - sizeof(ICCParameter) + sizeof(struct VLAN_ID) *num_of_vlan_id ;
    tlv->icc_parameter.type = TLV_T_MLACP_PORT_CHANNEL_INFO;
    tlv->agg_id = port_channel->po_id;
    tlv->ipv4_addr = htonl(port_channel->ipv4_addr);
    tlv->l3_mode = port_channel->l3_mode;
    tlv->po_id = port_channel->po_id;

    if(strlen(port_channel->name) < name_len)
        name_len = strlen(port_channel->name);
    memcpy(tlv->if_name, port_channel->name, name_len);
    tlv->if_name_len = name_len;
    tlv->num_of_vlan_id = num_of_vlan_id;
    
    num_of_vlan_id = 0;
    LIST_FOREACH(vlan_id, &(port_channel->vlan_list), port_next)
    {
        if (vlan_id != NULL ) 
        {
            tlv->vlanData[num_of_vlan_id].vlan_id = vlan_id->vid;
                
            num_of_vlan_id++;
            ICCPD_LOG_DEBUG(__FUNCTION__, "  port channel %d: addr = %s vlan id %d     num %d ", port_channel->po_id, show_ip_str( tlv->ipv4_addr), vlan_id->vid, num_of_vlan_id );
        }
    }   

    ICCPD_LOG_DEBUG(__FUNCTION__, "  port channel %d: addr = 0x%08x l3 mode %d", port_channel->po_id, tlv->ipv4_addr,  tlv->l3_mode);
    
    return msg_len;
}

/*****************************************
* Prprare Send port peerlink  info
*
* ***************************************/
int mlacp_prepare_for_port_peerlink_info(struct CSM* csm, char* buf,
                                        size_t max_buf_size,
                                        struct LocalInterface* peerlink_port)
{
    struct System* sys = NULL;
    ICCHdr* icc_hdr = NULL;
    struct mLACPPeerLinkInfoTLV* tlv = NULL;
    size_t msg_len;
    size_t tlv_len;    
    
    if (csm == NULL )
        return -1;
    if (buf == NULL )
        return -1;
    if (peerlink_port == NULL )
        return -1;
    if ((sys = system_get_instance()) == NULL )
        return -1;
    
    /* Prepare for port channel info */
    memset(buf, 0, max_buf_size);
    
    tlv_len = sizeof(struct mLACPPeerLinkInfoTLV);    
    
    if ((msg_len = sizeof(ICCHdr) + tlv_len) > max_buf_size)
        return -1;
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (struct mLACPPeerLinkInfoTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* Port Channel Info TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = tlv_len - sizeof(ICCParameter) ;
    tlv->icc_parameter.type = TLV_T_MLACP_PEERLINK_INFO;

    memcpy(tlv->if_name, peerlink_port->name, MAX_L_PORT_NAME);
    tlv->port_type = peerlink_port->type;
  

    ICCPD_LOG_DEBUG(__FUNCTION__, "  peerlink port info  portname %s  type  = %d", tlv->if_name, tlv->port_type);
    
    return msg_len;
}


/*****************************************
* Prprare Send Heartbeat
*
* ***************************************/
int mlacp_prepare_for_heartbeat(struct CSM* csm,char* buf, size_t max_buf_size)
{
    struct System* sys = NULL;
    ICCHdr* icc_hdr = (ICCHdr*) buf;
    struct mLACPHeartbeatTLV* tlv = (struct mLACPHeartbeatTLV*) &buf[sizeof(ICCHdr)];
    size_t msg_len = sizeof(ICCHdr) + sizeof(struct mLACPHeartbeatTLV);
    
    if(csm == NULL)
        return -1;
    
    if(buf == NULL)
        return -1;
    
    if(msg_len > max_buf_size)
        return -1;
    
    if((sys = system_get_instance()) == NULL)
        return -1;
    
    /* Prepare for sync request */
    memset(buf, 0, max_buf_size);
    
    icc_hdr = (ICCHdr*) buf;
    tlv = (struct mLACPHeartbeatTLV*) &buf[sizeof(ICCHdr)];
    
    /* ICC header */
    mlacp_fill_icc_header(csm, icc_hdr, msg_len);
    
    /* System Config TLV */
    tlv->icc_parameter.u_bit = 0;
    tlv->icc_parameter.f_bit = 0;
    tlv->icc_parameter.len = sizeof(struct mLACPHeartbeatTLV) - sizeof(ICCParameter);
    tlv->icc_parameter.type = TLV_T_MLACP_HEARTBEAT;
    
    tlv->heartbeat = 0xFF;
    return msg_len;
}

/*****************************************
* Tool : Prepare ICC Header
*
* ***************************************/
static int mlacp_fill_icc_header(struct CSM* csm, ICCHdr* icc_hdr, size_t msg_len)
{
    if(csm == NULL || icc_hdr == NULL)
        return -1;
    
    /* ICC header */
    icc_hdr->ldp_hdr.u_bit = 0x0;
    icc_hdr->ldp_hdr.msg_type = MSG_T_RG_APP_DATA;
    icc_hdr->ldp_hdr.msg_len = msg_len - MSG_L_INCLUD_U_BIT_MSG_T_L_FIELDS;
    icc_hdr->ldp_hdr.msg_id = ICCP_MSG_ID;
    ICCP_MSG_ID++;
    iccp_csm_fill_icc_rg_id_tlv(csm, icc_hdr);
    
    return 0;
}


/*****************************************
* Tool : Update System ID
* 
* ***************************************/
void iccp_set_portchannel_ipadd_mac(struct LocalInterface *lif,uint8_t * mac_addr )
{
    struct IccpSyncdHDr * msg_hdr;
    mclag_sub_option_hdr_t * sub_msg;
    char msg_buf[4096];
    struct System *sys;

    int src_len = 0,dst_len =0;
    sys = system_get_instance();
    if(sys == NULL)
    return;
    
    memset(msg_buf,0,4095);
    
    msg_hdr = (struct IccpSyncdHDr *)msg_buf;
    msg_hdr->ver= 1;
    msg_hdr->type = MCLAG_MSG_TYPE_SET_MAC;
    msg_hdr->len = sizeof(struct IccpSyncdHDr);

    /*sub msg src*/
    sub_msg = (mclag_sub_option_hdr_t *)&msg_buf[msg_hdr->len];
    sub_msg->op_type = MCLAG_SUB_OPTION_TYPE_SET_MAC_SRC;

    src_len = snprintf(sub_msg->data, 512, "%s:%s/%d", lif->name,show_ip_str(htonl(lif->ipv4_addr)),lif->prefixlen);

    sub_msg->op_len = src_len;

    /*sub msg dst */
    msg_hdr->len += sub_msg->op_len;
    msg_hdr->len += sizeof(mclag_sub_option_hdr_t);    
    sub_msg = (mclag_sub_option_hdr_t  *)&msg_buf[msg_hdr->len];
    sub_msg->op_type = MCLAG_SUB_OPTION_TYPE_SET_MAC_DST;
    
    dst_len = strlen(mac_addr);  
    memcpy(sub_msg->data, mac_addr, dst_len);	

    ICCPD_LOG_DEBUG(__FUNCTION__,"lif name %s    address %s mac    msg data %s  %d \n", lif->name , show_ip_str(lif->ipv4_addr), sub_msg->data  ,dst_len);

    sub_msg->op_len = dst_len;
    msg_hdr->len += sizeof(mclag_sub_option_hdr_t);    
    msg_hdr->len += sub_msg->op_len;	

    /*send msg*/
    if(sys->sync_fd)
        write(sys->sync_fd,msg_buf, msg_hdr->len);	

    return;    
}


