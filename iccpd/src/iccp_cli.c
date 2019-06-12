/*
* iccp_cli.c
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

#include <stdint.h>

#include "../include/system.h"
#include "../include/logger.h"
#include "../include/mlacp_link_handler.h"

/*
* 'id <1-65535>' command
*/
int set_mc_lag_id( struct CSM *csm, uint16_t id)
{
    if (!csm) return -1;
    
    ICCPD_LOG_INFO(__FUNCTION__, "Set mlag-id : %d", id);
    
    /* Mlag-ID, RG-ID, MLACP-ID
     Temporary let the three id be the same*/
    csm->mlag_id = id;
    csm->iccp_info.icc_rg_id = id;
    csm->app_csm.mlacp.id = id;
    return 0;
}

int unset_mc_lag_id( struct CSM *csm, uint16_t id)
{
    if (!csm) return -1;
    
    /* Mlag-ID, RG-ID, MLACP-ID*/
    csm->mlag_id = 0;
    csm->iccp_info.icc_rg_id = 0;
    csm->app_csm.mlacp.id = 0;
    
    iccp_csm_finalize(csm);
    
    return 0;
}

/*
* 'peer-link WORD' command
*/
int set_peer_link(int mid, const char* ifname)
{
    struct CSM* csm = NULL;
    struct LocalInterface *lif = NULL;
    size_t len = 0;

    len = strlen(ifname);

    if (strncmp(ifname, "Eth", 3) != 0 && strncmp(ifname, "Por", 3) != 0)
    {
        ICCPD_LOG_ERR(__FUNCTION__, "Peer-link is %s, must be Ethernet or PortChannel", ifname);
        return -1;
    }
    
    csm = system_get_csm_by_mlacp_id(mid);
    if(csm == NULL) return -1;

    if (len > IFNAMSIZ) return -1;
    
    if (strlen(csm->peer_itf_name) > 0) 
    {
        if(strcmp(csm->peer_itf_name, ifname) == 0) 
        {
            ICCPD_LOG_INFO(__FUNCTION__, "Peer-link not be changed");
            return 0;
        }
        else 
        {
            ICCPD_LOG_INFO(__FUNCTION__, "Change peer-link : %s -> %s",
                    csm->peer_itf_name, ifname);
            
            scheduler_session_disconnect_handler(csm);
            
            if(csm->peer_link_if)
            {
                csm->peer_link_if->is_peer_link = 0;
                csm->peer_link_if = NULL;
            }
        }
    }
    else 
    {
        ICCPD_LOG_INFO(__FUNCTION__, "Set mlag %d peer-link : %s",
                       csm->mlag_id,ifname);
    }
    
    memset(csm->peer_itf_name, 0, IFNAMSIZ);
    memcpy(csm->peer_itf_name, ifname, len);
    
    /* update peer-link link handler*/
    lif = local_if_find_by_name(csm->peer_itf_name);
    if (lif) 
    {
        csm->peer_link_if = lif;
        lif->is_peer_link = 1;        
        MLACP(csm).system_config_changed = 1;
        
        if(lif->type == IF_T_PORT_CHANNEL)
            iccp_get_port_member_list(lif);
    }
    
    return 0;
}

int unset_peer_link(int mid)
{
    struct CSM* csm = NULL;

    csm = system_get_csm_by_mlacp_id(mid);
    if(csm == NULL) return -1;    

    if(MLACP(csm).current_state == MLACP_STATE_EXCHANGE)
    {
        /*must be enabled mac learn*/
        set_peerlink_mlag_port_learn(csm->peer_link_if, 1);
    }

    /* Clean all port block*/
    peerlink_port_isolate_cleanup(csm);
    
    /* update peer-link link handler*/
    scheduler_session_disconnect_handler(csm);
    
    /* clean peer-link*/
    memset(csm->peer_itf_name, 0, IFNAMSIZ);
    if(csm->peer_link_if)
    {
        csm->peer_link_if->is_peer_link = 0;
        csm->peer_link_if = NULL;
        MLACP(csm).system_config_changed = 1;
    }
    
    return 0;
}

/*
* 'local ip address A.B.C.D' command
*/
int set_local_address(int mid, const char* addr)
{
    struct CSM* csm = NULL;
    size_t len = 0;
    
    csm = system_get_csm_by_mlacp_id(mid);
    if(csm == NULL) return -1;
    if (addr == NULL) return -1;
    
    if (strlen(csm->sender_ip) > 0) {
        if (strcmp(csm->sender_ip, addr) == 0) {
            ICCPD_LOG_INFO(__FUNCTION__, "Local-address not be changed");
            return 0;
        }
        else {
            ICCPD_LOG_INFO(__FUNCTION__, "Change local-address : %s -> %s", 
                    csm->sender_ip, addr);
            scheduler_session_disconnect_handler(csm);
        }
    }
    else {
        ICCPD_LOG_INFO(__FUNCTION__, "Set local-address : %s", addr);
    }
    
    len = strlen(addr);
    memset(csm->sender_ip, 0, INET_ADDRSTRLEN);
    memcpy(csm->sender_ip, addr, len);
    memset(csm->iccp_info.sender_name, 0, INET_ADDRSTRLEN);
    memcpy(csm->iccp_info.sender_name, addr, len);
    
    return 0;
}

int unset_local_address(int mid)
{
    struct CSM* csm = NULL;
    
    csm = system_get_csm_by_mlacp_id(mid);
    if(csm == NULL) return -1;

    memset(csm->sender_ip, 0, INET_ADDRSTRLEN);
    memset(csm->iccp_info.sender_name, 0, INET_ADDRSTRLEN);
    
    /* reset link*/
    scheduler_session_disconnect_handler(csm);
    
    return 0;
}

/*
* 'peer-address A.B.C.D' command
*/
int set_peer_address(int mid, const char* addr)
{
    struct CSM* csm = NULL;
    size_t len = 0;
    
    csm = system_get_csm_by_mlacp_id(mid);
    if(csm == NULL) return -1;
    if(addr == NULL) return -1;
    
    len = strlen(addr);
    
    if (strlen(csm->peer_ip) > 0) 
    {
        if(strcmp(csm->peer_ip, addr) == 0) 
        {
            ICCPD_LOG_INFO(__FUNCTION__, "Peer-address not be changed");
            return 0;
        }
        else 
        {
            ICCPD_LOG_INFO(__FUNCTION__, "Change peer-address : %s -> %s", 
                    csm->peer_ip, addr);
            scheduler_session_disconnect_handler(csm);
        }
    }
    else 
    {
        ICCPD_LOG_INFO(__FUNCTION__, "Set peer-address : %s", addr);
    }
    
    memset(csm->peer_ip, 0, INET_ADDRSTRLEN);
    memcpy(csm->peer_ip, addr, len);
    
    return 0;
}

int unset_peer_address(int mid)
{
    struct CSM* csm = NULL;
    
    csm = system_get_csm_by_mlacp_id(mid);
    if(csm == NULL) return -1;
    
    memset(csm->peer_ip, 0, INET_ADDRSTRLEN);
    
    /* reset link*/
    scheduler_session_disconnect_handler(csm);
    
    return 0;
}

int iccp_cli_attach_mclag_domain_to_port_channel( int domain, const char* ifname)
{
    struct CSM* csm = NULL;
    int i = 0;
    int id = 0;
    int len = 0;
    struct LocalInterface *lif = NULL;
    struct If_info * cif = NULL;
    
    if (!ifname)
        return -1;
    
    if(strncmp(ifname, "Po", 2)!=0) {
        ICCPD_LOG_DEBUG(__FUNCTION__,
                        "attach interface(%s) is not a port-channel", ifname);
        return -1;
    }
    
    csm = system_get_csm_by_mlacp_id(domain);
    if (csm == NULL) {
        ICCPD_LOG_DEBUG(__FUNCTION__, "MC-LAG ID %d doesn't exist", domain);
        return -1;
    }
    
    lif = local_if_find_by_name(ifname);
    if (lif) 
    {
    	mlacp_bind_port_channel_to_csm(csm, ifname);
    }
	
    LIST_FOREACH(cif, &(csm->if_bind_list), csm_next)
    {
        if (strcmp(cif->name,ifname) ==0)
        break;
    }
    
    if(cif == NULL)
    {
        cif = (struct If_info *) malloc(sizeof(struct If_info));
        if (!cif)
        return -1;
        
        snprintf(cif->name, MAX_L_PORT_NAME, "%s", ifname);
        LIST_INSERT_HEAD(&(csm->if_bind_list), cif, csm_next);
    }
	
    return 0;
}

int iccp_cli_detach_mclag_domain_to_port_channel( const char* ifname)
{
    int unbind_poid = -1;
    struct CSM *csm = NULL;
    struct LocalInterface *lif_po = NULL;
    struct LocalInterface *lif = NULL;
    struct If_info * cif = NULL;  
	
    if (!ifname)
        return -1;
    
    if (strncmp(ifname, "Po", 2)!=0) {
        ICCPD_LOG_DEBUG(__FUNCTION__,
                        "detach interface(%s) is not a port-channel",  ifname);
        return -1;
    }
    
    /* find po*/
    if (!(lif_po = local_if_find_by_name(ifname))
        || lif_po->type != IF_T_PORT_CHANNEL
        || lif_po->po_id <=0
        || lif_po->csm == NULL)
    {
        return -1;
    }
    
    /* find csm*/
    csm = lif_po->csm;
    
    ICCPD_LOG_DEBUG(__FUNCTION__, "detach mclag id = %d from ifname = %s", 
                    csm->mlag_id, lif_po->name);
    
    /* process link state handler before detaching it.*/
    mlacp_mlag_link_del_handler(csm, lif_po);
    
    unbind_poid = lif_po->po_id;
    mlacp_unbind_local_if(lif_po);
    LIST_FOREACH(lif, &(csm->app_csm.mlacp.lif_list), mlacp_next)
    {
        if (lif->type == IF_T_PORT && lif->po_id == unbind_poid)
            mlacp_unbind_local_if(lif);
    }
	
    LIST_FOREACH(cif, &(csm->if_bind_list), csm_next)
    {
        if (strcmp(ifname, cif->name) ==0)
        LIST_REMOVE(cif, csm_next);
    }    
    return 0;
}
