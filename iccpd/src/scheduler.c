/*
* scheduler.c
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

#include <unistd.h>
#include <pthread.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "../include/logger.h"
#include "../include/system.h"
#include "../include/scheduler.h"
#include "../include/iccp_csm.h"


/******************************************************
 *
 *    Global Variable
 *
 ******************************************************/

static int session_conn_thread_lock(pthread_mutex_t *conn_mutex)
{
    return 1; /*pthread_mutex_lock(conn_mutex);*/
}

static int session_conn_thread_trylock(pthread_mutex_t *conn_mutex)
{
    return 0 ;/*pthread_mutex_trylock(conn_mutex);*/
}

static int session_conn_thread_unlock(pthread_mutex_t *conn_mutex)
{
    return 1;/* pthread_mutex_unlock(conn_mutex);*/
}

static void heartbeat_check(struct CSM *csm)
{
    if (csm->heartbeat_update_time == 0) 
    {
        time(&csm->heartbeat_update_time);
        return;
    }
    
    if( (time(NULL) - csm->heartbeat_update_time) > HEARTBEAT_TIMEOUT_SEC)
    {
        /* hearbeat timeout*/
        ICCPD_LOG_INFO(__FUNCTION__, "iccpd connection timeout (heartbeat)");
        scheduler_session_disconnect_handler(csm);
    }

    return;
}

static void heartbeat_update(struct CSM *csm)
{
    if(csm->sock_fd > 0) 
    {
        heartbeat_check(csm);
    }

    return;
}

/* Transit FSM of all connections */
static int scheduler_transit_fsm()
{
    struct CSM* csm = NULL;
    struct System* sys = NULL;
    
    if ((sys = system_get_instance()) == NULL)
        return -1;
    
    LIST_FOREACH(csm, &(sys->csm_list), next)
    {
        heartbeat_update(csm);
        iccp_csm_transit(csm);
        app_csm_transit(csm);
        mlacp_fsm_transit(csm);

        if (MLACP(csm).current_state == MLACP_STATE_EXCHANGE && (time(NULL) - sys->csm_trans_time) >= 60)
        {   	 
            iccp_get_fdb_change_from_syncd();
            sys->csm_trans_time = time(NULL);
        }
    }
    
    local_if_change_flag_clear();
    local_if_purge_clear();
    
    return 1;
}

/* Receive packets call back function */
int scheduler_csm_read_callback(struct CSM* csm) 
{
    struct Msg* msg = NULL;    
    /*peer message*/
    char *peer_msg = g_csm_buf;
    LDPHdr* ldp_hdr = (LDPHdr*)peer_msg;
    char* data = &peer_msg[sizeof(LDPHdr)];
    size_t data_len = 0;
    size_t pos = 0;
    int recv_len=0, len=0, retval;
    
    if (csm->sock_fd <= 0)
        return -1;
    
    memset(peer_msg, 0, CSM_BUFFER_SIZE);
    
    recv_len = 0;
    while(recv_len != sizeof(LDPHdr))
    {
        len = recv(csm->sock_fd, peer_msg+recv_len, sizeof(LDPHdr)-recv_len, 0);
        if (len == -1)
        {
            perror("recv(). Error");
            goto recv_err;
        }
        else if (len == 0)
        {
            ICCPD_LOG_INFO(__FUNCTION__, "Peer disconnect");
            goto recv_err;
        }
        recv_len += len;
        /*usleep(100);*/
    }
    
    data_len = ldp_hdr->msg_len - MSG_L_INCLUD_U_BIT_MSG_T_L_FIELDS;
    pos = 0;
    while(data_len > 0)
    {
        recv_len = recv(csm->sock_fd, &data[pos], data_len, 0);
        if (recv_len == -1) {
            perror("continue recv(). Error");
            goto recv_err;
        } 
        else if (recv_len == 0) 
        {
            ICCPD_LOG_INFO(__FUNCTION__, "Peer disconnect");
            goto recv_err;
        }
        data_len -= recv_len;
        pos += recv_len;
        /*usleep(100);*/
    }
    
    retval = iccp_csm_init_msg(&msg, peer_msg, ldp_hdr->msg_len + MSG_L_INCLUD_U_BIT_MSG_T_L_FIELDS);
    if (retval == 0) 
    {
        iccp_csm_enqueue_msg(csm, msg);
        ++csm->icc_msg_in_count;
    } 
    else
        ++csm->i_msg_in_count;
    
    return 1;
    
recv_err:
    scheduler_session_disconnect_handler(csm);
    return -1;
}

/* Handle server accept client */
int scheduler_server_accept()
{
    int new_fd;
    int ret = -1;
    struct CSM* csm = NULL;
    struct System* sys = NULL;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    
    if ((sys = system_get_instance()) == NULL ) 
    {
        return -1;
    }
    if(sys->server_fd <= 0) 
    {
        return -1;
    }
    
    addr_len = sizeof(struct sockaddr_in);
    new_fd = accept(sys->server_fd, (struct sockaddr *) &client_addr, &addr_len);
    if (new_fd == -1) 
    {
        goto reject_client;
    }
    else 
    {
        csm = system_get_csm_by_peer_ip(inet_ntoa(client_addr.sin_addr));
        if(!csm) 
        {
            /* can't find csm with peer ip*/
            ICCPD_LOG_INFO(__FUNCTION__, "csm null with peer ip [%s]", inet_ntoa(client_addr.sin_addr));
            goto reject_client;
        }
        
        if(csm->sock_fd > 0) 
        {
            /* peer already connected*/
            ICCPD_LOG_INFO(__FUNCTION__, "csm sock is connected with peer ip [%s]", inet_ntoa(client_addr.sin_addr));
            goto reject_client;
        }
        
        if((ret = scheduler_check_csm_config(csm)) < 0) 
        {
            /* csm config error*/
            ICCPD_LOG_INFO(__FUNCTION__, "csm config error with peer ip [%s]", inet_ntoa(client_addr.sin_addr));
            goto reject_client;
        }
    }
    
    /* Accept*/
    goto accept_client;
    
reject_client:
    if(new_fd >= 0) close(new_fd);
    return -1;

accept_client:
    session_conn_thread_lock(&csm->conn_mutex);
    ICCPD_LOG_INFO(__FUNCTION__, "Server Accept, SocketFD [%d], %p", new_fd, csm);    
    
    struct epoll_event event;
    int err;
    event.data.fd = new_fd;
    event.events = EPOLLIN;
    err = epoll_ctl(sys->epoll_fd, EPOLL_CTL_ADD, new_fd, &event);	
    if(err)
    {
        session_conn_thread_unlock(&csm->conn_mutex);
        goto reject_client;    
    }
    
    csm->sock_fd = new_fd;
    csm->current_state = ICCP_NONEXISTENT;
    FD_SET(new_fd, &(sys->readfd)); 
    sys->readfd_count ++;
    session_conn_thread_unlock(&csm->conn_mutex);
    return 0;
}

/* scheduler initialization */
void scheduler_init()
{
    struct System* sys = NULL;

    if (!(sys = system_get_instance()))
        return;
	
    /*Get kernel interface and port */
    iccp_sys_local_if_list_get_init();

    /*Get kernel vlan info */
    iccp_get_if_vlan_info_from_netlink();  
    iccp_sys_local_if_list_get_addr();

    /*Interfaces must be created before this func called*/
    iccp_config_from_file(sys->config_file_path);

    /*Get kernel ARP info */
    iccp_arp_get_init();
    
    if(iccp_connect_syncd() < 0) 
    {
        ICCPD_LOG_DEBUG(__FUNCTION__, "%s:%d, syncd info socket connect fail",
                        __FUNCTION__, __LINE__);
    }
    else
    {
        ICCPD_LOG_DEBUG(__FUNCTION__, "%s:%d, syncd info socket connect success",
                        __FUNCTION__, __LINE__);
    }

    if (mclagd_ctl_sock_create() < 0)
    {
            ICCPD_LOG_DEBUG(__FUNCTION__, "%s:%d, mclagd ctl info socket connect fail",
                        __FUNCTION__, __LINE__);
    }
    
    return;
}

/* Thread fetch to call */
void scheduler_loop()
{
    struct System* sys = NULL;	
    int result;

    if ((sys = system_get_instance()) == NULL)
        return;
	 
    while(1)
    {          
        if(sys->sync_fd <= 0)
        {
            iccp_connect_syncd();
        }

        /*handle socket slelect event ,If no message received, it will block 0.1s*/
        iccp_handle_events(sys);
        /*csm, app state machine transit */
        scheduler_transit_fsm();		
        /*get netlink info again when error happens */
        iccp_netlink_sync_again();
    }

    return;
}

/* Scheduler start while loop */
void scheduler_start() 
{
    mlacp_sync_with_kernel_callback();
    
    scheduler_loop();

    return;
}

/* Scheduler tear down */
void scheduler_finalize() {
    struct System* sys = NULL;

    if ((sys = system_get_instance()) == NULL)
        return;
    
    syncd_info_close();

    log_finalize();

    ICCPD_LOG_INFO(__FUNCTION__, "Scheduler is terminated.");

    return;
}

void* session_client_conn_handler(struct CSM *csm)
{
    struct System* sys = NULL;
    struct sockaddr_in peer_addr;
    int connFd=-1, connStat=-1;
    struct timeval con_tv;
    socklen_t len = sizeof(con_tv);
    
    /* Lock the thread*/
    session_conn_thread_lock(&csm->conn_mutex);
    
    sys = system_get_instance();
    if(!sys)
        goto conn_fail;
    
    /* Create sock*/
    connFd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&peer_addr, sizeof(peer_addr));
    peer_addr.sin_family = PF_INET;
    peer_addr.sin_port = htons(ICCP_TCP_PORT);
    peer_addr.sin_addr.s_addr = inet_addr(csm->peer_ip);
    if (connFd == -1) 
    {
        ICCPD_LOG_DEBUG(__FUNCTION__, "Peer IP:%s Socket FD creation failed.",
                        csm->peer_ip);
        goto conn_fail;
    }
 
    /* Set connect timeout secs*/
    con_tv.tv_sec = 0;
    con_tv.tv_usec = CONNECT_TIMEOUT_MSEC*1000;
    if (setsockopt(connFd, SOL_SOCKET, SO_SNDTIMEO, &con_tv, len) == -1) 
    {
        ICCPD_LOG_INFO(__FUNCTION__, "Set socket timeout fail");
    }
    
    /* Try conn*/
    ICCPD_LOG_INFO(__FUNCTION__, "Connecting. peer ip = [%s], %p", csm->peer_ip, csm);
    connStat = connect(connFd, (struct sockaddr*) &(peer_addr), sizeof(peer_addr));
    ICCPD_LOG_INFO(__FUNCTION__, "Connection. fd = [%d], status = [%d], %p",
                   connFd, connStat, csm);
    
    if (connStat != 0)
    {
        /* Conn Fail*/
        goto conn_fail;
    }
    else
    {
        /* Conn OK*/
        struct epoll_event event;
        int err;
        event.data.fd = connFd;
        event.events = EPOLLIN;
        err = epoll_ctl(sys->epoll_fd, EPOLL_CTL_ADD, connFd, &event);	
        if(err)
        goto conn_fail;
        csm->sock_fd = connFd;
        FD_SET(connFd, &(sys->readfd));
        sys->readfd_count++;
        ICCPD_LOG_INFO(__FUNCTION__, "Connect to server %s sucess .", csm->peer_ip);
        goto conn_ok;
    }

conn_fail:
    if(connFd >= 0) 
    {
        csm->sock_fd = -1;
        close(connFd);
    }
conn_ok:
    time(&csm->connTimePrev);
    session_conn_thread_unlock(&csm->conn_mutex);
    return;
}

/* Create socket connect to peer */
int scheduler_prepare_session(struct CSM* csm)
{
    int ret = -1;
    uint32_t local_ip = 0;
    uint32_t peer_ip = 0;
    
    /* Init time_t*/
    if (csm->connTimePrev == 0) 
    {
        time(&csm->connTimePrev);
    }
    
    /* Don't conn to svr continously*/
    if((time(NULL) - csm->connTimePrev) < CONNECT_INTERVAL_SEC) 
    {
        goto no_time_update;
    }
    
    /* Already conn?*/
    if(csm->sock_fd > 0) 
    {
        goto time_update;
    }
    
    if ((ret = scheduler_check_csm_config(csm)) < 0)
        goto time_update;
    
    /* Who is client*/
    local_ip = inet_addr(csm->sender_ip);
    peer_ip = inet_addr(csm->peer_ip);
    if(local_ip > peer_ip) 
    {
        goto time_update;
    }
    else if(local_ip == peer_ip) 
    {
        ICCPD_LOG_WARN("connect",
                       "Sender IP is as the same as the peer IP. "
                       "This must be fixed before connection is built.");
        goto time_update;
    }
    
    if(session_conn_thread_trylock(&csm->conn_mutex) == 0) 
    {
        session_client_conn_handler(csm);
        session_conn_thread_unlock(&csm->conn_mutex);
    }

time_update:
    time(&csm->connTimePrev);
    return 0;
    
no_time_update:
    return 0;
}

/* Server socket initialization */
void scheduler_server_sock_init()
{
    int optval = 1;
    struct System* sys = NULL;
    struct sockaddr_in svr_addr;
    
    if ((sys = system_get_instance()) == NULL)
        return;
    
    sys->server_fd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&(svr_addr), sizeof(svr_addr));
    svr_addr.sin_family = PF_INET;
    svr_addr.sin_port = htons(ICCP_TCP_PORT);
    svr_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (sys->server_fd == -1) 
    {
        ICCPD_LOG_ERR(__FUNCTION__, "Server Socket FD creation failed.");
        return;
    }
    
    if (setsockopt(sys->server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1)
    {
        ICCPD_LOG_INFO(__FUNCTION__,"Set socket option failed. Error");
        /*return;*/
    }
    
    /* set_nonblocking(sys->server_fd);*/

    if (bind(sys->server_fd, (struct sockaddr*) &(svr_addr), sizeof(svr_addr)) < 0) 
    {
        ICCPD_LOG_INFO(__FUNCTION__,"Bind socket failed. Error");
        return;
    }
    
    if (listen(sys->server_fd, MAX_ACCEPT_CONNETIONS) == -1) 
    {
        ICCPD_LOG_INFO(__FUNCTION__,"Listen failed. Error");
        return;
    }
    
    ICCPD_LOG_INFO(__FUNCTION__, "Server socket init done.");

    return;
}

int iccp_get_server_sock_fd()
{
    struct System* sys = NULL;
    
    if ((sys = system_get_instance()) == NULL)
        return 0;

    return sys->server_fd;
}

/* Server socket initialization */
int scheduler_check_csm_config(struct CSM* csm)
{
    int ret = 1;
    struct LocalInterface* lif = NULL;
    struct System* sys = NULL;
    
    if((sys = system_get_instance()) == NULL)
        return -1;
    
    if (csm == NULL )
        return -1;
    
    if(csm->mlag_id <= 0)
        ret = -1;
    else if (strlen(csm->peer_itf_name) <= 0)
        ret = -1;
    else if (strlen(csm->peer_ip) <= 0)
        ret = -1;
    else if (strlen(csm->sender_ip) <= 0)
        ret = -1;
    else if ((lif=local_if_find_by_name(csm->peer_itf_name)) == NULL)
        ret = -1;    
    else
    {
        lif->is_peer_link = 1;
        csm->peer_link_if = lif;
    }
	
    if(ret == -1)
    ICCPD_LOG_INFO(__FUNCTION__, "mclag config is not complete or conflicting, please check!");	
    /* Decide STP role*/
    iccp_csm_stp_role_count(csm);
        
    return ret;        
}

int scheduler_unregister_sock_read_event_callback(struct CSM* csm) 
{
    struct System* sys = NULL;
    
    if ((sys = system_get_instance()) == NULL )
        return -1;
    
    if (csm == NULL ) 
    {
        return -2;
    }

    FD_CLR(csm->sock_fd, &(sys->readfd));
	
    return 0;
}

void scheduler_session_disconnect_handler(struct CSM* csm)
{
    struct System* sys = NULL;
    
    if ((sys = system_get_instance()) == NULL )
        return ;

    struct epoll_event event;  
    
    if (csm == NULL)
        return ;
    
    session_conn_thread_lock(&csm->conn_mutex);
    scheduler_unregister_sock_read_event_callback(csm);
    if(csm->sock_fd > 0)
    {
        event.data.fd = csm->sock_fd;
        event.events = EPOLLIN;
        epoll_ctl(sys->epoll_fd, EPOLL_CTL_DEL, csm->sock_fd, &event);
        
        close(csm->sock_fd);
        csm->sock_fd = -1;
    }

    mlacp_peerlink_disconn_handler(csm);
    MLACP(csm).current_state = MLACP_STATE_INIT;
    iccp_csm_status_reset(csm, 0);
    time(&csm->connTimePrev);
    session_conn_thread_unlock(&csm->conn_mutex);
    
    return;
}
