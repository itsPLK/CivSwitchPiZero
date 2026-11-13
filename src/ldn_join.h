/* Experimental Linux station join. Included after the nl80211 helpers.
 * Authentication layout follows esp32-ldn-civ7/main/main.c. */
#include <openssl/rand.h>
#include <openssl/hmac.h>
static unsigned char join_frame[1388], join_body[1280];
static unsigned int join_frequency;
static bool join_ready;

static bool ldn_session_key(unsigned char key[16]) {
    const unsigned char source[16]={0xf1,0xe7,0x01,0x84,0x19,0xa8,0x4f,0x71,0x1d,0xa7,0x14,0xc2,0xcf,0x91,0x9c,0x9c};
    const unsigned char pass[22]={0xcb,0x96,0x44,0x87,0xb4,0x49,0xf4,0x20,0x8b,0x1e,0xab,0xee,0x6e,0x92,0x7f,0x89,0x47,0xfa,0xd3,0xd8,0x8c,0x37};
    unsigned char a[16],b[16],data[38],digest[32]; unsigned int n;
    memcpy(data,join_body,16);memcpy(data+16,pass,22);
    bool ok=ldn_cipher(EVP_aes_128_ecb(),ldn_keys[0],NULL,ldn_keys[1],16,a)&&
        ldn_cipher(EVP_aes_128_ecb(),a,NULL,source,16,b)&&
        ldn_cipher(EVP_aes_128_ecb(),b,NULL,ldn_keys[2],16,a)&&
        EVP_Digest(data,sizeof(data),digest,&n,EVP_sha256(),NULL)==1&&
        ldn_cipher(EVP_aes_128_ecb(),a,NULL,digest,16,key);
    OPENSSL_cleanse(a,sizeof(a));OPENSSL_cleanse(b,sizeof(b));
    OPENSSL_cleanse(data,sizeof(data));OPENSSL_cleanse(digest,sizeof(digest));return ok;
}
static int ldn_install_key(int family,unsigned int index,const unsigned char key[16],bool pairwise) {
    unsigned char attrs[128]={0},slot=pairwise?0:1,seq[6]={0};
    unsigned int cipher=0x000fac04;
    size_t n=radio_attr(attrs,0,NL80211_ATTR_IFINDEX,&index,4);
    n=radio_attr(attrs,n,NL80211_ATTR_KEY_IDX,&slot,1);
    n=radio_attr(attrs,n,NL80211_ATTR_KEY_CIPHER,&cipher,4);
    n=radio_attr(attrs,n,NL80211_ATTR_KEY_DATA,key,16);
    n=radio_attr(attrs,n,NL80211_ATTR_KEY_SEQ,seq,6);
    if(pairwise)n=radio_attr(attrs,n,NL80211_ATTR_MAC,join_frame+10,6);
    int r=radio_request(family,NL80211_CMD_NEW_KEY,attrs,n,false);
    OPENSSL_cleanse(attrs,sizeof(attrs));return r;
}
static bool ldn_auth_exchange(unsigned int index,const unsigned char local[6],int ctl) {
    const unsigned char hkey[32]={0xf8,0x4b,0x48,0x7f,0xb3,0x72,0x51,0xc2,0x63,0xbf,0x11,0x60,0x90,0x36,0x58,0x92,0x66,0xaf,0x70,0xca,0x79,0xb4,0x4c,0x93,0xc7,0x37,0x0c,0x57,0x69,0xc0,0xf6,0x02};
    unsigned char packet[960]={0},random[16],challenge[720]={0};
    if(RAND_bytes(random,16)!=1||RAND_bytes(challenge+16,16)!=1)return false;
    for(int i=0;i<8;i++)challenge[8+i]=join_body[1279-i];
    memcpy(packet,join_frame+10,6);memcpy(packet+6,local,6);packet[12]=0x88;packet[13]=0xb7;
    unsigned char *p=packet+14;
    memcpy(p,"\x00\x22\xaa\x01\x02\x00",6);
    p[6]=4;p[7]=868&255;p[10]=868>>8;
    for(int i=0;i<8;i++)p[14+i]=join_frame[43-i];
    p[24]=join_frame[47];p[25]=join_frame[46];
    memcpy(p+30,join_frame+52,16);memcpy(p+46,join_body,16);memcpy(p+62,random,16);
    memcpy(p+78,"CivSwitch-Pi",12);p[110]=join_body[68];p[111]=join_body[69];
    unsigned int hn=0;
    if(!HMAC(EVP_sha256(),hkey,32,challenge,sizeof(challenge),p+182,&hn)||hn!=32)return false;
    memcpy(p+226,challenge,sizeof(challenge));
    int fd=socket(AF_PACKET,SOCK_RAW|SOCK_NONBLOCK,htons(ETH_P_ALL));
    if(fd<0){RADIO_LOG("auth_socket_errno=%d\n",errno);return false;}
    struct sockaddr_ll addr={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=index,.sll_halen=6};
    memcpy(addr.sll_addr,join_frame+10,6);
    struct ifreq mon={0};strcpy(mon.ifr_name,"ldnmon0");
    int monitor_fd=-1;bool monitor_up=false;
    unsigned int air_frames=0,air_from_host=0,air_to_host=0,air_data=0;
    unsigned int host_data_local=0,host_data_group=0,host_data_other=0,host_data_protected=0;
    if(ioctl(ctl,SIOCGIFINDEX,&mon)==0) {
        unsigned int mi=mon.ifr_ifindex;mon.ifr_flags=IFF_UP;
        int up=ioctl(ctl,SIOCSIFFLAGS,&mon);
        RADIO_LOG("auth_monitor_up=%d errno=%d\n",up,up<0?errno:0);
        monitor_up=up==0;
        if(monitor_up) {
            monitor_fd=socket(AF_PACKET,SOCK_RAW|SOCK_NONBLOCK,htons(ETH_P_ALL));
            struct sockaddr_ll ma={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=mi};
            if(monitor_fd>=0&&bind(monitor_fd,(struct sockaddr *)&ma,sizeof(ma))<0){close(monitor_fd);monitor_fd=-1;}
            RADIO_LOG("auth_monitor_socket=%d\n",monitor_fd>=0?0:-1);
        }
    } else RADIO_LOG("auth_monitor_lookup_errno=%d\n",errno);
    bool ok=false;
    unsigned int total=0,outgoing=0,peer=0,auth=0,short_reply=0,oui=0,header=0,network=0,nonce=0,errors=0;
    int bound=bind(fd,(struct sockaddr*)&addr,sizeof(addr));
    RADIO_LOG("auth_bind=%d errno=%d\n",bound,bound<0?errno:0);
    if(bound==0)for(int attempt=0;attempt<3&&!ok;attempt++) {
        ssize_t sent=sendto(fd,packet,sizeof(packet),0,(struct sockaddr*)&addr,sizeof(addr));
        RADIO_LOG("auth_send_%d=%d errno=%d\n",attempt+1,(int)sent,sent<0?errno:0);
        for(int tick=0;tick<200&&!ok;tick++) {
            if(monitor_fd>=0)for(int burst=0;burst<64;burst++) {
                unsigned char air[4096];ssize_t count=recv(monitor_fd,air,sizeof(air),MSG_DONTWAIT);
                if(count<8)break;
                size_t off=air[2]|((size_t)air[3]<<8);
                if(air[0]||off<8||off+24>(size_t)count)continue;
                const unsigned char *frame=air+off;
                air_frames++;
                bool from=!memcmp(frame+10,join_frame+10,6),to=!memcmp(frame+4,join_frame+10,6);
                if(from)air_from_host++;
                if(to)air_to_host++;
                if((frame[0]&12)==8&&(from||to)) {
                    air_data++;
                    if(from) {
                        bool local_destination=!memcmp(frame+4,local,6);
                        if(local_destination)host_data_local++;
                        else if(frame[4]&1)host_data_group++;
                        else host_data_other++;
                        if(frame[1]&0x40)host_data_protected++;
                        if(host_data_local+host_data_group+host_data_other<=8)
                            RADIO_LOG("auth_host_data len=%u subtype=%u ds=%u protected=%u retry=%u destination=%s\n",
                                (unsigned int)(count-off),frame[0]>>4,frame[1]&3,!!(frame[1]&0x40),!!(frame[1]&8),
                                local_destination?"local":((frame[4]&1)?"group":"other"));
                    }
                }
            }
            for(int burst=0;burst<32&&!ok;burst++) {
                unsigned char reply[2048];struct sockaddr_ll source={0};socklen_t sl=sizeof(source);
                ssize_t n=recvfrom(fd,reply,sizeof(reply),0,(struct sockaddr *)&source,&sl);
                if(n<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK)errors++;break;}
                total++;
                if(source.sll_pkttype==PACKET_OUTGOING){outgoing++;continue;}
                if(n<14||memcmp(reply,local,6)||memcmp(reply+6,join_frame+10,6))continue;
                peer++;
                unsigned int ether=((unsigned int)reply[12]<<8)|reply[13];
                if(peer<=6)RADIO_LOG("auth_peer_frame len=%d ethertype=%04x\n",(int)n,ether);
                if(ether!=0x88b7)continue;
                auth++;
                if(n<92){short_reply++;continue;}
                if(memcmp(reply+14,"\x00\x22\xaa\x01\x02\x00",6)){oui++;continue;}
                unsigned char *h=reply+20;
                if(auth<=6)RADIO_LOG("auth_reply version=%u status=%u type=%u encrypted=%u\n",h[0],h[2],h[3],h[5]);
                if(h[0]!=4||h[3]!=1||h[5]!=0){header++;continue;}
                if(memcmp(h+8,p+14,32)){network++;continue;}
                if(memcmp(h+56,random,16)){nonce++;continue;}
                RADIO_LOG("ldn_auth_status=%u\n",h[2]);ok=h[2]==0;
            }
            sleep_ms(10);
        }
    }
    RADIO_LOG("auth_rx total=%u outgoing=%u peer=%u auth=%u errors=%u\n",total,outgoing,peer,auth,errors);
    RADIO_LOG("auth_rejected short=%u oui=%u header=%u network=%u nonce=%u\n",short_reply,oui,header,network,nonce);
    if(monitor_fd>=0)close(monitor_fd);
    if(monitor_up){mon.ifr_flags=0;int down=ioctl(ctl,SIOCSIFFLAGS,&mon);RADIO_LOG("auth_monitor_down=%d\n",down);}
    RADIO_LOG("auth_air frames=%u from_host=%u to_host=%u data=%u\n",air_frames,air_from_host,air_to_host,air_data);
    RADIO_LOG("auth_host_data_counts local=%u group=%u other=%u protected=%u\n",host_data_local,host_data_group,host_data_other,host_data_protected);
    close(fd);OPENSSL_cleanse(packet,sizeof(packet));OPENSSL_cleanse(challenge,sizeof(challenge));return ok;
}
/* Subscribe before CONNECT: request ACKs do not report association completion. */
static const struct nlattr *ldn_attr_find(const void *data, size_t len, unsigned int type) {
    const unsigned char *p=data;
    while(len>=sizeof(struct nlattr)) {
        const struct nlattr *a=(const void *)p;
        if(a->nla_len<sizeof(*a)||a->nla_len>len)return NULL;
        if((a->nla_type&NLA_TYPE_MASK)==type)return a;
        size_t step=NLA_ALIGN(a->nla_len);if(step>len)return NULL;
        p+=step;len-=step;
    }
    return NULL;
}
static int ldn_event_socket(const char *group_name) {
    int fd=socket(AF_NETLINK,SOCK_RAW,NETLINK_GENERIC);if(fd<0)return -errno;
    struct sockaddr_nl local={.nl_family=AF_NETLINK},kernel={.nl_family=AF_NETLINK};
    int error=0;
    if(bind(fd,(struct sockaddr *)&local,sizeof(local))<0){error=-errno;goto fail;}
    unsigned char req[128]={0},reply[8192];
    struct nlmsghdr *h=(void *)req;
    h->nlmsg_type=GENL_ID_CTRL;h->nlmsg_flags=NLM_F_REQUEST;h->nlmsg_seq=19;
    struct genlmsghdr *g=(void *)(req+NLMSG_HDRLEN);g->cmd=CTRL_CMD_GETFAMILY;g->version=1;
    h->nlmsg_len=NLMSG_HDRLEN+GENL_HDRLEN+radio_attr(req+NLMSG_HDRLEN+GENL_HDRLEN,0,CTRL_ATTR_FAMILY_NAME,"nl80211",8);
    if(sendto(fd,req,h->nlmsg_len,0,(struct sockaddr *)&kernel,sizeof(kernel))<0){error=-errno;goto fail;}
    struct pollfd pollfd={.fd=fd,.events=POLLIN};
    if(poll(&pollfd,1,3000)<=0){error=-ETIMEDOUT;goto fail;}
    ssize_t count=recv(fd,reply,sizeof(reply),0);
    if(count<0){error=-errno;goto fail;}
    for(struct nlmsghdr *r=(void *)reply;NLMSG_OK(r,count);r=NLMSG_NEXT(r,count)) {
        if(r->nlmsg_seq!=19||r->nlmsg_type!=GENL_ID_CTRL||r->nlmsg_len<NLMSG_HDRLEN+GENL_HDRLEN)continue;
        const struct nlattr *groups=ldn_attr_find((unsigned char *)NLMSG_DATA(r)+GENL_HDRLEN,r->nlmsg_len-NLMSG_HDRLEN-GENL_HDRLEN,CTRL_ATTR_MCAST_GROUPS);
        if(!groups)continue;
        const unsigned char *p=(const unsigned char *)(groups+1);size_t left=groups->nla_len-sizeof(*groups);
        while(left>=sizeof(struct nlattr)) {
            const struct nlattr *a=(const void *)p;
            if(a->nla_len<sizeof(*a)||(size_t)NLA_ALIGN(a->nla_len)>left)break;
            const struct nlattr *name=ldn_attr_find(a+1,a->nla_len-sizeof(*a),CTRL_ATTR_MCAST_GRP_NAME);
            const struct nlattr *id=ldn_attr_find(a+1,a->nla_len-sizeof(*a),CTRL_ATTR_MCAST_GRP_ID);
            if(name&&id&&name->nla_len==sizeof(*name)+strlen(group_name)+1&&!memcmp(name+1,group_name,strlen(group_name)+1)&&id->nla_len==sizeof(*id)+4) {
                unsigned int group;memcpy(&group,id+1,4);
                if(setsockopt(fd,SOL_NETLINK,NETLINK_ADD_MEMBERSHIP,&group,sizeof(group))<0){error=-errno;goto fail;}
                return fd;
            }
            size_t step=NLA_ALIGN(a->nla_len);p+=step;left-=step;
        }
    }
    error=-ENOENT;
fail:
    close(fd);return error;
}
static bool ldn_wait_connected(int fd,int family,unsigned int index) {
    struct timespec start,now;clock_gettime(CLOCK_MONOTONIC,&start);
    for(;;) {
        clock_gettime(CLOCK_MONOTONIC,&now);
        long remaining=15000-(now.tv_sec-start.tv_sec)*1000-(now.tv_nsec-start.tv_nsec)/1000000;
        if(remaining<=0){RADIO_LOG("connect_event=timeout\n");return false;}
        struct pollfd pfd={.fd=fd,.events=POLLIN};int ready=poll(&pfd,1,(int)remaining);
        if(ready<0&&errno==EINTR)continue;
        if(ready<=0){RADIO_LOG("connect_event=%s\n",ready==0?"timeout":"poll_error");return false;}
        unsigned char buf[8192];ssize_t count=recv(fd,buf,sizeof(buf),MSG_DONTWAIT);
        if(count<0){if(errno==EAGAIN||errno==EINTR)continue;RADIO_LOG("connect_event_errno=%d\n",errno);return false;}
        for(struct nlmsghdr *h=(void *)buf;NLMSG_OK(h,count);h=NLMSG_NEXT(h,count)) {
            if(h->nlmsg_type!=family||h->nlmsg_len<NLMSG_HDRLEN+GENL_HDRLEN)continue;
            const struct genlmsghdr *g=NLMSG_DATA(h);
            const void *data=(const unsigned char *)g+GENL_HDRLEN;size_t len=h->nlmsg_len-NLMSG_HDRLEN-GENL_HDRLEN;
            const struct nlattr *a=ldn_attr_find(data,len,NL80211_ATTR_IFINDEX);
            unsigned int event_index=0;if(!a||a->nla_len!=sizeof(*a)+4)continue;
            memcpy(&event_index,a+1,4);if(event_index!=index)continue;
            if(g->cmd==NL80211_CMD_DISCONNECT) {
                unsigned short reason=0;a=ldn_attr_find(data,len,NL80211_ATTR_REASON_CODE);
                if(a&&a->nla_len==sizeof(*a)+2)memcpy(&reason,a+1,2);
                RADIO_LOG("connect_event=disconnected reason=%u\n",reason);return false;
            }
            if(g->cmd!=NL80211_CMD_CONNECT)continue;
            a=ldn_attr_find(data,len,NL80211_ATTR_MAC);
            if(!a||a->nla_len!=sizeof(*a)+6||memcmp(a+1,join_frame+10,6))continue;
            if(ldn_attr_find(data,len,NL80211_ATTR_TIMED_OUT)){RADIO_LOG("connect_event=driver_timeout\n");return false;}
            unsigned short status=0;a=ldn_attr_find(data,len,NL80211_ATTR_STATUS_CODE);
            if(!a||a->nla_len!=sizeof(*a)+2){RADIO_LOG("connect_event=missing_status\n");return false;}
            memcpy(&status,a+1,2);RADIO_LOG("connect_event=status status=%u\n",status);return status==0;
        }
    }
}

static bool ldn_bss_matches(const void *data,size_t len,const unsigned char ssid[32]) {
    const struct nlattr *bss=ldn_attr_find(data,len,NL80211_ATTR_BSS);
    if(!bss)return false;
    data=bss+1;len=bss->nla_len-sizeof(*bss);
    const struct nlattr *mac=ldn_attr_find(data,len,NL80211_BSS_BSSID);
    const struct nlattr *freq=ldn_attr_find(data,len,NL80211_BSS_FREQUENCY);
    unsigned int f=0;
    if(!mac||mac->nla_len!=sizeof(*mac)+6||memcmp(mac+1,join_frame+10,6)||!freq||freq->nla_len!=sizeof(*freq)+4)return false;
    memcpy(&f,freq+1,4);if(f!=join_frequency)return false;
    const struct nlattr *ies=ldn_attr_find(data,len,NL80211_BSS_INFORMATION_ELEMENTS);
    if(!ies)return false;
    const unsigned char *p=(const void *)(ies+1);size_t left=ies->nla_len-sizeof(*ies);
    while(left>=2) {
        size_t step=2+p[1];if(step>left)return false;
        if(p[0]==0)return p[1]==32&&!memcmp(p+2,ssid,32);
        p+=step;left-=step;
    }
    return false;
}
/* Read the complete multipart scan dump; ACK alone cannot establish a cache hit. */
static int ldn_cached_target(int family,unsigned int index,const unsigned char ssid[32]) {
    int fd=socket(AF_NETLINK,SOCK_RAW,NETLINK_GENERIC);if(fd<0)return -errno;
    struct sockaddr_nl local={.nl_family=AF_NETLINK},kernel={.nl_family=AF_NETLINK};
    int result=-ETIMEDOUT;bool found=false;
    if(bind(fd,(struct sockaddr *)&local,sizeof(local))<0){result=-errno;goto done;}
    unsigned char req[64]={0},buf[32768];
    struct nlmsghdr *h=(void *)req;struct genlmsghdr *g=(void *)(req+NLMSG_HDRLEN);
    h->nlmsg_type=family;h->nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;h->nlmsg_seq=27;
    g->cmd=NL80211_CMD_GET_SCAN;g->version=1;
    h->nlmsg_len=NLMSG_HDRLEN+GENL_HDRLEN+radio_attr(req+NLMSG_HDRLEN+GENL_HDRLEN,0,NL80211_ATTR_IFINDEX,&index,4);
    if(sendto(fd,req,h->nlmsg_len,0,(struct sockaddr *)&kernel,sizeof(kernel))<0){result=-errno;goto done;}
    struct timespec start,now;clock_gettime(CLOCK_MONOTONIC,&start);
    for(;;) {
        clock_gettime(CLOCK_MONOTONIC,&now);
        long ms=3000-(now.tv_sec-start.tv_sec)*1000-(now.tv_nsec-start.tv_nsec)/1000000;
        if(ms<=0)break;
        struct pollfd pfd={.fd=fd,.events=POLLIN};int r=poll(&pfd,1,(int)ms);
        if(r<0&&errno==EINTR)continue;
        if(r<=0)break;
        ssize_t count=recv(fd,buf,sizeof(buf),MSG_DONTWAIT|MSG_TRUNC);
        if(count<0){result=-errno;break;}
        if((size_t)count>sizeof(buf)){result=-EMSGSIZE;break;}
        for(struct nlmsghdr *m=(void *)buf;NLMSG_OK(m,count);m=NLMSG_NEXT(m,count)) {
            if(m->nlmsg_seq!=27)continue;
            if(m->nlmsg_flags&NLM_F_DUMP_INTR){result=-EINTR;goto done;}
            if(m->nlmsg_type==NLMSG_DONE){
                int error=0;if(m->nlmsg_len>=NLMSG_LENGTH(sizeof(error)))memcpy(&error,NLMSG_DATA(m),sizeof(error));
                result=error?error:(found?1:0);goto done;
            }
            if(m->nlmsg_type==NLMSG_ERROR&&m->nlmsg_len>=NLMSG_LENGTH(sizeof(struct nlmsgerr))){result=((struct nlmsgerr *)NLMSG_DATA(m))->error;goto done;}
            if(m->nlmsg_type==family&&m->nlmsg_len>=NLMSG_HDRLEN+GENL_HDRLEN)
                found|=ldn_bss_matches((unsigned char *)NLMSG_DATA(m)+GENL_HDRLEN,m->nlmsg_len-NLMSG_HDRLEN-GENL_HDRLEN,ssid);
        }
    }
done:
    close(fd);return result;
}
static bool ldn_scan_target(int family,unsigned int index,const unsigned char ssid[32]) {
    int fd=ldn_event_socket("scan");RADIO_LOG("scan_subscription=%d\n",fd<0?fd:0);
    if(fd<0)return false;
    unsigned char attrs[128],nested[40];
    size_t n=radio_attr(attrs,0,NL80211_ATTR_IFINDEX,&index,4);
    size_t inner=radio_attr(nested,0,1,&join_frequency,4);
    n=radio_attr(attrs,n,NL80211_ATTR_SCAN_FREQUENCIES|NLA_F_NESTED,nested,inner);
    inner=radio_attr(nested,0,1,ssid,32);
    n=radio_attr(attrs,n,NL80211_ATTR_SCAN_SSIDS|NLA_F_NESTED,nested,inner);
    int r=radio_request(family,NL80211_CMD_TRIGGER_SCAN,attrs,n,false);
    RADIO_LOG("scan_request=%d\n",r);
    bool complete=false;
    struct timespec start,now;clock_gettime(CLOCK_MONOTONIC,&start);
    while(r==0&&!complete) {
        clock_gettime(CLOCK_MONOTONIC,&now);
        long ms=15000-(now.tv_sec-start.tv_sec)*1000-(now.tv_nsec-start.tv_nsec)/1000000;
        if(ms<=0){RADIO_LOG("scan_event=timeout\n");break;}
        struct pollfd pfd={.fd=fd,.events=POLLIN};int ready=poll(&pfd,1,(int)ms);
        if(ready<0&&errno==EINTR)continue;
        if(ready<=0){RADIO_LOG("scan_event=%s\n",ready==0?"timeout":"poll_error");break;}
        unsigned char buf[8192];ssize_t count=recv(fd,buf,sizeof(buf),MSG_DONTWAIT);
        if(count<0){if(errno==EAGAIN||errno==EINTR)continue;break;}
        for(struct nlmsghdr *h=(void *)buf;NLMSG_OK(h,count);h=NLMSG_NEXT(h,count)) {
            if(h->nlmsg_type!=family||h->nlmsg_len<NLMSG_HDRLEN+GENL_HDRLEN)continue;
            const struct genlmsghdr *g=NLMSG_DATA(h);
            const struct nlattr *a=ldn_attr_find((unsigned char *)NLMSG_DATA(h)+GENL_HDRLEN,h->nlmsg_len-NLMSG_HDRLEN-GENL_HDRLEN,NL80211_ATTR_IFINDEX);
            unsigned int event_index=0;if(!a||a->nla_len!=sizeof(*a)+4)continue;
            memcpy(&event_index,a+1,4);if(event_index!=index)continue;
            if(g->cmd==NL80211_CMD_SCAN_ABORTED){RADIO_LOG("scan_event=aborted\n");r=-ECANCELED;break;}
            if(g->cmd==NL80211_CMD_NEW_SCAN_RESULTS){RADIO_LOG("scan_event=complete\n");complete=true;break;}
        }
    }
    close(fd);
    if(!complete)return false;
    int cached=ldn_cached_target(family,index,ssid);
    RADIO_LOG("target_bss_cached=%d\n",cached);return cached==1;
}

#include "ldn_transfer.h"
/* Keep the associated station up; use a same-channel monitor only for updated membership. */
static bool ldn_assigned_ip(int family,int ctl,unsigned int station,const unsigned char local[6],unsigned char ip[4],unsigned char host[4]) {
    (void)family;(void)station;
    struct ifreq ifr={0};strcpy(ifr.ifr_name,"ldnmon0");
    int fd=-1;unsigned int monitor=0;bool found=false;
    unsigned int packets=0,verified=0;
    if(ioctl(ctl,SIOCGIFINDEX,&ifr)<0){RADIO_LOG("ip_monitor_lookup_errno=%d\n",errno);goto cleanup;}
    monitor=ifr.ifr_ifindex;
    RADIO_LOG("ip_monitor_reused=%u\n",monitor);
    ifr.ifr_flags=IFF_UP;
    int up=ioctl(ctl,SIOCSIFFLAGS,&ifr);
    RADIO_LOG("ip_monitor_up=%d errno=%d\n",up,up<0?errno:0);
    if(up<0)goto cleanup;
    fd=socket(AF_PACKET,SOCK_RAW|SOCK_NONBLOCK,htons(ETH_P_ALL));
    struct sockaddr_ll addr={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=monitor};
    if(fd<0||bind(fd,(struct sockaddr *)&addr,sizeof(addr))<0){RADIO_LOG("ip_capture_errno=%d\n",errno);goto cleanup;}
    uint64_t deadline=ldn_now_ms()+10000;
    while(!found&&ldn_now_ms()<deadline) {
        unsigned char packet[4096],body[1280];ssize_t length=recv(fd,packet,sizeof(packet),0);
        if(length<8){sleep_ms(5);continue;}
        packets++;
        size_t off=packet[2]|((size_t)packet[3]<<8);
        if(packet[0]||off<8||off+1388>(size_t)length||memcmp(packet+off+10,join_frame+10,6)||
            memcmp(packet+off+36,join_frame+36,32))continue;
        if(ldn_decrypt_advertisement(packet+off,length-off,body)) {
            verified++;
            for(int i=1;i<8;i++) {
                const unsigned char *member=body+24+i*56;
                if(member[10]&&!memcmp(member+4,local,6)&&body[34]) {
                    memcpy(ip,member,4);memcpy(host,body+24,4);
                    found=ip[0]!=0&&host[0]!=0&&memcmp(ip,host,4)!=0;break;
                }
            }
        }
        OPENSSL_cleanse(body,sizeof(body));
    }
cleanup:
    if(fd>=0)close(fd);
    if(monitor){
        ifr.ifr_flags=0;int down=ioctl(ctl,SIOCSIFFLAGS,&ifr);
        RADIO_LOG("ip_monitor_down=%d errno=%d\n",down,down<0?errno:0);
    }
    RADIO_LOG("ip_capture_packets=%u verified=%u\n",packets,verified);
    RADIO_LOG("assigned_ip=%s\n",found?"found":"unavailable");return found;
}

static void ldn_join_probe(int family,int ctl) {
    if(!join_ready){RADIO_LOG("join=no_verified_target\n");return;}
    struct ifreq ifr={0};strcpy(ifr.ifr_name,"wlan0");
    if(ioctl(ctl,SIOCGIFINDEX,&ifr)<0)return;
    unsigned int index=ifr.ifr_ifindex;
    if(ioctl(ctl,SIOCGIFHWADDR,&ifr)<0)return;
    unsigned char local[6];memcpy(local,ifr.ifr_hwaddr.sa_data,6);
    ifr.ifr_flags=IFF_UP;if(ioctl(ctl,SIOCSIFFLAGS,&ifr)<0)return;
    unsigned char attrs[256]={0},key[16],ssid[32];
    static const char hex[]="0123456789abcdef";
    for(int i=0;i<16;i++){ssid[2*i]=hex[join_frame[52+i]>>4];ssid[2*i+1]=hex[join_frame[52+i]&15];}
    if(!ldn_scan_target(family,index,ssid)){RADIO_LOG("join=scan_target_unavailable\n");OPENSSL_cleanse(join_body,sizeof(join_body));join_ready=false;return;}
    if(!ldn_session_key(key)){RADIO_LOG("session_key=failed\n");return;}
    unsigned int auth=NL80211_AUTHTYPE_OPEN_SYSTEM,wpa=NL80211_WPA_VERSION_2,cipher=0x000fac04,akm=0x000fac02;
    size_t n=radio_attr(attrs,0,NL80211_ATTR_IFINDEX,&index,4);
    n=radio_attr(attrs,n,NL80211_ATTR_MAC,join_frame+10,6);
    n=radio_attr(attrs,n,NL80211_ATTR_SSID,ssid,32);
    n=radio_attr(attrs,n,NL80211_ATTR_WIPHY_FREQ,&join_frequency,4);
    n=radio_attr(attrs,n,NL80211_ATTR_AUTH_TYPE,&auth,4);
    n=radio_attr(attrs,n,NL80211_ATTR_WPA_VERSIONS,&wpa,4);
    n=radio_attr(attrs,n,NL80211_ATTR_CIPHER_SUITES_PAIRWISE,&cipher,4);
    n=radio_attr(attrs,n,NL80211_ATTR_CIPHER_SUITE_GROUP,&cipher,4);
    n=radio_attr(attrs,n,NL80211_ATTR_AKM_SUITES,&akm,4);
    n=radio_attr(attrs,n,NL80211_ATTR_PRIVACY,"",0);
    n=radio_attr(attrs,n,NL80211_ATTR_CONTROL_PORT,"",0);
    unsigned char connect_attrs[256];memcpy(connect_attrs,attrs,n);size_t connect_len=n;
    bool session_authenticated=false;
    for(int session=1;session<=3&&!session_authenticated;session++) {
    RADIO_LOG("association_attempt=%d\n",session);
    memcpy(attrs,connect_attrs,connect_len);n=connect_len;
    int events=ldn_event_socket("mlme");
    RADIO_LOG("mlme_subscription=%d\n",events<0?events:0);
    if(events<0){OPENSSL_cleanse(key,sizeof(key));OPENSSL_cleanse(join_body,sizeof(join_body));join_ready=false;return;}
    int r=radio_request(family,NL80211_CMD_CONNECT,attrs,n,false);
    RADIO_LOG("connect_request=%d\n",r);
    if(r==0) {
        bool associated=ldn_wait_connected(events,family,index);
        RADIO_LOG("association_confirmed=%d\n",associated);
        if(associated) {
            int pw=ldn_install_key(family,index,key,true),group=ldn_install_key(family,index,key,false);
            RADIO_LOG("pairwise_key=%d group_key=%d\n",pw,group);
            struct nl80211_sta_flag_update flags={.mask=1u<<NL80211_STA_FLAG_AUTHORIZED,.set=1u<<NL80211_STA_FLAG_AUTHORIZED};
            n=radio_attr(attrs,0,NL80211_ATTR_IFINDEX,&index,4);
            n=radio_attr(attrs,n,NL80211_ATTR_MAC,join_frame+10,6);
            n=radio_attr(attrs,n,NL80211_ATTR_STA_FLAGS2,&flags,sizeof(flags));
            int authorized=radio_request(family,NL80211_CMD_SET_STATION,attrs,n,false);
            RADIO_LOG("authorize_port=%d\n",authorized);
            if(!pw&&!group&&!authorized) {
                RADIO_LOG("auth_key_settle_ms=500\n");
                sleep_ms(500);
                bool authenticated=ldn_auth_exchange(index,local,ctl);
                RADIO_LOG("ldn_authenticated=%d\n",authenticated);
                session_authenticated=authenticated;
                n=radio_attr(attrs,0,NL80211_ATTR_IFINDEX,&index,4);
                n=radio_attr(attrs,n,NL80211_ATTR_MAC,join_frame+10,6);
                int station_status=radio_request(family,NL80211_CMD_GET_STATION,attrs,n,false);
                RADIO_LOG("auth_station_query=%d\n",station_status);
                struct ifreq state={0};strcpy(state.ifr_name,"wlan0");
                int flags_result=ioctl(ctl,SIOCGIFFLAGS,&state);
                RADIO_LOG("auth_link_flags_result=%d flags=%04x\n",flags_result,(unsigned short)state.ifr_flags);
                struct pollfd ep={.fd=events,.events=POLLIN};
                if(poll(&ep,1,0)>0){
                    unsigned char buffer[8192];ssize_t count=recv(events,buffer,sizeof(buffer),MSG_DONTWAIT);
                    for(struct nlmsghdr *h=(void *)buffer;NLMSG_OK(h,count);h=NLMSG_NEXT(h,count)){
                        if(h->nlmsg_type!=family||h->nlmsg_len<NLMSG_HDRLEN+GENL_HDRLEN)continue;
                        struct genlmsghdr *g=NLMSG_DATA(h);
                        unsigned short reason=0;
                        const struct nlattr *ra=ldn_attr_find((unsigned char *)g+GENL_HDRLEN,h->nlmsg_len-NLMSG_HDRLEN-GENL_HDRLEN,NL80211_ATTR_REASON_CODE);
                        if(ra&&ra->nla_len==sizeof(*ra)+2)memcpy(&reason,ra+1,2);
                        RADIO_LOG("auth_pending_event cmd=%u reason=%u\n",g->cmd,reason);
                    }
                }
                if(authenticated&&cfg_ldn_install) {
                    unsigned char ip[4],host[4];
                    if(ldn_assigned_ip(family,ctl,index,local,ip,host))ldn_transfer(index,local,ip,host);
                }
            }
        }
        n=radio_attr(attrs,0,NL80211_ATTR_IFINDEX,&index,4);
        unsigned short reason=3;n=radio_attr(attrs,n,NL80211_ATTR_REASON_CODE,&reason,2);
        RADIO_LOG("disconnect=%d\n",radio_request(family,NL80211_CMD_DISCONNECT,attrs,n,false));
    }
    close(events);
    if(!session_authenticated&&session<3) {
        /* Close the old event socket before retrying, so its disconnect event
         * cannot be mistaken for the result of the next connection. */
        sleep_ms(300);
    }
    }
    RADIO_LOG("authentication_attempts_result=%s\n",session_authenticated?"accepted":"exhausted");
    OPENSSL_cleanse(key,sizeof(key));OPENSSL_cleanse(join_body,sizeof(join_body));join_ready=false;
}
