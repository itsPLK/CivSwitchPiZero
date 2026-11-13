/* Linux transport for the esp32-ldn-civ7 offline installer flow. */
static uint64_t ldn_now_ms(void) {
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
#include "ldn_civ7.h"
static int transfer_fd=-1;
static unsigned int transfer_index;
static bool transfer_ack;
static unsigned char *transfer_tpl,*transfer_js;
static size_t transfer_tpl_len,transfer_js_len;
static bool repair_tpl[4096],repair_js[4096];
static struct {
    unsigned int frames, peer, ethernet, ip, ip_checksum, udp, port, udp_checksum;
    unsigned int installer, requests, invalid_requests, arp, arp_failures, rx_errors;
    unsigned int first_source_port;
} transfer_stats;

static int ldn_frame_tx(const void *frame,size_t len) {
    struct sockaddr_ll addr={.sll_family=AF_PACKET,.sll_ifindex=transfer_index,.sll_halen=6};
    memcpy(addr.sll_addr,frame,6);
    ssize_t n=sendto(transfer_fd,frame,len,0,(struct sockaddr *)&addr,sizeof(addr));
    return n==(ssize_t)len?0:-1;
}
static void transfer_rx(const unsigned char *p,size_t n) {
    if(n==1&&p[0]=='D'){transfer_ack=true;return;}
    if(n<2||n>5||(p[0]!='t'&&p[0]!='j')){transfer_stats.invalid_requests++;return;}
    unsigned int index=0;
    for(size_t i=1;i<n;i++){if(p[i]<'0'||p[i]>'9'){transfer_stats.invalid_requests++;return;}index=index*10+p[i]-'0';}
    size_t total=p[0]=='t'?transfer_tpl_len:transfer_js_len;
    if(index>=4096||index>=(total+1099)/1100){transfer_stats.invalid_requests++;return;}
    transfer_stats.requests++;
    (p[0]=='t'?repair_tpl:repair_js)[index]=true;
}
static void ldn_pump(unsigned int ms) {
    uint64_t end=ldn_now_ms()+ms;
    do {
        unsigned char frame[2048];
        for(int burst=0;burst<64;burst++) {
            ssize_t n=recv(transfer_fd,frame,sizeof(frame),MSG_DONTWAIT);
            if(n<=0){if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK)transfer_stats.rx_errors++;break;}
            transfer_stats.frames++;
            if(n<42||memcmp(frame+6,s_host_mac,6)){transfer_stats.peer++;continue;}
            /* Answer the selected host's ARP queries without configuring a kernel IP. */
            if(frame[12]==8&&frame[13]==6&&frame[20]==0&&frame[21]==1&&
                !memcmp(frame+14,"\x00\x01\x08\x00\x06\x04",6)&&
                !memcmp(frame+28,s_host_ip,4)&&!memcmp(frame+38,s_local_ip,4)) {
                unsigned char reply[42];memcpy(reply,frame,42);
                memcpy(reply,s_host_mac,6);memcpy(reply+6,s_sta_mac,6);reply[21]=2;
                memcpy(reply+22,s_sta_mac,6);memcpy(reply+28,s_local_ip,4);
                memcpy(reply+32,s_host_mac,6);memcpy(reply+38,s_host_ip,4);
                transfer_stats.arp++;if(ldn_frame_tx(reply,42))transfer_stats.arp_failures++;continue;
            }
            if(memcmp(frame,s_sta_mac,6)||frame[12]!=8||frame[13]!=0){transfer_stats.ethernet++;continue;}
            const unsigned char *ip=frame+14;size_t ihl=(ip[0]&15)*4,total=((size_t)ip[2]<<8)|ip[3];
            if((ip[0]>>4)!=4||ihl<20||total<ihl+8||14+total>(size_t)n||ip[9]!=17||
                (ip[6]&0x3f)||ip[7]||memcmp(ip+12,s_host_ip,4)||memcmp(ip+16,s_local_ip,4)){transfer_stats.ip++;continue;}
            if(ip_checksum(ip,ihl)!=0){transfer_stats.ip_checksum++;continue;}
            const unsigned char *udp=ip+ihl;size_t length=((size_t)udp[4]<<8)|udp[5];
            if(length<8||length>total-ihl){transfer_stats.udp++;continue;}
            unsigned int port=((unsigned int)udp[2]<<8)|udp[3];
            unsigned int source_port=((unsigned int)udp[0]<<8)|udp[1];
            /* The return socket need not use the destination port as its source.
             * MAC/IP and destination-port checks still restrict replies to our peer. */
            if(port!=9027&&(port!=62056||source_port!=62056)){transfer_stats.port++;continue;}
            if(udp[6]||udp[7]){
                uint32_t sum=sum16(ip+12,8)+17+length+sum16(udp,length);
                while(sum>>16)sum=(sum&65535)+(sum>>16);
                if(sum!=65535){transfer_stats.udp_checksum++;continue;}
            }
            if(port==62056)civ7_rx_udp(udp+8,length-8);
            else if(port==9027){
                if(!transfer_stats.installer)transfer_stats.first_source_port=source_port;
                transfer_stats.installer++;transfer_rx(udp+8,length-8);
            }
        }
        if(ldn_now_ms()>=end)break;
        sleep_ms(1);
    }while(true);
}
static unsigned char *transfer_load(const char *path,size_t *length) {
    FILE *f=fopen(path,"rb");if(!f)return NULL;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return NULL;}
    long n=ftell(f);if(n<=0||n>4096*1100||n%4){fclose(f);return NULL;}
    rewind(f);unsigned char *data=malloc((size_t)n);
    if(!data){fclose(f);return NULL;}
    bool ok=fread(data,1,n,f)==(size_t)n;fclose(f);
    for(long i=0;ok&&i<n;i++)if(!((data[i]>='A'&&data[i]<='Z')||(data[i]>='a'&&data[i]<='z')||
        (data[i]>='0'&&data[i]<='9')||data[i]=='+'||data[i]=='/'||data[i]=='='))ok=false;
    if(!ok){free(data);return NULL;}*length=n;return data;
}
static bool transfer_chunk(bool js,size_t index) {
    size_t total=js?transfer_js_len:transfer_tpl_len,off=index*1100;
    if(off>=total)return false;
    unsigned char packet[1120];int prefix=snprintf((char *)packet,20,"%c%zu:",js?'J':'T',index);
    size_t n=total-off;if(n>1100)n=1100;
    memcpy(packet+prefix,(js?transfer_js:transfer_tpl)+off,n);
    for(int retry=0;retry<20;retry++) {
        if(civ7_udp_send(9027,packet,prefix+n)==0)return true;
        ldn_pump(2);
    }
    return false;
}
static void ldn_transfer(unsigned int index,const unsigned char local[6],const unsigned char ip[4],const unsigned char host_ip[4]) {
    transfer_tpl=transfer_load("/ldn/template.b64",&transfer_tpl_len);
    transfer_js=transfer_load("/ldn/apply.b64",&transfer_js_len);
    if(!transfer_tpl||!transfer_js){RADIO_LOG("installer=assets_invalid\n");goto cleanup;}
    transfer_index=index;transfer_ack=false;
    memset(&transfer_stats,0,sizeof(transfer_stats));
    memset(repair_tpl,0,sizeof(repair_tpl));memset(repair_js,0,sizeof(repair_js));
    transfer_fd=socket(AF_PACKET,SOCK_RAW|SOCK_NONBLOCK,htons(ETH_P_ALL));
    struct sockaddr_ll addr={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=index};
    if(transfer_fd<0||bind(transfer_fd,(struct sockaddr *)&addr,sizeof(addr))<0){RADIO_LOG("installer=socket_failed errno=%d\n",errno);goto cleanup;}
    int receive_buffer=1024*1024;
    setsockopt(transfer_fd,SOL_SOCKET,SO_RCVBUF,&receive_buffer,sizeof(receive_buffer));
    civ7_set_net(ip,host_ip,join_frame+10,local);civ7_run();
    if(!civ7_done()){RADIO_LOG("installer=lobby_failed\n");goto cleanup;}
    ldn_pump(800);
    size_t nt=(transfer_tpl_len+1099)/1100,nj=(transfer_js_len+1099)/1100;
    char header[80];int hn=snprintf(header,sizeof(header),"A%zu:%zu:%u.%u.%u.%u",nt,nj,ip[0],ip[1],ip[2],ip[3]);
    for(int i=0;i<3;i++){civ7_udp_send(9027,(unsigned char *)header,hn);ldn_pump(100);}
    RADIO_LOG("installer_chunks template=%zu apply=%zu\n",nt,nj);
    unsigned int send_failures=0;
    for(size_t i=0;i<nj&&!transfer_ack;i++){if(!transfer_chunk(true,i))send_failures++;ldn_pump(10);}
    for(size_t i=0;i<nt&&!transfer_ack;i++){if(!transfer_chunk(false,i))send_failures++;ldn_pump(10);}
    uint64_t deadline=ldn_now_ms()+120000;unsigned int repairs=0;
    while(!transfer_ack&&ldn_now_ms()<deadline) {
        civ7_udp_send(9027,(const unsigned char *)"G",1);ldn_pump(150);
        for(size_t i=0;i<nt&&!transfer_ack&&ldn_now_ms()<deadline;i++)if(repair_tpl[i]){repair_tpl[i]=false;if(!transfer_chunk(false,i))send_failures++;repairs++;ldn_pump(10);}
        for(size_t i=0;i<nj&&!transfer_ack&&ldn_now_ms()<deadline;i++)if(repair_js[i]){repair_js[i]=false;if(!transfer_chunk(true,i))send_failures++;repairs++;ldn_pump(10);}
    }
    RADIO_LOG("installer_transfer=%s repairs=%u send_failures=%u\n",transfer_ack?"acknowledged":"timeout",repairs,send_failures);
    RADIO_LOG("installer_result=check_console\n");
    /* D is sent before apply starts; keep the link alive while it runs. */
    if(transfer_ack)ldn_pump(15000);
cleanup:
    RADIO_LOG("transfer_rx frames=%u installer=%u requests=%u invalid_requests=%u source_port=%u\n",
        transfer_stats.frames,transfer_stats.installer,transfer_stats.requests,transfer_stats.invalid_requests,transfer_stats.first_source_port);
    RADIO_LOG("transfer_drop peer=%u ethernet=%u ip=%u ip_checksum=%u udp=%u port=%u udp_checksum=%u\n",
        transfer_stats.peer,transfer_stats.ethernet,transfer_stats.ip,transfer_stats.ip_checksum,transfer_stats.udp,transfer_stats.port,transfer_stats.udp_checksum);
    RADIO_LOG("transfer_arp requests=%u send_failures=%u rx_errors=%u\n",transfer_stats.arp,transfer_stats.arp_failures,transfer_stats.rx_errors);
    if(transfer_fd>=0)close(transfer_fd);
    transfer_fd=-1;
    free(transfer_tpl);free(transfer_js);transfer_tpl=NULL;transfer_js=NULL;
    for(int i=0;i<TX_RING;i++){free(s_tx[i]);s_tx[i]=NULL;}
}
