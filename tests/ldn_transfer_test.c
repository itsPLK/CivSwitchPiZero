#define main civswitch_init_main
#include "../src/init.c"
#undef main
#include <assert.h>

static size_t ack_packet(unsigned char frame[64]) {
    memset(frame,0,64);memcpy(frame,s_sta_mac,6);memcpy(frame+6,s_host_mac,6);
    frame[12]=8;
    unsigned char *ip=frame+14;ip[0]=0x45;ip[3]=29;ip[8]=64;ip[9]=17;
    memcpy(ip+12,s_host_ip,4);memcpy(ip+16,s_local_ip,4);
    uint16_t checksum=ip_checksum(ip,20);ip[10]=checksum>>8;ip[11]=checksum;
    unsigned char *udp=ip+20;udp[0]=udp[2]=9027>>8;udp[1]=udp[3]=9027&255;
    udp[5]=9;udp[8]='D';return 43;
}
int main(void) {
    assert(ldn_supported_model("Raspberry Pi Zero W Rev 1.1"));
    assert(ldn_supported_model("Raspberry Pi Zero 2 W Rev 1.0"));
    assert(!ldn_supported_model("Raspberry Pi Zero Rev 1.3"));
    assert(!ldn_supported_model("Raspberry Pi Zero Rev 1.2"));
    assert(!ldn_supported_model(""));
    assert(!ldn_supported_model("Raspberry Pi 3 Model B Rev 1.2"));
    transfer_tpl_len=2201;transfer_js_len=1100;
    transfer_rx((const unsigned char *)"t2",2);assert(repair_tpl[2]);
    transfer_rx((const unsigned char *)"t3",2);assert(!repair_tpl[3]);
    transfer_rx((const unsigned char *)"j1",2);assert(!repair_js[1]);
    transfer_rx((const unsigned char *)"j0",2);assert(repair_js[0]);
    repair_js[0]=false;
    transfer_rx((const unsigned char *)"j-1",3);transfer_rx((const unsigned char *)"j0x",3);
    assert(!repair_js[0]);
    int sockets[2];assert(socketpair(AF_UNIX,SOCK_DGRAM,0,sockets)==0);
    transfer_fd=sockets[1];
    const unsigned char local[6]={2,1,2,3,4,5},host[6]={2,5,4,3,2,1},ip[4]={169,254,1,2},hip[4]={169,254,1,1};
    civ7_set_net(ip,hip,host,local);
    unsigned char frame[64];size_t n=ack_packet(frame);
    for(size_t i=0;i<n;i++){
        transfer_ack=false;assert(send(sockets[0],frame,i,0)==(ssize_t)i);ldn_pump(0);assert(!transfer_ack);
    }
    frame[6]^=1;assert(send(sockets[0],frame,n,0)==(ssize_t)n);ldn_pump(0);assert(!transfer_ack);frame[6]^=1;
    frame[16]=255;assert(send(sockets[0],frame,n,0)==(ssize_t)n);ldn_pump(0);assert(!transfer_ack);
    n=ack_packet(frame);assert(send(sockets[0],frame,n,0)==(ssize_t)n);ldn_pump(0);assert(transfer_ack);
    transfer_ack=false;n=ack_packet(frame);
    frame[34]=0xc0;frame[35]=1; /* valid reply from a different source port */
    assert(send(sockets[0],frame,n,0)==(ssize_t)n);ldn_pump(0);assert(transfer_ack);
    transfer_ack=false;frame[36]=0;frame[37]=1;
    assert(send(sockets[0],frame,n,0)==(ssize_t)n);ldn_pump(0);assert(!transfer_ack);
    n=ack_packet(frame);frame[40]=1; /* invalid nonzero UDP checksum */
    assert(send(sockets[0],frame,n,0)==(ssize_t)n);ldn_pump(0);assert(!transfer_ack);
    assert(transfer_stats.udp_checksum>0);
    n=ack_packet(frame);frame[17]=30;frame[24]=frame[25]=0;
    uint16_t ck=ip_checksum(frame+14,20);frame[24]=ck>>8;frame[25]=ck;
    frame[34]=0xc0;frame[35]=1;frame[39]=10;frame[42]='t';frame[43]='2';
    repair_tpl[2]=false;
    assert(send(sockets[0],frame,44,0)==44);ldn_pump(0);assert(repair_tpl[2]);
    close(sockets[0]);close(sockets[1]);transfer_fd=-1;
    puts("Transfer ACK, peer validation, truncation, and repair bounds passed");
    return 0;
}
