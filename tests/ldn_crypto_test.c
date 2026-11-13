#include <assert.h>
#include <unistd.h>
#include "ldn_crypto.h"
int main(void) {
    unsigned char frame[1388] = {0}, body[1280], plain[1312], check[1352];
    unsigned char kek[16], next[16], key[16], digest[32], iv[16] = {0};
    const unsigned char source[16] = {0x19,0x18,0x84,0x74,0x3e,0x24,0xc7,0x7d,0x87,0xc6,0x9e,0x42,0x07,0xd0,0xc4,0x38};
    unsigned int n;
    assert(!ldn_load_keys("/nonexistent/civswitch-test.keys"));
    char path[] = "/tmp/civswitch-keys-XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0);
    FILE *f = fdopen(fd, "w"); assert(f);
    fputs("\xef\xbb\xbfmaster_key_00=00000000000000000000000000000000\r\n", f);
    fputs("unrelated_rsa_key=", f);
    for (int i=0;i<2048;i++) fputc('a', f);
    fputs("\naes_kek_generation_source = 11111111111111111111111111111111\n", f);
    fputs("aes_key_generation_source=22222222222222222222222222222222", f);
    fclose(f);
    assert(ldn_load_keys(path)); assert(ldn_key_mask == 7);
    f=fopen(path,"a"); assert(f);
    fputs("\nmaster_key_00=33333333333333333333333333333333\n",f);fclose(f);
    assert(!ldn_load_keys(path)); assert(!strcmp(ldn_key_status,"malformed_or_duplicate_entry"));
    unlink(path);
    memset(ldn_keys, 0x42, sizeof(ldn_keys)); ldn_keys_ready = true;
    frame[0]=0xd0; memcpy(frame+24,"\x7f\x00\x22\xaa",4);
    frame[68]=4;frame[69]=2;frame[70]=5;frame[72]=17;
    assert(ldn_cipher(EVP_aes_128_ecb(),ldn_keys[0],NULL,ldn_keys[1],16,kek));
    assert(ldn_cipher(EVP_aes_128_ecb(),kek,NULL,source,16,next));
    assert(ldn_cipher(EVP_aes_128_ecb(),next,NULL,ldn_keys[2],16,kek));
    assert(EVP_Digest(frame+36,32,digest,&n,EVP_sha256(),NULL));
    assert(ldn_cipher(EVP_aes_128_ecb(),kek,NULL,digest,16,key));
    memset(plain+32,0xa7,1280);memcpy(check,frame+36,40);memset(check+40,0,32);
    memcpy(check+72,plain+32,1280);
    assert(EVP_Digest(check,sizeof(check),plain,&n,EVP_sha256(),NULL));
    memcpy(iv,frame+72,4);
    assert(ldn_cipher(EVP_aes_128_ctr(),key,iv,plain,sizeof(plain),frame+76));
    assert(ldn_decrypt_advertisement(frame,sizeof(frame),body));
    for (int i=0;i<1280;i++) assert(body[i]==0xa7);
    frame[200]^=1; assert(!ldn_decrypt_advertisement(frame,sizeof(frame),body));frame[200]^=1;
    for (int i=0;i<1280;i++) assert(body[i]==0);
    ldn_keys[0][0]^=1;assert(!ldn_decrypt_advertisement(frame,sizeof(frame),body));
    assert(!ldn_decrypt_advertisement(frame,100,body));
    return 0;
}
