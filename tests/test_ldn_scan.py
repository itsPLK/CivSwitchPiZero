"""Exercise the scan-cache matcher with native Linux headers or Alpine Docker."""
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

root = Path(__file__).resolve().parents[1]
join = (root / 'src/ldn_join.h').read_text()
wifi = (root / 'src/wifi_probe.h').read_text()
def section(text, start, end):
    return text[text.index(start):text.index(end)]
source = '''#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
static unsigned char join_frame[1388];
static unsigned int join_frequency=2462;
'''
source += section(wifi, 'static size_t radio_attr', '/* A fresh socket')
source += section(join, 'static const struct nlattr *ldn_attr_find', 'static int ldn_event_socket')
source += section(join, 'static bool ldn_bss_matches', '/* Read the complete multipart')
source += '''
int main(void) {
 unsigned char inner[256]={0},outer[300]={0},ssid[32],ie[34]={0,32};
 memset(ssid,'a',32);memcpy(ie+2,ssid,32);
 memcpy(join_frame+10,"abcdef",6);
 size_t n=radio_attr(inner,0,NL80211_BSS_BSSID,join_frame+10,6);
 n=radio_attr(inner,n,NL80211_BSS_FREQUENCY,&join_frequency,4);
 n=radio_attr(inner,n,NL80211_BSS_INFORMATION_ELEMENTS,ie,sizeof(ie));
 size_t len=radio_attr(outer,0,NL80211_ATTR_BSS|NLA_F_NESTED,inner,n);
 assert(ldn_bss_matches(outer,len,ssid));
 ssid[0]='b';assert(!ldn_bss_matches(outer,len,ssid));ssid[0]='a';
 join_frame[10]^=1;assert(!ldn_bss_matches(outer,len,ssid));join_frame[10]^=1;
 join_frequency=2412;assert(!ldn_bss_matches(outer,len,ssid));join_frequency=2462;
 for(size_t i=0;i<len;i++)assert(!ldn_bss_matches(outer,i,ssid));
 ((struct nlattr *)outer)->nla_len=2;assert(!ldn_bss_matches(outer,len,ssid));
 return 0;
}
'''
class ScanCacheTest(unittest.TestCase):
    def test_target_matching_and_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp, 'test.c')
            exe = Path(tmp, 'test')
            src.write_text(source)
            if sys.platform.startswith('linux'):
                subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
                subprocess.run([str(exe)], check=True)
            else:
                subprocess.run(['docker', 'run', '--rm', '-v', f'{tmp}:/test:ro', 'alpine:3.21', 'sh', '-c',
                                'apk add --no-cache build-base linux-headers >/dev/null && cc -Wall -Wextra -Werror /test/test.c -o /tmp/test && /tmp/test'], check=True)


if __name__ == '__main__':
    unittest.main()
