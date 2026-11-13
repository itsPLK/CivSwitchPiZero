"""Bounds and format checks for untrusted over-the-air advertisements."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class AdvertisementTest(unittest.TestCase):
    def test_frame_boundaries(self):
        code = r'''
#include <assert.h>
#include "ldn_advertisement.h"
int main(void) {
    uint8_t f[1392] = {0};
    LdnAdvertisement a;
    f[0] = 0xd0; memcpy(f + 24, "\x7f\x00\x22\xaa", 4);
    f[68] = 4; f[69] = 2; f[70] = 5;
    for (size_t n = 0; n < 1388; n++) {
        assert(!ldn_advertisement_parse(f, n, &a));
        assert(a.ciphertext == NULL);
    }
    assert(ldn_advertisement_parse(f, 1388, &a));
    assert(a.payload_size == 1280 && a.ciphertext_size == 1312);
    assert(a.network_id == f + 36 && a.nonce == f + 72);
    assert(ldn_advertisement_parse(f, sizeof(f), &a));
    f[70] = 255; assert(!ldn_advertisement_parse(f, sizeof(f), &a)); f[70] = 5;
    f[69] = 0; assert(!ldn_advertisement_parse(f, sizeof(f), &a)); f[69] = 2;
    f[1] = 0x40; assert(!ldn_advertisement_parse(f, sizeof(f), &a)); f[1] = 0;
    f[24] = 0; assert(!ldn_advertisement_parse(f, sizeof(f), &a));
    assert(!ldn_advertisement_parse(NULL, 2000, &a));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d) / 'test.c'
            exe = pathlib.Path(d) / 'test'
            src.write_text(code)
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-I', str(ROOT / 'src'), str(src), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)
