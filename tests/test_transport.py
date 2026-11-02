"""Exercise the actual transport helpers with deterministic POSIX stubs."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class TransportTest(unittest.TestCase):
    def test_delivery_and_errors(self):
        source = (ROOT / 'src/init.c').read_text()
        helpers = source[source.index('static void drain_hid_out_reports'):source.index('#endif /* __linux__ */', source.index('static void drain_hid_out_reports'))]
        harness = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <assert.h>
#include <string.h>
static uint64_t ticks;
static int mode, writes, polls;
static uint64_t now_ms(void) { return ticks++; }
static int echo_len, echo_reads, echo_writes;
static ssize_t fake_read(int fd, void *b, size_t n) {
    if (echo_len && fd == 1 && echo_reads++ == 0) {
        assert(n >= (size_t)echo_len);
        memset(b, 0xA5, echo_len);
        return echo_len;
    }
    return -1;
}
static ssize_t fake_write(int fd, const void *b, size_t n) {
    if (echo_len) {
        assert(fd == 1 && n == (size_t)echo_len);
        for (size_t i = 0; i < n; i++) assert(((const unsigned char *)b)[i] == 0xA5);
        echo_writes++;
        return n;
    }
    writes++;
    if (mode == 2) { errno = EIO; return -1; }
    if (mode == 3 && writes == 1) { errno = EAGAIN; return -1; }
    if (mode == 4) return 1;
    return n;
}
static int fake_poll(struct pollfd *p, unsigned long n, int timeout) {
    polls++;
    ticks += 10;
    p->revents = 0;
    if (mode == 1 || (mode == 5 && writes)) return 0;
    if (polls < 5) return 0; /* endpoint busy longer than old 20ms limit */
    p->revents = POLLOUT;
    return 1;
}
#define read fake_read
#define write fake_write
#define poll fake_poll
'''
        harness += helpers + r'''
int main(void) {
    for (echo_len = 1; echo_len <= 64; echo_len++) {
        echo_reads = echo_writes = 0;
        drain_hid_out_reports(1, 2);
        assert(echo_writes == 0);
    }
    echo_len = 0;
    char report[8] = {0};
    for (mode = 0; mode < 6; mode++) {
        ticks = writes = polls = 0;
        bool ok = write_report_reliable(1, report, 8, 1, 2);
        assert(ok == (mode == 0 || mode == 3));
        if (ok) assert(polls >= 6); /* includes completion wait */
        if (mode == 1 || mode == 5) assert(errno == ETIMEDOUT);
        if (mode == 2 || mode == 4) assert(errno == EIO);
        if (mode == 3) assert(writes == 2);
    }
}
'''
        with tempfile.TemporaryDirectory() as d:
            c = pathlib.Path(d) / 'test.c'
            c.write_text(harness)
            exe = pathlib.Path(d) / 'test'
            subprocess.run(['cc', '-std=c11', str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)

if __name__ == '__main__':
    unittest.main()
