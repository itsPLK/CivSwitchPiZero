/* Bounded, receive-only nl80211 monitor probe. No console keys required. */
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "ldn_advertisement.h"
#ifdef LDN_CRYPTO
#include "ldn_crypto.h"
#endif

static char radio_log[16384];
static size_t radio_used;
#define RADIO_LOG(...) do { if (radio_used < sizeof(radio_log)) { \
 int radio_log_written = snprintf(radio_log + radio_used, sizeof(radio_log) - radio_used, __VA_ARGS__); \
 if (radio_log_written > 0) radio_used += (size_t)radio_log_written; } } while (0)

static size_t radio_attr(unsigned char *b, size_t off, unsigned short type,
                         const void *data, size_t len) {
    struct nlattr a = {.nla_len = (unsigned short)(sizeof(a) + len), .nla_type = type};
    memcpy(b + off, &a, sizeof(a)); memcpy(b + off + sizeof(a), data, len);
    return off + NLA_ALIGN(a.nla_len);
}

/* A fresh socket per request avoids stale replies; kernel errors are logged verbatim. */
static int radio_request(int family, int cmd, unsigned char *attrs, size_t len, bool resolve) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) return -errno;
    struct timeval timeout = {.tv_sec = 3};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) { int e = errno; close(fd); return -e; }
    unsigned char request[512] = {0}, reply[8192];
    struct nlmsghdr h = {.nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + len,
        .nlmsg_type = family, .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK, .nlmsg_seq = 1};
    struct genlmsghdr g = {.cmd = cmd, .version = 1};
    memcpy(request, &h, sizeof(h)); memcpy(request + NLMSG_HDRLEN, &g, sizeof(g));
    memcpy(request + NLMSG_HDRLEN + GENL_HDRLEN, attrs, len);
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    int result = -ETIMEDOUT;
    if (sendto(fd, request, h.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) result = -errno;
    else for (int attempt = 0; attempt < 4; attempt++) {
        bool complete = false;
        ssize_t n = recv(fd, reply, sizeof(reply), 0);
        if (n < 0) { result = -errno; break; }
        else for (struct nlmsghdr *r = (void *)reply; NLMSG_OK(r, n); r = NLMSG_NEXT(r, n)) {
            if (r->nlmsg_seq != 1) continue;
            if (r->nlmsg_type == NLMSG_ERROR && r->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                result = ((struct nlmsgerr *)NLMSG_DATA(r))->error; complete = true; break;
            }
            if (resolve && r->nlmsg_len >= NLMSG_HDRLEN + GENL_HDRLEN) {
                size_t left = r->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
                unsigned char *p = (unsigned char *)NLMSG_DATA(r) + GENL_HDRLEN;
                while (left >= sizeof(struct nlattr)) {
                    struct nlattr a; memcpy(&a, p, sizeof(a));
                    if (a.nla_len < sizeof(a) || (size_t)NLA_ALIGN(a.nla_len) > left) break;
                    if (a.nla_type == CTRL_ATTR_FAMILY_ID && a.nla_len >= sizeof(a) + 2) {
                        unsigned short id; memcpy(&id, p + sizeof(a), 2); result = id; break;
                    }
                    left -= NLA_ALIGN(a.nla_len); p += NLA_ALIGN(a.nla_len);
                }
                if (result > 0) { complete = true; break; }
            }
        }
        if (complete) break;
    }
    close(fd); return result;
}

#ifdef LDN_CRYPTO
#include "ldn_join.h"
#endif

static void probe_ldn_radio(void) {
    unsigned char attrs[128] = {0};
    size_t len = radio_attr(attrs, 0, CTRL_ATTR_FAMILY_NAME, "nl80211", 8);
    int family = radio_request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attrs, len, true);
    RADIO_LOG("probe=ldn-auto-auth-v4 nl80211=%d\n", family);
#ifdef LDN_CRYPTO
    bool keys_ok = ldn_load_keys("/boot/prod.keys");
    RADIO_LOG("ldn_keys=%s\n", ldn_key_status);
    RADIO_LOG("ldn_key_errno=%d required_key_mask=%u\n", ldn_key_errno, ldn_key_mask);
    unsigned int verified = 0, failed = 0;
#endif
    if (family <= 0) return;
    int ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) { RADIO_LOG("control_socket_errno=%d\n", errno); return; }
    struct ifreq ifr = {0}; strcpy(ifr.ifr_name, "wlan0");
    if (ioctl(ctl, SIOCGIFINDEX, &ifr) < 0) { RADIO_LOG("interface_errno=%d\n", errno); close(ctl); return; }
    unsigned int index = ifr.ifr_ifindex;
    unsigned int retained_monitor = 0;
    if (ioctl(ctl, SIOCGIFFLAGS, &ifr) < 0) { close(ctl); return; }
    short parent_flags = ifr.ifr_flags;
    ifr.ifr_flags = parent_flags | IFF_UP;
    int parent_up = ioctl(ctl, SIOCSIFFLAGS, &ifr);
    RADIO_LOG("parent_up=%d errno=%d\n", parent_up, parent_up < 0 ? errno : 0);
    if (parent_up < 0) { close(ctl); return; }
    sleep_ms(500);
    /* cfg80211_set_monitor_channel requires monitors-only operation.
     * Preserve normal radio initialization, but stop the station before capture. */
    ifr.ifr_flags = parent_flags & ~IFF_UP;
    int parent_down = ioctl(ctl, SIOCSIFFLAGS, &ifr);
    RADIO_LOG("parent_down_before_monitor=%d errno=%d\n", parent_down, parent_down < 0 ? errno : 0);
    if (parent_down < 0) goto restore_parent;
    /* NEW_INTERFACE takes a parent IFINDEX to identify the radio. */
    unsigned int mode = NL80211_IFTYPE_MONITOR;
    len = radio_attr(attrs, 0, NL80211_ATTR_IFINDEX, &index, 4);
    len = radio_attr(attrs, len, NL80211_ATTR_IFTYPE, &mode, 4);
    len = radio_attr(attrs, len, NL80211_ATTR_IFNAME, "ldnmon0", 8);
    int result = radio_request(family, NL80211_CMD_NEW_INTERFACE, attrs, len, false);
    RADIO_LOG("create_monitor=%d (%s)\n", result, result < 0 ? strerror(-result) : "accepted");
    if (result == 0) {
        memset(&ifr, 0, sizeof(ifr)); strcpy(ifr.ifr_name, "ldnmon0");
        if (ioctl(ctl, SIOCGIFINDEX, &ifr) < 0) {
            RADIO_LOG("monitor_lookup_errno=%d\n", errno); goto restore_parent;
        }
        index = ifr.ifr_ifindex;
        RADIO_LOG("monitor_ifindex=%u\n", index);
        ifr.ifr_flags = IFF_UP;
        int up = ioctl(ctl, SIOCSIFFLAGS, &ifr);
        RADIO_LOG("interface_up=%d errno=%d\n", up, up < 0 ? errno : 0);
        int hardware = -1;
        if (ioctl(ctl, SIOCGIFHWADDR, &ifr) == 0) hardware = ifr.ifr_hwaddr.sa_family;
        RADIO_LOG("link_type=%d\n", hardware);
        int rx = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
        RADIO_LOG("packet_socket=%d errno=%d\n", rx >= 0 ? 0 : -1, rx < 0 ? errno : 0);
        struct sockaddr_ll addr = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = index};
        if (rx >= 0 && up == 0 && bind(rx, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
            (hardware == ARPHRD_IEEE80211_RADIOTAP || hardware == ARPHRD_IEEE80211)) {
            const unsigned int channels[] = {2412, 2437, 2462};
            for (size_t ch = 0; ch < 3; ch++) {
                len = radio_attr(attrs, 0, NL80211_ATTR_IFINDEX, &index, 4);
                len = radio_attr(attrs, len, NL80211_ATTR_WIPHY_FREQ, &channels[ch], 4);
                result = radio_request(family, NL80211_CMD_SET_WIPHY, attrs, len, false);
                unsigned int frames = 0, ldn = 0, packets = 0, valid_ldn = 0;
                int rx_error = 0;
                if (result == 0) for (int tick = 0; tick < 300; tick++) {
                    unsigned char packet[4096];
                    for (int burst = 0; burst < 32; burst++) {
                        ssize_t n = recv(rx, packet, sizeof(packet), 0);
                        if (n <= 0) {
                            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) rx_error = errno;
                            break;
                        }
                        packets++;
                        size_t offset = 0;
                        if (hardware == ARPHRD_IEEE80211_RADIOTAP) {
                            if (n < 8 || packet[0] != 0) continue;
                            offset = packet[2] | ((size_t)packet[3] << 8);
                            if (offset < 8) continue;
                        }
                        if (offset + 28 > (size_t)n) continue;
                        frames++;
                        if ((packet[offset] & 0xfc) == 0xd0 &&
                            memcmp(packet + offset + 24, "\x7f\x00\x22\xaa", 4) == 0) {
                            LdnAdvertisement advertisement;
                            ldn++;
                            if (ldn_advertisement_parse(packet + offset, (size_t)n - offset, &advertisement)) {
                                valid_ldn++;
#ifdef LDN_CRYPTO
                                if (keys_ok && verified + failed < 8) {
                                    unsigned char body[1280];
                                    if (ldn_decrypt_advertisement(packet + offset, (size_t)n - offset, body)) {
                                        verified++;
                                        if (!join_ready && advertisement.version == 4) {
                                            memcpy(join_frame, packet + offset, sizeof(join_frame));
                                            memcpy(join_body, body, sizeof(join_body));
                                            join_frequency = channels[ch]; join_ready = true;
                                        }
                                    }
                                    else failed++;
                                    OPENSSL_cleanse(body, sizeof(body));
                                }
#endif
                            }
                        }
                    }
                    sleep_ms(10);
                }
                RADIO_LOG("frequency=%u set_channel=%d packets=%u frames=%u ldn_advertisements=%u valid_layout=%u rx_errno=%d\n", channels[ch], result, packets, frames, ldn, valid_ldn, rx_error);
            }
        } else RADIO_LOG("capture_unavailable errno=%d\n", errno);
        if (rx >= 0) close(rx);
        ifr.ifr_flags = 0;
        int down = ioctl(ctl, SIOCSIFFLAGS, &ifr);
        RADIO_LOG("monitor_down=%d errno=%d\n", down, down < 0 ? errno : 0);
        retained_monitor = index;
        RADIO_LOG("monitor_retained=%u\n", retained_monitor);
    }
restore_parent:
#ifdef LDN_CRYPTO
    ldn_target_selected = cfg_ldn_install && join_ready;
    ldn_join_probe(family, ctl);
#endif
    if (retained_monitor) {
        len = radio_attr(attrs, 0, NL80211_ATTR_IFINDEX, &retained_monitor, 4);
        int deleted = radio_request(family, NL80211_CMD_DEL_INTERFACE, attrs, len, false);
        RADIO_LOG("delete_monitor_final=%d\n", deleted);
    }
    memset(&ifr, 0, sizeof(ifr)); strcpy(ifr.ifr_name, "wlan0");
    ifr.ifr_flags = parent_flags;
    int restored = ioctl(ctl, SIOCSIFFLAGS, &ifr);
    RADIO_LOG("restore_parent=%d errno=%d\n", restored, restored < 0 ? errno : 0);
#ifdef LDN_CRYPTO
    RADIO_LOG("advertisement_verified=%u verification_failed=%u\n", verified, failed);
    OPENSSL_cleanse(ldn_keys, sizeof(ldn_keys)); ldn_keys_ready = false;
#endif
    close(ctl);
}
