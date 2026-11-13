/* Structural validation of the encrypted LDN advertisement layout used by
 * esp32-ldn-civ7. No fields in the encrypted body are trusted before digest
 * verification. This parser accepts optional trailing 802.11 FCS bytes. */
#ifndef CIVSWITCH_LDN_ADVERTISEMENT_H
#define CIVSWITCH_LDN_ADVERTISEMENT_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    const uint8_t *network_id;
    const uint8_t *nonce;
    const uint8_t *ciphertext;
    size_t ciphertext_size;
    uint8_t version;
    uint16_t payload_size;
} LdnAdvertisement;

static bool ldn_advertisement_parse(const uint8_t *frame, size_t size,
                                    LdnAdvertisement *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!frame || size < 108 || (frame[0] & 0xfc) != 0xd0 ||
        (frame[1] & 0x40) || memcmp(frame + 24, "\x7f\x00\x22\xaa", 4)) return false;
    /* Reference uses encrypted format 2 with a 0x500-byte participant body. */
    if (frame[69] != 2) return false;
    uint16_t body = ((uint16_t)frame[70] << 8) | frame[71];
    if (body != 0x500 || size < 108u + body) return false;
    out->network_id = frame + 36;
    out->version = frame[68];
    out->nonce = frame + 72;
    out->ciphertext = frame + 76;
    out->ciphertext_size = 32u + body;
    out->payload_size = body;
    return true;
}
#endif
