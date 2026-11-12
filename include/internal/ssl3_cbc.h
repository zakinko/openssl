/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_INTERNAL_SSL3_CBC_H)
#define OSSL_INTERNAL_SSL3_CBC_H

#include <openssl/evp.h>

/*
 * The TLS MAC header is 13 bytes: seq_num(8) + type(1) + version(2) +
 * length(2) (RFC 5246 section 6.2.3.1).  The DTLS 1.2 Connection ID one of
 * RFC 9146 section 5.1 is seq_num_placeholder(8) + tls12_cid(1) +
 * cid_length(1) + tls12_cid(1) + version(2) + epoch(2) + sequence_number(6)
 * + cid(up to 255) + length_of_DTLSInnerPlaintext(2).
 */
#define SSL3_CBC_TLS_HEADER_LENGTH 13
#define SSL3_CBC_MAX_HEADER_LENGTH (8 + 1 + 1 + 1 + 2 + 2 + 6 + 255 + 2)

/* ssl3_cbc.c */
__owur char ssl3_cbc_record_digest_supported(const EVP_MD_CTX *ctx);
__owur int ssl3_cbc_digest_record(const EVP_MD *md,
    unsigned char *md_out,
    size_t *md_out_size,
    const unsigned char *header,
    size_t header_length,
    const unsigned char *data,
    size_t data_size,
    size_t data_plus_mac_plus_padding_size,
    const unsigned char *mac_secret,
    size_t mac_secret_length);

#endif /* !defined(OSSL_INTERNAL_SSL3_CBC_H) */
