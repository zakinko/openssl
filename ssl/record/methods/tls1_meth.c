/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include "internal/ssl3_cbc.h"
#include "../../ssl_local.h"
#include "../record_local.h"
#include "recmethod_local.h"

/* RFC 7905 section 2: "SecurityParameters.fixed_iv_length is twelve bytes" */
#define DTLS_CID_CHACHA_IV_LEN 12
/* RFC 9146 section 5: "seq_num_placeholder:  8 bytes of 0xff." */
#define DTLS_CID_SEQ_NUM_PLACEHOLDER_LEN 8
/* 8 + tls12_cid + cid_length + tls12_cid + version(2) + epoch(2) + seq(6) */
#define DTLS_CID_MAC_HEADER_FIXED_LEN (DTLS_CID_SEQ_NUM_PLACEHOLDER_LEN + 13)
/* ... + cid + a two byte length */
#define DTLS_CID_MAC_HEADER_MAX_LEN \
    (DTLS_CID_MAC_HEADER_FIXED_LEN + SSL_DTLS_CID_MAX_LEN + 2)

static int tls1_set_crypto_state(OSSL_RECORD_LAYER *rl, int level,
    unsigned char *snkey,
    unsigned char *key, size_t keylen,
    unsigned char *iv, size_t ivlen,
    unsigned char *mackey, size_t mackeylen,
    const EVP_CIPHER *snciph,
    const EVP_CIPHER *ciph,
    size_t taglen,
    int mactype,
    const EVP_MD *md,
    COMP_METHOD *comp)
{
    EVP_CIPHER_CTX *ciph_ctx;
    EVP_PKEY *mac_key;
    OSSL_PARAM params[2], *p = params;
    int enc = (rl->direction == OSSL_RECORD_DIRECTION_WRITE) ? 1 : 0;

    if (level != OSSL_RECORD_PROTECTION_LEVEL_APPLICATION)
        return OSSL_RECORD_RETURN_FATAL;

    if ((rl->enc_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        return OSSL_RECORD_RETURN_FATAL;
    }

    ciph_ctx = rl->enc_ctx;

    rl->md_ctx = EVP_MD_CTX_new();
    if (rl->md_ctx == NULL) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }
#ifndef OPENSSL_NO_COMP
    if (comp != NULL) {
        rl->compctx = COMP_CTX_new(comp);
        if (rl->compctx == NULL) {
            ERR_raise(ERR_LIB_SSL, SSL_R_COMPRESSION_LIBRARY_ERROR);
            return OSSL_RECORD_RETURN_FATAL;
        }
    }
#endif

    /*
     * If we have an AEAD Cipher, then there is no separate MAC, so we can skip
     * setting up the MAC key.
     */
    if ((EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) == 0) {
        if (mactype == EVP_PKEY_HMAC) {
            mac_key = EVP_PKEY_new_raw_private_key_ex(rl->libctx, "HMAC",
                rl->propq, mackey,
                mackeylen);
        } else {
            /*
             * If its not HMAC then the only other types of MAC we support are
             * the GOST MACs, so we need to use the old style way of creating
             * a MAC key.
             */
            mac_key = EVP_PKEY_new_mac_key(mactype, NULL, mackey,
                (int)mackeylen);
        }

        /*
         * We want the underlying mac to use our passed property query when allocating
         * its internal digest as well
         */
        if (rl->propq != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                (char *)rl->propq, 0);

        *p = OSSL_PARAM_construct_end();

        if (mac_key == NULL
            || EVP_DigestSignInit_ex(rl->md_ctx, NULL, EVP_MD_get0_name(md),
                   rl->libctx, rl->propq, mac_key,
                   params)
                <= 0) {
            EVP_PKEY_free(mac_key);
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return OSSL_RECORD_RETURN_FATAL;
        }
        EVP_PKEY_free(mac_key);
    }

    if (EVP_CIPHER_get_mode(ciph) == EVP_CIPH_GCM_MODE) {
        if (!EVP_CipherInit_ex(ciph_ctx, ciph, NULL, key, NULL, enc)
            || EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_GCM_SET_IV_FIXED,
                   (int)ivlen, iv)
                <= 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return OSSL_RECORD_RETURN_FATAL;
        }
    } else if (EVP_CIPHER_get_mode(ciph) == EVP_CIPH_CCM_MODE) {
        if (!EVP_CipherInit_ex(ciph_ctx, ciph, NULL, NULL, NULL, enc)
            || EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12,
                   NULL)
                <= 0
            || EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_TAG,
                   (int)taglen, NULL)
                <= 0
            || EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_CCM_SET_IV_FIXED,
                   (int)ivlen, iv)
                <= 0
            || !EVP_CipherInit_ex(ciph_ctx, NULL, NULL, key, NULL, enc)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return OSSL_RECORD_RETURN_FATAL;
        }
    } else {
        if (!EVP_CipherInit_ex(ciph_ctx, ciph, NULL, key, iv, enc)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return OSSL_RECORD_RETURN_FATAL;
        }
    }
    /* Needed for "composite" AEADs, such as RC4-HMAC-MD5 */
    if ((EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0
        && mackeylen != 0
        && EVP_CIPHER_CTX_ctrl(ciph_ctx, EVP_CTRL_AEAD_SET_MAC_KEY,
               (int)mackeylen, mackey)
            <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return OSSL_RECORD_RETURN_FATAL;
    }

    if (EVP_CIPHER_get0_provider(EVP_CIPHER_CTX_get0_cipher(ciph_ctx)) != NULL
        && !ossl_set_tls_provider_parameters(rl, ciph_ctx, ciph, md)) {
        /* ERR_raise already called */
        return OSSL_RECORD_RETURN_FATAL;
    }

    /* Calculate the explicit IV length */
    if (RLAYER_USE_EXPLICIT_IV(rl)) {
        int mode = EVP_CIPHER_CTX_get_mode(ciph_ctx);
        int eivlen = 0;

        if (mode == EVP_CIPH_CBC_MODE) {
            eivlen = EVP_CIPHER_CTX_get_iv_length(ciph_ctx);
            if (eivlen < 0) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_LIBRARY_BUG);
                return OSSL_RECORD_RETURN_FATAL;
            }
            if (eivlen <= 1)
                eivlen = 0;
        } else if (mode == EVP_CIPH_GCM_MODE) {
            /* Need explicit part of IV for GCM mode */
            eivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
        } else if (mode == EVP_CIPH_CCM_MODE) {
            eivlen = EVP_CCM_TLS_EXPLICIT_IV_LEN;
        }
        rl->eivlen = (size_t)eivlen;
    }

    if (rl->cid_len != 0) {
        int mode = EVP_CIPHER_get_mode(ciph);
        int aead = (EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;

        /*
         * RFC 9146 sections 5.2 (block cipher with Encrypt-then-MAC) and 5.3
         * (AEAD) are implemented, 5.1 (MAC-then-encrypt) is not; see
         * tls_dtls_cid_record_protection_ok(), which keeps the handshake from
         * getting here with one.  A "composite" cipher (AES-CBC-HMAC-SHA)
         * carries the AEAD flag but is CBC MAC-then-encrypt underneath.
         */
        if (!(aead && mode != EVP_CIPH_CBC_MODE)
            && !(rl->use_etm && mode == EVP_CIPH_CBC_MODE)) {
            ERR_raise(ERR_LIB_SSL, SSL_R_CONNECTION_ID_NOT_SUPPORTED_WITH_CIPHER);
            return OSSL_RECORD_RETURN_FATAL;
        }
        if (aead) {
            /*
             * The fixed part of the nonce: "salt[4]" for GCM (RFC 5288
             * section 3) and CCM (RFC 6655 section 3), the 12 byte write IV
             * for ChaCha20-Poly1305 (RFC 7905 section 2).
             */
            size_t want = (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_CCM_MODE)
                ? EVP_GCM_TLS_FIXED_IV_LEN
                : DTLS_CID_CHACHA_IV_LEN;

            if (ivlen != want || ivlen > sizeof(rl->cid_iv)) {
                ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
                return OSSL_RECORD_RETURN_FATAL;
            }
            memcpy(rl->cid_iv, iv, ivlen);
            rl->cid_ivlen = ivlen;
        }
    }

    return OSSL_RECORD_RETURN_SUCCESS;
}

static int setup_record_header(const OSSL_RECORD_LAYER *rl, TLS_RL_RECORD *rec,
    unsigned char *buf, size_t buflen)
{
    WPACKET hdr;
    size_t hdrsize;

    if (buflen < EVP_AEAD_TLS1_AAD_LEN)
        return 0;
    if (!WPACKET_init_static_len(&hdr, buf, EVP_AEAD_TLS1_AAD_LEN, 0)
        || (rl->isdtls && !WPACKET_put_bytes_u16(&hdr, rl->epoch))
        || (rl->isdtls ? !WPACKET_put_bytes_u48(&hdr, rl->sequence)
                       : !WPACKET_put_bytes_u64(&hdr, rl->sequence))
        || !WPACKET_put_bytes_u8(&hdr, rec->type)
        || !WPACKET_put_bytes_u16(&hdr, rl->version)
        || !WPACKET_put_bytes_u16(&hdr, rec->length)
        || !WPACKET_finish(&hdr)
        || !WPACKET_get_total_written(&hdr, &hdrsize)
        || hdrsize != EVP_AEAD_TLS1_AAD_LEN) {
        WPACKET_cleanup(&hdr);
        return 0;
    }

    return 1;
}

/*-
 * Write the part that RFC 9146 section 5 puts in front of the protected data
 * of a tls12_cid record, the same for the MAC of sections 5.1 and 5.2 and the
 * additional data of section 5.3:
 *
 *     seq_num_placeholder +
 *     tls12_cid +
 *     cid_length +
 *     tls12_cid +
 *     DTLSCiphertext.version +
 *     epoch +
 *     sequence_number +
 *     cid +
 *     <length>
 *
 * where <length> is length_of_DTLSInnerPlaintext in 5.1 and 5.3 and
 * DTLSCiphertext.length in 5.2.  The caller passes it in |length|.  "The
 * epoch and sequence_number are now fed into the MAC in the same order as
 * they appear on the wire" (5.1).
 */
static int dtls_cid_write_header(const OSSL_RECORD_LAYER *rl,
    const TLS_RL_RECORD *rec, size_t length,
    unsigned char *buf, size_t buflen, size_t *outlen)
{
    WPACKET hdr;
    int ok;

    if (!WPACKET_init_static_len(&hdr, buf, buflen, 0))
        return 0;
    ok = WPACKET_memset(&hdr, 0xff, DTLS_CID_SEQ_NUM_PLACEHOLDER_LEN)
        && WPACKET_put_bytes_u8(&hdr, SSL3_RT_TLS12_CID)
        /* "cid_length:  The length (in bytes) of the negotiated CID (one-byte integer)" */
        && WPACKET_put_bytes_u8(&hdr, rl->cid_len)
        && WPACKET_put_bytes_u8(&hdr, SSL3_RT_TLS12_CID)
        && WPACKET_put_bytes_u16(&hdr, rec->rec_version)
        && WPACKET_put_bytes_u16(&hdr, rl->epoch)
        && WPACKET_put_bytes_u48(&hdr, rl->sequence)
        && WPACKET_memcpy(&hdr, rl->cid, rl->cid_len)
        /* "two-byte integer"; 5 says the inner plaintext "MUST NOT exceed 2^14" */
        && WPACKET_put_bytes_u16(&hdr, length)
        && WPACKET_finish(&hdr)
        && WPACKET_get_total_written(&hdr, outlen);
    if (!ok)
        WPACKET_cleanup(&hdr);
    return ok;
}

/*
 * Encrypt or decrypt one tls12_cid record with an AEAD cipher (RFC 9146
 * section 5.3).  The additional data is not the 13 bytes of
 * EVP_CTRL_AEAD_TLS1_AAD, so the cipher is used through the generic AEAD
 * calls and the nonce, which the TLS mode of the cipher would otherwise build
 * itself, is built here.  Returns 1 on success and 0 when the record is
 * publicly invalid, fails authentication, or on internal error (in which case
 * RLAYERfatal() has been called), as tls1_cipher() does.
 */
static int dtls_cid_aead_cipher(OSSL_RECORD_LAYER *rl, TLS_RL_RECORD *rec,
    int sending)
{
    EVP_CIPHER_CTX *ds = rl->enc_ctx;
    int mode = EVP_CIPHER_CTX_get_mode(ds);
    unsigned char nonce[EVP_MAX_IV_LENGTH];
    unsigned char aad[DTLS_CID_MAC_HEADER_MAX_LEN];
    unsigned char seq64[8];
    unsigned char *explicit, *data, *tag;
    size_t aadlen, inlen, i;
    int outl;

    /*
     * RFC 6655 section 3 and RFC 7905 section 2: "In DTLS, the 64-bit
     * seq_num is the 16-bit epoch concatenated with the 48-bit seq_num."
     */
    for (i = 0; i < 2; i++)
        seq64[i] = (unsigned char)(rl->epoch >> (8 * (1 - i)));
    for (i = 0; i < 6; i++)
        seq64[2 + i] = (unsigned char)(rl->sequence >> (8 * (5 - i)));

    /*
     * |rec| holds nonce_explicit (|rl->eivlen| bytes, none for
     * ChaCha20-Poly1305), then the DTLSInnerPlaintext or its ciphertext,
     * then on reading the tag; on sending the tag goes after the ciphertext,
     * into the room tls_prepare_for_encryption_default() left for it.
     */
    if (sending) {
        if (rec->data != rec->input || rec->length < rl->eivlen) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        inlen = rec->length - rl->eivlen;
    } else {
        /* Publicly invalid: shorter than nonce_explicit plus the tag */
        if (rec->length < rl->eivlen + rl->taglen)
            return 0;
        inlen = rec->length - rl->eivlen - rl->taglen;
    }
    explicit = rec->input;
    data = rec->input + rl->eivlen;
    tag = data + inlen;

    if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_CCM_MODE) {
        /*
         * RFC 5288 section 3 and RFC 6655 section 3: nonce = salt[4] ||
         * nonce_explicit[8].  "Each value of the nonce_explicit MUST be
         * distinct for each distinct invocation of the GCM encrypt function
         * for any fixed key"; it "MAY be the 64-bit sequence number", which
         * is distinct within an epoch, whose keys are its own.
         */
        if (!ossl_assert(rl->eivlen == sizeof(seq64)
                && rl->cid_ivlen + rl->eivlen == EVP_GCM_TLS_FIXED_IV_LEN
                        + EVP_GCM_TLS_EXPLICIT_IV_LEN)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (sending)
            memcpy(explicit, seq64, sizeof(seq64));
        memcpy(nonce, rl->cid_iv, rl->cid_ivlen);
        memcpy(nonce + rl->cid_ivlen, explicit, rl->eivlen);
    } else {
        /*
         * RFC 7905 section 2: the sequence number "padded on the left with
         * four 0x00 bytes" and "XORed with the client_write_IV ... or
         * server_write_IV".
         */
        if (!ossl_assert(rl->eivlen == 0
                && rl->cid_ivlen == DTLS_CID_CHACHA_IV_LEN)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memcpy(nonce, rl->cid_iv, DTLS_CID_CHACHA_IV_LEN);
        for (i = 0; i < sizeof(seq64); i++)
            nonce[DTLS_CID_CHACHA_IV_LEN - sizeof(seq64) + i] ^= seq64[i];
    }

    /*
     * RFC 9146 section 5.3: the additional data ends with
     * length_of_DTLSInnerPlaintext, which these ciphers do not change.
     */
    if (!dtls_cid_write_header(rl, rec, inlen, aad, sizeof(aad), &aadlen)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (inlen > INT_MAX
        || !EVP_CipherInit_ex(ds, NULL, NULL, NULL, nonce, sending)
        /* CCM takes the tag before the data, and the data length up front */
        || (!sending
            && EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_SET_TAG, (int)rl->taglen,
                   tag)
                <= 0)
        || (mode == EVP_CIPH_CCM_MODE
            && !EVP_CipherUpdate(ds, NULL, &outl, NULL, (int)inlen))
        || !EVP_CipherUpdate(ds, NULL, &outl, aad, (int)aadlen)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* A failure from here on, when reading, is a record that is not genuine */
    if (!EVP_CipherUpdate(ds, data, &outl, data, (int)inlen)
        || (size_t)outl != inlen
        || (mode != EVP_CIPH_CCM_MODE
            && !EVP_CipherFinal_ex(ds, data + outl, &outl))) {
        if (sending)
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (sending) {
        if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_GET_TAG, (int)rl->taglen,
                tag)
            <= 0) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        rec->length += rl->taglen;
    } else {
        rec->data += rl->eivlen;
        rec->input += rl->eivlen;
        rec->length = inlen;
    }

    return 1;
}

#define MAX_PADDING 256
/*-
 * tls1_cipher encrypts/decrypts |n_recs| in |recs|. Calls RLAYERfatal on
 * internal error, but not otherwise. It is the responsibility of the caller to
 * report a bad_record_mac - if appropriate (DTLS just drops the record).
 *
 * Returns:
 *    0: if the record is publicly invalid, or an internal error, or AEAD
 *       decryption failed, or Encrypt-then-mac decryption failed.
 *    1: Success or Mac-then-encrypt decryption failed (MAC will be randomised)
 */
static int tls1_cipher(OSSL_RECORD_LAYER *rl, TLS_RL_RECORD *recs,
    size_t n_recs, int sending, unsigned char **mac,
    size_t macsize)
{
    EVP_CIPHER_CTX *ds;
    size_t reclen[SSL_MAX_PIPELINES];
    unsigned char buf[SSL_MAX_PIPELINES][EVP_AEAD_TLS1_AAD_LEN];
    unsigned char *data[SSL_MAX_PIPELINES];
    int pad = 0;
    size_t bs, ctr;
    const EVP_CIPHER *enc;
    int outlen;

    if (n_recs == 0) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_MD_CTX_get0_md(rl->md_ctx)) {
        int n = EVP_MD_CTX_get_size(rl->md_ctx);

        if (!ossl_assert(n >= 0)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    ds = rl->enc_ctx;
    if (!ossl_assert(rl->enc_ctx != NULL)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    enc = EVP_CIPHER_CTX_get0_cipher(rl->enc_ctx);

    /*
     * A tls12_cid record under an AEAD cipher (RFC 9146 section 5.3); the
     * record layer was only set up with a CID for a true AEAD or for CBC with
     * Encrypt-then-MAC (tls1_set_crypto_state()).
     */
    if (rl->cid_len != 0
        && (EVP_CIPHER_get_flags(enc) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0) {
        if (n_recs != 1) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        return dtls_cid_aead_cipher(rl, recs, sending);
    }

    if (sending) {
        int ivlen;

        /* For TLSv1.1 and later explicit IV */
        if (RLAYER_USE_EXPLICIT_IV(rl)
            && EVP_CIPHER_get_mode(enc) == EVP_CIPH_CBC_MODE)
            ivlen = EVP_CIPHER_get_iv_length(enc);
        else
            ivlen = 0;
        if (ivlen > 1) {
            for (ctr = 0; ctr < n_recs; ctr++) {
                if (recs[ctr].data != recs[ctr].input) {
                    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                } else if (RAND_bytes_ex(rl->libctx, recs[ctr].input,
                               ivlen, 0)
                    <= 0) {
                    RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            }
        }
    }
    if (!ossl_assert(enc != NULL)) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    bs = EVP_CIPHER_get_block_size(EVP_CIPHER_CTX_get0_cipher(ds));

    if (bs == 0) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_CIPHER);
        return 0;
    }

    if (n_recs > 1) {
        if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ds))
                & EVP_CIPH_FLAG_PIPELINE)
            == 0) {
            /*
             * We shouldn't have been called with pipeline data if the
             * cipher doesn't support pipelining
             */
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
            return 0;
        }
    }
    for (ctr = 0; ctr < n_recs; ctr++) {
        reclen[ctr] = recs[ctr].length;

        if ((EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ds))
                & EVP_CIPH_FLAG_AEAD_CIPHER)
            != 0) {
            /*
             * Publicly invalid: the record is shorter than the mandatory
             * AEAD overhead (explicit IV plus authentication tag). Leave
             * alert handling to the caller so TLS reports bad_record_mac
             * and DTLS silently discards the record.
             */
            if (!sending && reclen[ctr] < rl->eivlen + rl->taglen)
                return 0;

            if (!setup_record_header(rl, &recs[ctr], buf[ctr], sizeof(buf[ctr]))) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }

            if (!rl->isdtls && !tls_increment_sequence_ctr(rl)) {
                /* RLAYERfatal already called */
                return 0;
            }

            pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
                EVP_AEAD_TLS1_AAD_LEN, buf[ctr]);
            if (pad <= 0) {
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }

            if (sending) {
                reclen[ctr] += pad;
                recs[ctr].length += pad;
            }
        }

        if (!sending) {
            if (reclen[ctr] == 0 || reclen[ctr] % bs != 0) {
                /* Publicly invalid */
                return 0;
            }
        }
    }
    if (n_recs > 1) {
        /* Set the output buffers */
        for (ctr = 0; ctr < n_recs; ctr++)
            data[ctr] = recs[ctr].data;

        if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS,
                (int)n_recs, data)
            <= 0) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
            return 0;
        }
        /* Set the input buffers */
        for (ctr = 0; ctr < n_recs; ctr++)
            data[ctr] = recs[ctr].input;

        if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_SET_PIPELINE_INPUT_BUFS,
                (int)n_recs, data)
                <= 0
            || EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_SET_PIPELINE_INPUT_LENS,
                   (int)n_recs, reclen)
                <= 0) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, SSL_R_PIPELINE_FAILURE);
            return 0;
        }
    }

    if (!rl->isdtls && rl->tlstree) {
        int decrement_seq = 0;
        unsigned char recseq[SEQ_NUM_SIZE], *p_recseq = recseq;

        l2n8(rl->sequence, p_recseq);

        /*
         * When sending, seq is incremented after MAC calculation.
         * So if we are in ETM mode, we use seq 'as is' in the ctrl-function.
         * Otherwise we have to decrease it in the implementation
         */
        if (sending && !rl->use_etm)
            decrement_seq = 1;

        if (EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_TLSTREE, decrement_seq, recseq) <= 0) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /* Provided cipher - we do not support pipelining on this path */
    if (n_recs > 1) {
        RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!EVP_CipherUpdate(ds, recs[0].data, &outlen, recs[0].input,
            (int)reclen[0]))
        return 0;
    recs[0].length = outlen;

    /*
     * The length returned from EVP_CipherUpdate above is the actual
     * payload length. We need to adjust the data/input ptr to skip over
     * any explicit IV
     */
    if (!sending) {
        if (EVP_CIPHER_get_mode(enc) == EVP_CIPH_GCM_MODE) {
            recs[0].data += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            recs[0].input += EVP_GCM_TLS_EXPLICIT_IV_LEN;
        } else if (EVP_CIPHER_get_mode(enc) == EVP_CIPH_CCM_MODE) {
            recs[0].data += EVP_CCM_TLS_EXPLICIT_IV_LEN;
            recs[0].input += EVP_CCM_TLS_EXPLICIT_IV_LEN;
        } else if (bs != 1 && RLAYER_USE_EXPLICIT_IV(rl)) {
            recs[0].data += bs;
            recs[0].input += bs;
            recs[0].orig_len -= bs;
        }

        /* Now get a pointer to the MAC (if applicable) */
        if (mac != NULL) {
            OSSL_PARAM params[2], *p = params;

            /* Get the MAC */
            *p++ = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_TLS_MAC,
                (void **)mac, macsize);
            *p = OSSL_PARAM_construct_end();

            if (!EVP_CIPHER_CTX_get_params(ds, params)) {
                /* Shouldn't normally happen */
                RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR,
                    ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }

    return 1;
}

static int tls1_mac(OSSL_RECORD_LAYER *rl, TLS_RL_RECORD *rec, unsigned char *md,
    int sending)
{
    unsigned char seq[SEQ_NUM_SIZE], *p_seq = seq;
    EVP_MD_CTX *hash;
    size_t md_size;
    EVP_MD_CTX *hmac = NULL, *mac_ctx;
    EVP_PKEY_CTX *pkctx;
    unsigned char header[13];
    unsigned char cidheader[DTLS_CID_MAC_HEADER_MAX_LEN];
    size_t cidheaderlen = 0;
    int t;
    int ret = 0;

    hash = rl->md_ctx;
    l2n8(rl->sequence, p_seq);

    t = EVP_MD_CTX_get_size(hash);
    if (!ossl_assert(t >= 0))
        return 0;
    md_size = t;

    if (rl->stream_mac) {
        mac_ctx = hash;
    } else {
        hmac = EVP_MD_CTX_new();
        if (hmac == NULL || !EVP_MD_CTX_copy(hmac, hash)) {
            goto end;
        }
        mac_ctx = hmac;
    }

    if (!rl->isdtls
        && rl->tlstree
        && EVP_MD_CTX_ctrl(mac_ctx, EVP_MD_CTRL_TLSTREE, 0, seq) <= 0)
        goto end;

    /*
     * RFC 9146 section 5.2 (Encrypt-then-MAC): "DTLSCiphertext.length + IV +
     * ENC(content + padding + padding_length)".  DTLSCiphertext.length is
     * taken as for Encrypt-then-MAC without a CID, the length of what the MAC
     * covers after the header (RFC 7366 section 3), which is |rec->length|
     * here.  Section 5.1 (MAC-then-encrypt) is refused in
     * tls1_set_crypto_state().
     */
    if (rl->cid_len != 0) {
        if (!ossl_assert(rl->use_etm)
            || !dtls_cid_write_header(rl, rec, rec->length, cidheader,
                sizeof(cidheader), &cidheaderlen))
            goto end;
    } else if (!setup_record_header(rl, rec, header, sizeof(header))) {
        goto end;
    }

    if (!sending && !rl->use_etm
        && EVP_CIPHER_CTX_get_mode(rl->enc_ctx) == EVP_CIPH_CBC_MODE
        && ssl3_cbc_record_digest_supported(mac_ctx)) {
        OSSL_PARAM tls_hmac_params[2], *p = tls_hmac_params;

        *p++ = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE,
            &rec->orig_len);
        *p++ = OSSL_PARAM_construct_end();

        pkctx = EVP_MD_CTX_get_pkey_ctx(mac_ctx);
        if (pkctx == NULL) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto end;
        }

        if (!EVP_PKEY_CTX_set_params(pkctx, tls_hmac_params))
            goto end;
    }

    if ((cidheaderlen != 0
                ? EVP_DigestSignUpdate(mac_ctx, cidheader, cidheaderlen)
                : EVP_DigestSignUpdate(mac_ctx, header, sizeof(header)))
            <= 0
        || EVP_DigestSignUpdate(mac_ctx, rec->input, rec->length) <= 0
        || EVP_DigestSignFinal(mac_ctx, md, &md_size) <= 0)
        goto end;

    OSSL_TRACE_BEGIN(TLS)
    {
        BIO_printf(trc_out, "seq:\n");
        BIO_dump_indent(trc_out, seq, 8, 4);
        BIO_printf(trc_out, "rec:\n");
        BIO_dump_indent(trc_out, rec->data, (int)rec->length, 4);
    }
    OSSL_TRACE_END(TLS);

    if (!rl->isdtls && !tls_increment_sequence_ctr(rl)) {
        /* RLAYERfatal already called */
        goto end;
    }

    OSSL_TRACE_BEGIN(TLS)
    {
        BIO_printf(trc_out, "md:\n");
        BIO_dump_indent(trc_out, md, (int)md_size, 4);
    }
    OSSL_TRACE_END(TLS);
    ret = 1;
end:
    EVP_MD_CTX_free(hmac);
    return ret;
}

#if defined(SSL3_ALIGN_PAYLOAD) && SSL3_ALIGN_PAYLOAD != 0
#ifndef OPENSSL_NO_COMP
#define MAX_PREFIX_LEN ((SSL3_ALIGN_PAYLOAD - 1) \
    + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD        \
    + SSL3_RT_HEADER_LENGTH                      \
    + SSL3_RT_MAX_COMPRESSED_OVERHEAD)
#else
#define MAX_PREFIX_LEN ((SSL3_ALIGN_PAYLOAD - 1) \
    + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD        \
    + SSL3_RT_HEADER_LENGTH)
#endif /* OPENSSL_NO_COMP */
#else
#ifndef OPENSSL_NO_COMP
#define MAX_PREFIX_LEN (SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD \
    + SSL3_RT_HEADER_LENGTH                                 \
    + SSL3_RT_MAX_COMPRESSED_OVERHEAD)
#else
#define MAX_PREFIX_LEN (SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD \
    + SSL3_RT_HEADER_LENGTH)
#endif /* OPENSSL_NO_COMP */
#endif

int tls1_allocate_write_buffers(OSSL_RECORD_LAYER *rl,
    OSSL_RECORD_TEMPLATE *templates,
    size_t numtempl, size_t *prefix)
{
    /* Do we need to add an empty record prefix? */
    *prefix = rl->need_empty_fragments
        && templates[0].type == SSL3_RT_APPLICATION_DATA;

    /*
     * In the prefix case we can allocate a much smaller buffer. Otherwise we
     * just allocate the default buffer size
     */
    if (!tls_setup_write_buffer(rl, numtempl + *prefix,
            *prefix ? MAX_PREFIX_LEN : 0, 0)) {
        /* RLAYERfatal() already called */
        return 0;
    }

    return 1;
}

int tls1_initialise_write_packets(OSSL_RECORD_LAYER *rl,
    OSSL_RECORD_TEMPLATE *templates,
    size_t numtempl,
    OSSL_RECORD_TEMPLATE *prefixtempl,
    WPACKET *pkt,
    TLS_BUFFER *bufs,
    size_t *wpinited)
{
    size_t align = 0;
    TLS_BUFFER *wb;
    size_t prefix;

    /* Do we need to add an empty record prefix? */
    prefix = rl->need_empty_fragments
        && templates[0].type == SSL3_RT_APPLICATION_DATA;

    if (prefix) {
        /*
         * countermeasure against known-IV weakness in CBC ciphersuites (see
         * http://www.openssl.org/~bodo/tls-cbc.txt)
         */
        prefixtempl->buf = NULL;
        prefixtempl->version = templates[0].version;
        prefixtempl->buflen = 0;
        prefixtempl->type = SSL3_RT_APPLICATION_DATA;

        wb = &bufs[0];
        align = tls_get_record_body_alignment_offset(rl, TLS_BUFFER_get_buf(wb));
        TLS_BUFFER_set_offset(wb, align);

        if (!WPACKET_init_static_len(&pkt[0], TLS_BUFFER_get_buf(wb),
                TLS_BUFFER_get_len(wb), 0)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        *wpinited = 1;
        if (!WPACKET_allocate_bytes(&pkt[0], align, NULL)) {
            RLAYERfatal(rl, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return tls_initialise_write_packets_default(rl, templates, numtempl,
        NULL,
        pkt + prefix, bufs + prefix,
        wpinited);
}

/* TLSv1.0, TLSv1.1 and TLSv1.2 all use the same funcs */
const struct record_functions_st tls_1_funcs = {
    tls1_set_crypto_state,
    tls1_cipher,
    tls1_mac,
    tls_default_set_protocol_version,
    tls_default_read_n,
    tls_get_more_records,
    tls_default_validate_record_header,
    tls_default_post_process_record,
    tls_get_max_records_multiblock,
    tls_write_records_multiblock, /* Defined in tls_multib.c */
    tls1_allocate_write_buffers,
    tls1_initialise_write_packets,
    NULL,
    tls_prepare_record_header_default,
    NULL,
    tls_prepare_for_encryption_default,
    tls_post_encryption_processing_default,
    NULL
};

const struct record_functions_st dtls_1_funcs = {
    tls1_set_crypto_state,
    tls1_cipher,
    tls1_mac,
    tls_default_set_protocol_version,
    tls_default_read_n,
    dtls_get_more_records,
    NULL,
    dtls_cid_post_process_record,
    NULL,
    tls_write_records_default,
    /*
     * Don't use tls1_allocate_write_buffers since that handles empty fragment
     * records which aren't needed in DTLS. We just use the default allocation
     * instead.
     */
    tls_allocate_write_buffers_default,
    /* Don't use tls1_initialise_write_packets for same reason as above */
    tls_initialise_write_packets_default,
    dtls_cid_get_record_type,
    dtls_prepare_record_header,
    dtls_cid_add_record_padding,
    tls_prepare_for_encryption_default,
    dtls_post_encryption_processing,
    NULL
};
