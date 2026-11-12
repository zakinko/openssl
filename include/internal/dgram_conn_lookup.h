/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_DGRAM_CONN_LOOKUP_H
#define OSSL_INTERNAL_DGRAM_CONN_LOOKUP_H
#pragma once

#include <openssl/ssl.h>
#include "internal/dgram_demux.h"

#ifndef OPENSSL_NO_DTLS

/*
 * DGRAM_CONN_LOOKUP - Address-based connection lookup for DTLS
 * =============================================================
 *
 * This provides connection lookup by peer address (IP:port) for DTLS.
 * QUIC uses its own QUIC_LCIDM for CID-based lookup and does not use
 * this interface.
 *
 * The lookup uses the peer address from the DGRAM_URXE to find the
 * associated connection.
 */

/* Forward declarations */
typedef struct dgram_conn_lookup_st DGRAM_CONN_LOOKUP;
typedef struct dgram_cid_lookup_st DGRAM_CID_LOOKUP;
typedef struct dgram_conn_lookup_methods_st DGRAM_CONN_LOOKUP_METHODS;

/* Callback type for iterating over connections */
typedef void (*ossl_dgram_conn_lookup_iter_fn)(SSL *ssl, const BIO_ADDR *peer,
    void *arg);

struct dgram_conn_lookup_methods_st {
    SSL *(*lookup)(DGRAM_CONN_LOOKUP *lookup, const DGRAM_URXE *e);
    int (*register_conn)(DGRAM_CONN_LOOKUP *lookup, const DGRAM_URXE *e, SSL *ssl);
    int (*register_conn_addr)(DGRAM_CONN_LOOKUP *lookup, const BIO_ADDR *peer, SSL *ssl);
    int (*unregister_conn)(DGRAM_CONN_LOOKUP *lookup, const BIO_ADDR *peer);
    void (*foreach)(DGRAM_CONN_LOOKUP *lookup, ossl_dgram_conn_lookup_iter_fn cb,
        void *arg);
    void (*free)(DGRAM_CONN_LOOKUP *lookup);
    size_t (*num_items)(const DGRAM_CONN_LOOKUP *lookup);
};

struct dgram_conn_lookup_st {
    const DGRAM_CONN_LOOKUP_METHODS *methods;
    void *impl_data;
};

/* Factory function for address-based lookup (DTLS) */
DGRAM_CONN_LOOKUP *ossl_dgram_conn_lookup_new_addr(void);

/*
 * Public API - calls through methods table.
 */
SSL *ossl_dgram_conn_lookup_find(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_URXE *e);
int ossl_dgram_conn_lookup_register(DGRAM_CONN_LOOKUP *lookup,
    const DGRAM_URXE *e, SSL *ssl);
int ossl_dgram_conn_lookup_register_addr(DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer,
    SSL *ssl);
int ossl_dgram_conn_lookup_unregister(DGRAM_CONN_LOOKUP *lookup,
    const BIO_ADDR *peer);
void ossl_dgram_conn_lookup_foreach(DGRAM_CONN_LOOKUP *lookup,
    ossl_dgram_conn_lookup_iter_fn cb,
    void *arg);
void ossl_dgram_conn_lookup_free(DGRAM_CONN_LOOKUP *lookup);
size_t ossl_dgram_conn_lookup_num_items(const DGRAM_CONN_LOOKUP *lookup);

/*
 * DGRAM_CID_LOOKUP - Connection ID based connection lookup for DTLS
 * =================================================================
 *
 * Finds a connection by the Connection ID (RFC 9146) in a record.  The
 * caller takes the CID out of the datagram, so the table holds byte strings
 * and knows nothing of the record formats.  It does not own the SSL objects.
 * Not internally synchronised: the caller holds the lock that serialises
 * access, as for DGRAM_CONN_LOOKUP.
 */

/**
 * @brief Create an empty CID lookup table.
 * @returns the table, or NULL on allocation failure
 */
DGRAM_CID_LOOKUP *ossl_dgram_cid_lookup_new(void);

/**
 * @brief Find the connection registered under a CID.
 * @param lookup the table
 * @param cid the CID bytes
 * @param cid_len the length of @p cid
 * @returns the connection, or NULL if none
 */
SSL *ossl_dgram_cid_lookup_find(DGRAM_CID_LOOKUP *lookup,
    const unsigned char *cid, size_t cid_len);

/**
 * @brief Register a connection under a CID that is not registered yet.
 * @param lookup the table
 * @param cid the CID bytes, copied
 * @param cid_len the length of @p cid
 * @param ssl the connection
 * @returns 1 on success, 0 on failure or if @p cid is already registered
 */
int ossl_dgram_cid_lookup_register(DGRAM_CID_LOOKUP *lookup,
    const unsigned char *cid, size_t cid_len, SSL *ssl);

/**
 * @brief Remove whatever CID a connection is registered under, if any.
 * @param lookup the table
 * @param ssl the connection
 */
void ossl_dgram_cid_lookup_unregister_ssl(DGRAM_CID_LOOKUP *lookup, SSL *ssl);

/**
 * @brief Count the registered CIDs.
 * @param lookup the table
 * @returns the number of entries
 */
size_t ossl_dgram_cid_lookup_num_items(const DGRAM_CID_LOOKUP *lookup);

/**
 * @brief Free the table and its entries, not the connections.
 * @param lookup the table, may be NULL
 */
void ossl_dgram_cid_lookup_free(DGRAM_CID_LOOKUP *lookup);

#endif /* OPENSSL_NO_DTLS */
#endif /* OSSL_INTERNAL_DGRAM_CONN_LOOKUP_H */
