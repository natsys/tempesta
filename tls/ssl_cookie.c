/*
 *  DTLS cookie callbacks implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_COOKIE_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "platform.h"
#else
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include "ssl_cookie.h"
#include "ssl_internal.h"

#include <string.h>

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * If DTLS is in use, then at least one of SHA-1, SHA-256, SHA-512 is
 * available. Try SHA-256 first, 512 wastes resources since we need to stay
 * with max 32 bytes of cookie for DTLS 1.0
 */
#if defined(MBEDTLS_SHA256_C)
#define COOKIE_MD           MBEDTLS_MD_SHA224
#define COOKIE_MD_OUTLEN    32
#define COOKIE_HMAC_LEN     28
#elif defined(MBEDTLS_SHA512_C)
#define COOKIE_MD           MBEDTLS_MD_SHA384
#define COOKIE_MD_OUTLEN    48
#define COOKIE_HMAC_LEN     28
#elif defined(MBEDTLS_SHA1_C)
#define COOKIE_MD           MBEDTLS_MD_SHA1
#define COOKIE_MD_OUTLEN    20
#define COOKIE_HMAC_LEN     20
#else
#error "DTLS hello verify needs SHA-1 or SHA-2"
#endif

/*
 * Cookies are formed of a 4-bytes timestamp (or serial number) and
 * an HMAC of timestemp and client ID.
 */
#define COOKIE_LEN      ( 4 + COOKIE_HMAC_LEN )

void mbedtls_ssl_cookie_init( mbedtls_ssl_cookie_ctx *ctx )
{
    mbedtls_md_init( &ctx->hmac_ctx );
    ctx->serial = 0;
    ctx->timeout = MBEDTLS_SSL_COOKIE_TIMEOUT;
    spin_lock_init( &ctx->mutex );
}

void mbedtls_ssl_cookie_set_timeout( mbedtls_ssl_cookie_ctx *ctx, unsigned long delay )
{
    ctx->timeout = delay;
}

void mbedtls_ssl_cookie_free( mbedtls_ssl_cookie_ctx *ctx )
{
    mbedtls_md_free( &ctx->hmac_ctx );
    mbedtls_zeroize( ctx, sizeof( mbedtls_ssl_cookie_ctx ) );
}

int mbedtls_ssl_cookie_setup( mbedtls_ssl_cookie_ctx *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;
    unsigned char key[COOKIE_MD_OUTLEN];

    if( ( ret = f_rng( p_rng, key, sizeof( key ) ) ) != 0 )
        return( ret );

    ret = mbedtls_md_setup( &ctx->hmac_ctx, mbedtls_md_info_from_type( COOKIE_MD ), 1 );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_md_hmac_starts( &ctx->hmac_ctx, key, sizeof( key ) );
    if( ret != 0 )
        return( ret );

    mbedtls_zeroize( key, sizeof( key ) );

    return( 0 );
}

/*
 * Generate the HMAC part of a cookie
 */
static int ssl_cookie_hmac( mbedtls_md_context_t *hmac_ctx,
                            const unsigned char time[4],
                            unsigned char **p, unsigned char *end,
                            const unsigned char *cli_id, size_t cli_id_len )
{
    unsigned char hmac_out[COOKIE_MD_OUTLEN];

    if( (size_t)( end - *p ) < COOKIE_HMAC_LEN )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    if( mbedtls_md_hmac_reset(  hmac_ctx ) != 0 ||
        mbedtls_md_hmac_update( hmac_ctx, time, 4 ) != 0 ||
        mbedtls_md_hmac_update( hmac_ctx, cli_id, cli_id_len ) != 0 ||
        mbedtls_md_hmac_finish( hmac_ctx, hmac_out ) != 0 )
    {
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    memcpy( *p, hmac_out, COOKIE_HMAC_LEN );
    *p += COOKIE_HMAC_LEN;

    return( 0 );
}

/*
 * Generate cookie for DTLS ClientHello verification
 */
int mbedtls_ssl_cookie_write( void *p_ctx,
                      unsigned char **p, unsigned char *end,
                      const unsigned char *cli_id, size_t cli_id_len )
{
    int ret;
    mbedtls_ssl_cookie_ctx *ctx = (mbedtls_ssl_cookie_ctx *) p_ctx;
    unsigned long t;

    if( ctx == NULL || cli_id == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( (size_t)( end - *p ) < COOKIE_LEN )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    t = (unsigned long) mbedtls_time( NULL );
    t = ctx->serial++;

    (*p)[0] = (unsigned char)( t >> 24 );
    (*p)[1] = (unsigned char)( t >> 16 );
    (*p)[2] = (unsigned char)( t >>  8 );
    (*p)[3] = (unsigned char)( t       );
    *p += 4;

    spin_lock( &ctx->mutex );

    ret = ssl_cookie_hmac( &ctx->hmac_ctx, *p - 4,
                           p, end, cli_id, cli_id_len );

    spin_unlock( &ctx->mutex );

    return( ret );
}

/*
 * Check a cookie
 */
int mbedtls_ssl_cookie_check( void *p_ctx,
                      const unsigned char *cookie, size_t cookie_len,
                      const unsigned char *cli_id, size_t cli_id_len )
{
    unsigned char ref_hmac[COOKIE_HMAC_LEN];
    int ret = 0;
    unsigned char *p = ref_hmac;
    mbedtls_ssl_cookie_ctx *ctx = (mbedtls_ssl_cookie_ctx *) p_ctx;
    unsigned long cur_time, cookie_time;

    if( ctx == NULL || cli_id == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( cookie_len != COOKIE_LEN )
        return( -1 );

    spin_lock( &ctx->mutex );

    if( ssl_cookie_hmac( &ctx->hmac_ctx, cookie,
                         &p, p + sizeof( ref_hmac ),
                         cli_id, cli_id_len ) != 0 )
        ret = -1;

    spin_unlock( &ctx->mutex );

    if( ret != 0 )
        return( ret );

    if( mbedtls_ssl_safer_memcmp( cookie + 4, ref_hmac, sizeof( ref_hmac ) ) != 0 )
        return( -1 );

    cur_time = (unsigned long) mbedtls_time( NULL );

    cookie_time = ( (unsigned long) cookie[0] << 24 ) |
                  ( (unsigned long) cookie[1] << 16 ) |
                  ( (unsigned long) cookie[2] <<  8 ) |
                  ( (unsigned long) cookie[3]       );

    if( ctx->timeout != 0 && cur_time - cookie_time > ctx->timeout )
        return( -1 );

    return( 0 );
}
#endif /* MBEDTLS_SSL_COOKIE_C */
