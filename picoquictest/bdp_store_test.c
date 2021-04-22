/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>
#include "picoquic_internal.h"

static char const* test_bdp_file_name = "bdp_store_test.bin";


/*
 * The bdp store is extremely similar to the ticket store.
 */


/* IP addresses with individual hash */
static uint8_t const test_addr1[] = { 127, 0, 0, 1 };
static uint8_t const test_addr2[] = { 128, 12, 34, 56 };
static uint8_t const test_addr3[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static uint8_t const test_addr4[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

typedef struct st_test_bdp_store_addr_t {
    uint8_t const * ip_addr;
    uint8_t ip_addr_length;
} test_bdp_store_addr_t;

static test_bdp_store_addr_t test_ip_addr[] = {
    { test_addr1, (uint8_t)sizeof(test_addr1) },
    { test_addr2, (uint8_t)sizeof(test_addr2) },
    { test_addr3, (uint8_t)sizeof(test_addr3) },
    { test_addr4, (uint8_t)sizeof(test_addr4) },
};

static size_t nb_test_ip_addr = sizeof(test_ip_addr) / sizeof(test_bdp_store_addr_t);


/* Hash and compare for BDP hash table */
static uint64_t picoquic_net_bdp_hash(const void* key)
{
    const picoquic_net_bdp_key_t* net_bdp = (const picoquic_net_bdp_key_t*)key;

    return picohash_bytes(net_bdp->ip_addr, net_bdp->ip_addr_length);
}

static int picoquic_net_bdp_compare(const void* key1, const void* key2)
{
    const picoquic_net_bdp_key_t* net_bdp1 = (const picoquic_net_bdp_key_t*)key1;
    const picoquic_net_bdp_key_t* net_bdp2 = (const picoquic_net_bdp_key_t*)key2;

    int ret = -1;

    if (net_bdp1->ip_addr_length == net_bdp2->ip_addr_length && memcmp(net_bdp1->ip_addr, net_bdp2->ip_addr, net_bdp1->ip_addr_length) == 0) {
        ret = 0;
    }

    return ret;
}

static int bdp_store_compare(picohash_table * t1, picohash_table * t2)
{
    int ret = 0;
    picoquic_stored_bdp_t* s1 = NULL;
    picoquic_stored_bdp_t* s2 = NULL;
   
    if (t1 == t2) {
        ret = 0;
    }
    else if ((t1 == NULL || t2 == NULL) || ((t1->nb_bin != t2->nb_bin || t1->count != t2->count))) {
       ret = -1;
    } 
    else {
        for (uint32_t i = 0; ret == 0 && i < t1->nb_bin; i++) { 
             picohash_item* item1 = t1->hash_bin[i];
             picohash_item* item2 = t2->hash_bin[i];
             while (!(item1 == NULL && item2 == NULL)) {
                 if (item1 == NULL || item2 == NULL) {
                     ret = -1;
                     break;
                 }
                 s1 = ((picoquic_net_bdp_key_t *)(item1->key))->stored_bdp;
                 s2 = ((picoquic_net_bdp_key_t *)(item2->key))->stored_bdp;
                 if (s1->time_valid_until != s2->time_valid_until ||  
                     s1->ip_addr_length != s2->ip_addr_length || 
                     memcmp(s1->ip_addr, s2->ip_addr, s1->ip_addr_length) != 0 || 
                     s1->bdp[picoquic_bdp_lifetime] != s2->bdp[picoquic_bdp_lifetime] || 
                     s1->bdp[picoquic_bdp_recon_bytes_in_flight] != s2->bdp[picoquic_bdp_recon_bytes_in_flight] || 
                     s1->bdp[picoquic_bdp_recon_min_rtt] != s2->bdp[picoquic_bdp_recon_min_rtt]) {
                     ret = -1;
                     break;
                 }
                 else {
                     item1 = item1->next_in_bin;
                     item2 = item2->next_in_bin;
                }
             }
        }
    }

    return ret;
}



int bdp_store_test()
{
    int ret = 0;
    picohash_table * p_first_bdp =  picohash_create((size_t)16, picoquic_net_bdp_hash, picoquic_net_bdp_compare);
    picohash_table * p_first_bdp_bis =  picohash_create((size_t)16, picoquic_net_bdp_hash, picoquic_net_bdp_compare);
    picohash_table * p_first_bdp_ter =  picohash_create((size_t)16, picoquic_net_bdp_hash, picoquic_net_bdp_compare);
    picohash_table * p_first_bdp_empty =  picohash_create((size_t)16, picoquic_net_bdp_hash, picoquic_net_bdp_compare);

    uint64_t current_time = 50000000000ull;
    uint64_t retrieve_time = 60000000000ull;
    uint64_t too_late_time = 150000000000ull;
    uint64_t ttl = 10000000;

    /* Writing an empty file */
    ret = picoquic_save_bdps(p_first_bdp, current_time, test_bdp_file_name);

    /* Load the empty file again */
    if (ret == 0) {
        ret = picoquic_load_bdps(p_first_bdp_empty, retrieve_time, test_bdp_file_name);

        /* Verify that the content is empty */
        if (p_first_bdp_empty->count != 0) {
            if (ret == 0) {
                ret = -1;
            }
            picoquic_free_bdps(p_first_bdp_empty);
        }
    }
    /* Generate a set of bdps */
    for (size_t i = 0; ret == 0 && i < nb_test_ip_addr; i++) {
        size_t delta_factor = (i * nb_test_ip_addr);
        uint64_t delta_time = ((uint64_t)1000) * delta_factor;
        uint64_t lifetime = ttl + delta_time;
        picoquic_bdp_t bdp = { lifetime, (uint64_t)i, (uint64_t)i * nb_test_ip_addr };

        if (ret != 0) {
            break;
        }

        ret = picoquic_store_bdp(p_first_bdp, current_time, test_ip_addr[i].ip_addr, 
              test_ip_addr[i].ip_addr_length, &bdp);
        if (ret != 0) {
            break;
        }
    }

    /* Verify that they can be retrieved */
    for (size_t i = 0; ret == 0 && i < nb_test_ip_addr; i++) {
        size_t delta_factor = (i * nb_test_ip_addr);
        uint64_t delta_time = ((uint64_t)1000) * delta_factor;
        uint64_t expected_lifetime = ttl + delta_time;
        uint64_t expected_recon_bytes_in_flight = (uint64_t)i;
        uint64_t expected_recon_min_rtt = (uint64_t)i * nb_test_ip_addr;
        picoquic_bdp_t * bdp = (picoquic_bdp_t *)malloc(sizeof(picoquic_bdp_t));
        bdp->lifetime = 0;
        bdp->recon_bytes_in_flight = 0;
        bdp->recon_min_rtt = 0;
        ret = picoquic_get_bdp(p_first_bdp, current_time,
              test_ip_addr[i].ip_addr, test_ip_addr[i].ip_addr_length, bdp);
        if (ret != 0) {
            break;
        }
        if (bdp->lifetime != expected_lifetime || 
            bdp->recon_bytes_in_flight != expected_recon_bytes_in_flight || 
            bdp->recon_min_rtt != expected_recon_min_rtt) {
            ret = -1;
            break;
        }

        if (bdp != NULL) {
            free(bdp);
            bdp = NULL;
        }
    }
    /* Store them on a file */
    if (ret == 0) {
        ret = picoquic_save_bdps(p_first_bdp, current_time, test_bdp_file_name);
    }
    /* Load the file again */
    ret = picoquic_load_bdps(p_first_bdp_bis, retrieve_time, test_bdp_file_name);

    /* Verify that the two contents match */
    if (ret == 0) {
        ret = bdp_store_compare(p_first_bdp, p_first_bdp_bis);
    }

    /* Reload after a long time */
    if (ret == 0) {
        ret = picoquic_load_bdps(p_first_bdp_ter, too_late_time, test_bdp_file_name);
        if (ret == 0 && p_first_bdp_ter->count != 0) {
            ret = -1;
        }
    }
    /* Free what needs be */
    picoquic_free_bdps(p_first_bdp);
    picoquic_free_bdps(p_first_bdp_bis);
    picoquic_free_bdps(p_first_bdp_ter);

    return ret;
}


