/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#include "picoquic_internal.h"
#include "picohash.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

picoquic_stored_bdp_t* picoquic_format_bdp(uint64_t time_valid_until,
    const uint8_t * ip_addr, uint8_t ip_addr_length, const picoquic_bdp_t * bdp)
{
    size_t bdp_size = sizeof(picoquic_stored_bdp_t) + ip_addr_length + 1;
    picoquic_stored_bdp_t* stored = (picoquic_stored_bdp_t*)malloc(bdp_size);
    
    if (stored != NULL) {
        uint8_t* next_p = ((uint8_t*)stored) + sizeof(picoquic_stored_bdp_t);
        memset(stored, 0, bdp_size);
        stored->time_valid_until = time_valid_until;
        stored->ip_addr = next_p;
        stored->ip_addr_length = ip_addr_length;
        memcpy(next_p, ip_addr, ip_addr_length);
        next_p += ip_addr_length;
        *next_p++ = 0;

        if (bdp != NULL) {
            stored->bdp[picoquic_bdp_lifetime] = bdp->lifetime;
            stored->bdp[picoquic_bdp_recon_bytes_in_flight] = bdp->recon_bytes_in_flight;
            stored->bdp[picoquic_bdp_recon_min_rtt] = bdp->recon_min_rtt;
        }
    }

    return stored;
}

int picoquic_serialize_bdp(const picoquic_stored_bdp_t * stored_bdp, uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t required_length;

    /* Compute serialized length */
    required_length = (size_t)(8 + 2) + stored_bdp->ip_addr_length + PICOQUIC_NB_BDP * 8;
    /* Serialize */
    if (required_length > bytes_max) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        picoformat_64(bytes + byte_index, stored_bdp->time_valid_until);
        byte_index += 8;

        picoformat_16(bytes + byte_index, stored_bdp->ip_addr_length);
        byte_index += 2;
        memcpy(bytes + byte_index, stored_bdp->ip_addr, stored_bdp->ip_addr_length);
        byte_index += stored_bdp->ip_addr_length;
        for (int i = 0; i < PICOQUIC_NB_BDP; i++) {
            picoformat_64(bytes + byte_index, stored_bdp->bdp[i]);
            byte_index += 8;
        }
        *consumed = byte_index;
    }

    return ret;
}

int picoquic_deserialize_bdp(picoquic_stored_bdp_t ** stored_bdp, uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    uint64_t time_valid_until = 0;
    size_t required_length = 8 + 2 + PICOQUIC_NB_BDP * 8;
    size_t byte_index = 0;
    size_t ip_addr_index = 0;
    uint8_t ip_addr_length = 0;
    /* There is no explicit TTL for bdps. We assume they are OK for 24 hours */
    uint64_t lifetime = ((uint64_t)24 * 3600) * ((uint64_t)1000000);
    uint64_t bdp[PICOQUIC_NB_BDP] = { lifetime, 0, 0 };

    *consumed = 0;
    *stored_bdp = NULL;

    if (required_length < bytes_max) {
        time_valid_until = PICOPARSE_64(bytes);
        byte_index = 8;
        ip_addr_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        ip_addr_index = byte_index;
        required_length += ip_addr_length;
        byte_index += ip_addr_length;
    }

    if (required_length <= bytes_max) {
        for (int i=0; i < PICOQUIC_NB_BDP; i++) {
            bdp[i] = PICOPARSE_64(bytes + byte_index);
            byte_index += 8;
        }
    }

    if (required_length > bytes_max) {
        *stored_bdp = NULL;
        ret = PICOQUIC_ERROR_INVALID_BDP;
    } else {
        *stored_bdp = picoquic_format_bdp(time_valid_until, bytes + ip_addr_index, ip_addr_length, NULL);
        if (*stored_bdp == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            for (int i=0; i < PICOQUIC_NB_BDP; i++) {
                (*stored_bdp)->bdp[i] = bdp[i];
            }                  
            *consumed = required_length;
        }
    }

    return ret;
}

int picoquic_register_net_bdp(picohash_table * hash_table, uint8_t const* ip_addr, uint8_t ip_addr_length, picoquic_stored_bdp_t* stored_bdp)
{
    int ret = 0;
    picoquic_net_bdp_key_t* key = (picoquic_net_bdp_key_t*)malloc(sizeof(picoquic_net_bdp_key_t));

    if (key == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(key, 0, sizeof(picoquic_net_bdp_key_t));
        key->ip_addr = (uint8_t*)malloc(ip_addr_length);
        memcpy(key->ip_addr, ip_addr, ip_addr_length);
        key->ip_addr_length = ip_addr_length;
        key->stored_bdp = stored_bdp;
        picohash_item* item = picohash_retrieve(hash_table, key);
        // Only keep last bdp: delete old value if exists then insert new one
        if (item != NULL) {
            picohash_delete_item(hash_table, item, 1);
        }
        ret = picohash_insert(hash_table, key);
    }

    if (key != NULL && ret != 0) {
        free(key);
        key = NULL;
    }

    return ret;
}

int picoquic_store_bdp(picohash_table * hash_table, uint64_t current_time,
    uint8_t const* ip_addr, uint8_t ip_addr_length, 
    picoquic_bdp_t const * bdp)
{
    int ret = 0;

    if (bdp == NULL) {
        ret = PICOQUIC_ERROR_INVALID_BDP;
    }
    else {
        uint64_t time_valid_until = current_time + (bdp->lifetime * ((uint64_t)1000));
        picoquic_stored_bdp_t* stored_bdp = picoquic_format_bdp(time_valid_until, ip_addr, ip_addr_length, bdp);
        if (stored_bdp == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            ret = picoquic_register_net_bdp(hash_table, ip_addr, ip_addr_length, stored_bdp); 
        }
    } 

    return ret;
}

int picoquic_get_bdp(picohash_table * hash_table, uint64_t current_time,
    uint8_t const* ip_addr, uint8_t ip_addr_length, picoquic_bdp_t * bdp)
{
    int ret = 0;
    picoquic_net_bdp_key_t* key = (picoquic_net_bdp_key_t*)malloc(sizeof(picoquic_net_bdp_key_t));
    picoquic_stored_bdp_t* stored_bdp = NULL; 
    
    if (key == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(key, 0, sizeof(picoquic_net_bdp_key_t));
        key->ip_addr = (uint8_t*)malloc(ip_addr_length);
        memcpy(key->ip_addr, ip_addr, ip_addr_length);
        key->ip_addr_length = ip_addr_length;
        picohash_item* item = picohash_retrieve(hash_table, key);
        ret = -1;
        if (item != NULL && ((picoquic_net_bdp_key_t*)(item->key))->stored_bdp->time_valid_until > current_time) {
            stored_bdp = ((picoquic_net_bdp_key_t*)(item->key))->stored_bdp;
            if (bdp != NULL && stored_bdp != NULL) {
                bdp->lifetime = stored_bdp->bdp[picoquic_bdp_lifetime];
                bdp->recon_bytes_in_flight = stored_bdp->bdp[picoquic_bdp_recon_bytes_in_flight];
                bdp->recon_min_rtt = stored_bdp->bdp[picoquic_bdp_recon_min_rtt];
                ret = 0;
            }
        }
    }

    if (key != NULL) {
        if (key->ip_addr != NULL) {
            free(key->ip_addr);
            key->ip_addr = NULL;
        }
        free(key);
        key = NULL;
    }

    return ret;
}

int picoquic_save_bdps(picohash_table * hash_table,
    uint64_t current_time, char const* bdp_file_name)
{
    int ret = 0;
    FILE* F = NULL;
    picoquic_stored_bdp_t* stored_bdp = NULL;

    if ((F = picoquic_file_open(bdp_file_name, "wb")) == NULL) {
        ret = -1;
    } else {
        int stop = 0;
        for (uint32_t i = 0; stop == 0 && i < hash_table->nb_bin; i++) {
             picohash_item* item = hash_table->hash_bin[i];
             while (ret == 0 && item != NULL) {
                 /* Only store the bdps that are valid going forward */
                 stored_bdp = ((picoquic_net_bdp_key_t *)(item->key))->stored_bdp;
                 if (stored_bdp->time_valid_until > current_time) {
                     /* Compute the serialized size */
                     uint8_t buffer[2048];
                     size_t record_size;
                     ret = picoquic_serialize_bdp(stored_bdp, buffer, sizeof(buffer), &record_size);
                     if (ret == 0) {
                         if (fwrite(&record_size, 4, 1, F) != 1 || fwrite(buffer, 1, record_size, F) != record_size) {
                             ret = PICOQUIC_ERROR_INVALID_FILE;
                             stop = 1;
                             break;
                         }
                     }
                 }
                 item = item->next_in_bin;
             }
       
        }     
        (void)picoquic_file_close(F);
    }

    return ret;
}

int picoquic_load_bdps(picohash_table * hash_table,
    uint64_t current_time, char const* bdp_file_name)
{
    int ret = 0;
    int file_ret = 0;
    FILE* F = NULL;
    picoquic_stored_bdp_t* stored_bdp = NULL;
    uint32_t record_size;
    uint32_t storage_size;

    if ((F = picoquic_file_open_ex(bdp_file_name, "rb", &file_ret)) == NULL) {
        ret = (file_ret == ENOENT) ? PICOQUIC_ERROR_NO_SUCH_FILE : -1;
    }

    while (ret == 0) {
        if (fread(&storage_size, 4, 1, F) != 1) {
            /* end of file */
            break;
        }
        else if (storage_size > 2048 ||
            (record_size = storage_size + offsetof(struct st_picoquic_stored_bdp_t, time_valid_until)) > 2048) {
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        }
        else {
            uint8_t buffer[2048];
            if (fread(buffer, 1, storage_size, F) != storage_size) {
                ret = PICOQUIC_ERROR_INVALID_FILE;
            }
            else {
                size_t consumed = 0;
                ret = picoquic_deserialize_bdp(&stored_bdp, buffer, storage_size, &consumed);

                if (ret == 0 && (consumed != storage_size || stored_bdp == NULL)) {
                    ret = PICOQUIC_ERROR_INVALID_FILE;
                }

                if (ret == 0 && stored_bdp != NULL) {
                    if (stored_bdp->time_valid_until < current_time) {
                        free(stored_bdp);
                        stored_bdp = NULL;
                    }
                    else {
                        stored_bdp->ip_addr = ((uint8_t*)stored_bdp) + sizeof(picoquic_stored_bdp_t);
                        picoquic_register_net_bdp(hash_table,  stored_bdp->ip_addr, stored_bdp->ip_addr_length, stored_bdp);
                    }
                }
            }
        }
    }

    (void)picoquic_file_close(F);

    return ret;
}

void picoquic_free_bdps(picohash_table * hash_table)
{
     if (hash_table != NULL) {
         for (uint32_t i = 0; i < hash_table->nb_bin; i++) {
              picohash_item* item = hash_table->hash_bin[i];
              while (item != NULL) {
                  picoquic_net_bdp_key_t * key = (picoquic_net_bdp_key_t *)item->key;
                  if (key->ip_addr != NULL) {
                     free(key->ip_addr);
                     key->ip_addr = NULL;
                  }
                  if (key->stored_bdp != NULL) {
                     free(key->stored_bdp);
                     key->stored_bdp = NULL;
                  }
                  item = item->next_in_bin;
              }

         }  

         picohash_delete(hash_table, 1);
     }
}

int picoquic_save_bdp_samples(picoquic_quic_t* quic, char const* bdp_store_filename)
{
    return picoquic_save_bdps(quic->table_bdp_by_net, picoquic_get_quic_time(quic), bdp_store_filename);
}

int picoquic_load_bdp_samples(picoquic_quic_t* quic, char const* bdp_store_filename)
{
    return picoquic_load_bdps(quic->table_bdp_by_net, picoquic_get_quic_time(quic), bdp_store_filename);
}

