/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/**
 * @file nasl_crypto2.c
 * @brief This file contains all the crypto functionality needed by the SSH
 * protocol
 */

#include "nasl_aes_mac_gcm.h"

#include <gcrypt.h>
#include <stdlib.h>

#define NASL_ENCRYPT 0
#define NASL_DECRYPT 1
#define NASL_AAD 2

int
nasl_aes_mac_gcm (char *data, size_t data_len, char *key, size_t key_len,
                  char *iv, size_t iv_len, char **out)
{
  // guardian
  gpg_err_code_t err = 0;
  gcry_mac_hd_t hd;
  char *result;
  size_t result_len;

  if (key == NULL || key_len < 1)
    return GPG_ERR_MISSING_KEY;
  if (data == NULL || data_len < 1)
    return GPG_ERR_MISSING_VALUE;
  if (iv == NULL || iv_len < 1)
    return GPG_ERR_GENERAL;
  if (*out == NULL)
    {
      return GPG_ERR_GENERAL;
    }
  if ((err =
         gcry_mac_open (&hd, GCRY_MAC_GMAC_AES, GCRY_MAC_FLAG_SECURE, NULL)))
    return err;
  if ((err = gcry_mac_setkey (hd, key, key_len)))
    goto cexit;
  if ((err = gcry_mac_write (hd, data, data_len)))
    goto cexit;
  if ((err = gcry_mac_setiv (hd, iv, iv_len)))
    goto cexit;

  result_len = gcry_mac_get_algo_maclen (GCRY_MAC_GMAC_AES);
  result = malloc (result_len * sizeof (result));
  if (!result)
    {
      err = GPG_ERR_ENOMEM;
      goto cexit;
    }
  if ((err = gcry_mac_read (hd, result, &result_len)))
    goto cexit;

  *out = result;

cexit:
  gcry_mac_close (hd);
  return err;
}

unsigned int
get_aes_mac_gcm_len ()
{
  return gcry_mac_get_algo_maclen (GCRY_MAC_GMAC_AES);
}
