/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2003 Michel Arboi
 * SPDX-FileCopyrightText: 2002-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_AES_MAC_GCM_H
#define NASL_AES_MAC_GCM_H

#include <stdlib.h>

int
nasl_aes_mac_gcm (char *data, size_t data_len, char *key, size_t key_len,
                  char *iv, size_t iv_len, char **out);

unsigned int
get_aes_mac_gcm_len ();

#endif
