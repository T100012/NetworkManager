/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_WIMAX_UTIL_H
#define NM_WIMAX_UTIL_H

#include <WiMaxType.h>
#include "nm-wimax-types.h"

void nm_wimax_util_error (struct WIMAX_API_DEVICE_ID *device_id,
			  const char *message,
			  WIMAX_API_RET result);

NMWimaxNspNetworkType nm_wimax_util_convert_network_type (WIMAX_API_NETWORK_TYPE wimax_network_type);
int nm_wimax_util_cinr_to_percentage (int cinr);

const char *nm_wimax_util_device_status_to_str (WIMAX_API_DEVICE_STATUS status);

#endif	/* NM_WIMAX_UTIL_H */