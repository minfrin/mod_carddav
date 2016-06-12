/**
 * This is part of a mod_carddav library.
 * 
 * Copyright (C) 2008 Nokia Corporation.
 * 
 * Contact: Jari Urpalainen <jari.urpalainen@nokia.com>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 */
#ifndef _CARDDAV_LIVEPROPS_H_
#define _CARDDAV_LIVEPROPS_H_

void carddav_register_props(apr_pool_t *p);
void carddav_gather_propsets(apr_array_header_t *uris);

int carddav_find_liveprop(const dav_resource *resource,
                          const char *ns_uri, const char *name,
                          const dav_hooks_liveprop **hooks);
#endif  /* _CARDDAV_LIVEPROPS_H_ */
