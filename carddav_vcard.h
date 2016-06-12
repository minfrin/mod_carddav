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

#ifndef _CARDDAV_VCARD_H_
#define _CARDDAV_VCARD_H_

int carddav_vcard_search(const char *file, xmlNode *data, xmlNode *filter,
                         carddav_search_t **p);

char *carddav_vcard_dump(carddav_search_t *p);
int carddav_vcard_free(carddav_search_t *p);

#endif  /* _CARDDAV_VCARD_H_ */
