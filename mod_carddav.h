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
#ifndef _MOD_CARDDAV_H_
#define _MOD_CARDDAV_H_

#define NS_CARDDAV "urn:ietf:params:xml:ns:carddav"

#define XML_VERSION "1.0"

#define NODE_NS(node, ns_string) (node->ns && node->ns->href && \
				  strcmp((char *) node->ns->href, ns_string) == 0)

#define FOR_CHILD(node, parent) \
	for (node = parent ? parent->children : NULL; node; node = node->next)

#define NODE_NOT_DAV(node) node->type != XML_ELEMENT_NODE || !NODE_NS(node, NS_DAV)
#define NODE_NOT_CARDDAV(node) node->type != XML_ELEMENT_NODE || !NODE_NS(node, NS_CARDDAV)

#define NODE_MATCH(node, y) (strcmp((char *) node->name, y) == 0)

typedef struct carddav_search_s carddav_search_t;

#endif /* _MOD_CARDDAV_H_ */
