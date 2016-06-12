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
/*
 * carddav_liveprops.c: mod_carddav live property provider functions
 *
 */

#include <sys/types.h>

#include <glib.h>
#include <httpd.h>
#include <libxml/tree.h>

#include <mod_dav.h>

#include "mod_dav_acl.h"

#include "mod_carddav.h"
#include "carddav_vcard.h"
#include "apr_strings.h"

/*
** The namespace URIs that we use. This list and the enumeration must
** stay in sync.
*/
static const char * const carddav_namespace_uris[] =
{
    NS_CARDDAV,
    NULL	/* sentinel */
};

enum {
    CARDDAV_NAMESPACE_URI_NO = 0  /* the DAV: namespace URI */
};

#define CARDDAV_RO_PROP(name, enum_name) \
        { CARDDAV_NAMESPACE_URI_NO, name, CARDDAV_PROPID_##enum_name, 0 }
#define CARDDAV_RW_PROP(name, enum_name) \
        { CARDDAV_NAMESPACE_URI_NO, name, CARDDAV_PROPID_##enum_name, 1 }

enum {
    CARDDAV_PROPID_addressbook_description = 1,
    CARDDAV_PROPID_supported_address_data,
    CARDDAV_PROPID_max_resource_size,
    CARDDAV_PROPID_address_data,
    CARDDAV_PROPID_supported_collation_set,
    CARDDAV_PROPID_addressbook_home_set,
    CARDDAV_PROPID_principal_address,
};

static const dav_liveprop_spec carddav_props[] =
{
    CARDDAV_RO_PROP("supported-address-data", supported_address_data),
    CARDDAV_RO_PROP("max-resource-size", max_resource_size),
    CARDDAV_RW_PROP("addressbook-description", addressbook_description),
    CARDDAV_RO_PROP("address-data", address_data),
    CARDDAV_RO_PROP("supported-collation-set", supported_collation_set),
    CARDDAV_RW_PROP("addressbook-home-set", addressbook_home_set),
    CARDDAV_RW_PROP("principal-address", principal_address),
    { 0 } /* sentinel */
};

const dav_hooks_liveprop carddav_hooks_liveprop;

static const dav_liveprop_group carddav_liveprop_group =
{
    carddav_props,
    carddav_namespace_uris,
    &carddav_hooks_liveprop
};

static dav_prop_insert carddav_insert_prop(const dav_resource *resource,
                                           int propid, dav_prop_insert what,
                                           apr_text_header *phdr)
{
    const char *value = NULL;
    const char *s = NULL;
    apr_pool_t *p = resource->pool;
    const dav_liveprop_spec *info;
    int global_ns;
    char *fchar = NULL;

    if (!resource->exists)
	return DAV_PROP_INSERT_NOTDEF;

    /* ### we may want to respond to DAV_PROPID_resourcetype for PRIVATE
       ### resources. need to think on "proper" interaction with mod_dav */

    switch (propid) {
    case CARDDAV_PROPID_address_data:
	{
	    request_rec *r = resource->hooks->get_request_rec(resource);
	    carddav_search_t *p;

	    if (r->method_number != M_REPORT)
		return DAV_PROP_INSERT_NOTDEF;

	    p = resource->ctx;
	    value = fchar = carddav_vcard_dump(p);
	    if (value == NULL)
		return DAV_PROP_INSERT_NOTDEF;
	    break;
	}

    case CARDDAV_PROPID_supported_collation_set:
	if (what == DAV_PROP_INSERT_VALUE) {
	    global_ns = dav_get_liveprop_info(propid, &carddav_liveprop_group, &info);

	    s = apr_psprintf(p,
		 "<lp%d:%s>" DEBUG_CR
		 "<lp%d:supported-collation>i;ascii-casemap</lp%d:supported-collation>" DEBUG_CR
		 "<lp%d:supported-collation>i;octet</lp%d:supported-collation>" DEBUG_CR
		 "<lp%d:supported-collation>i;unicode-casemap</lp%d:supported-collation>" DEBUG_CR
		 "</lp%d:%s>" DEBUG_CR,
		 global_ns, info->name,
		 global_ns, global_ns,
		 global_ns, global_ns,
		 global_ns, global_ns,
		 global_ns, info->name);

	    apr_text_append(p, phdr, s);
	    return what;
	}
	break;

    case CARDDAV_PROPID_supported_address_data:
	if (what == DAV_PROP_INSERT_VALUE) {
	    global_ns = dav_get_liveprop_info(propid, &carddav_liveprop_group, &info);

	    s = apr_psprintf(p,
		"<lp%d:%s>" DEBUG_CR
		"<lp%d:address-data content-type=\"text/vcard\" version=\"3.0\"/>" DEBUG_CR
		"</lp%d:%s>" DEBUG_CR,
		global_ns, info->name,
		global_ns,
		global_ns, info->name);

	    apr_text_append(p, phdr, s);
	    return what;
	}
	break;

    default:
	/* ### what the heck was this property? */
	return DAV_PROP_INSERT_NOTDEF;
    }

    /* get the information and global NS index for the property */
    global_ns = dav_get_liveprop_info(propid, &carddav_liveprop_group, &info);

    /* assert: info != NULL && info->name != NULL */
    if (what == DAV_PROP_INSERT_VALUE)
	s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
			 global_ns, info->name, value, global_ns, info->name);
    else if (what == DAV_PROP_INSERT_NAME)
	s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, global_ns, info->name);
    else
	/* assert: what == DAV_PROP_INSERT_SUPPORTED */
	s = apr_psprintf(p, "<D:supported-live-property D:name=\"%s\" "
			 "D:namespace=\"%s\"/>" DEBUG_CR, info->name,
			 carddav_namespace_uris[info->ns]);

    apr_text_append(p, phdr, s);
    g_free(fchar);

    /* we inserted whatever was asked for */
    return what;
}

static int carddav_is_writable(const dav_resource *resource, int propid)
{
    const dav_liveprop_spec *info;

    dav_get_liveprop_info(propid, &carddav_liveprop_group, &info);

    return info->is_writable;
}

static dav_error *carddav_patch_validate(const dav_resource *resource,
                                         const apr_xml_elem *elem,
                                         int operation, void **context,
                                         int *defer_to_dead)
{
    /* NOTE: this function will not be called unless/until we have
     * modifiable (writable) live properties. */
    dav_elem_private *priv = elem->priv;

    switch (priv->propid) {
    case CARDDAV_PROPID_addressbook_home_set:
    case CARDDAV_PROPID_principal_address:
	if (!dav_acl_is_resource_principal(resource))
	    return dav_new_error(resource->pool, HTTP_CONFLICT, 0,
				 "The resource URI is not a principal");

	*defer_to_dead = TRUE;
	break;

    case CARDDAV_PROPID_addressbook_description:
	*defer_to_dead = TRUE;
	break;

    default:
	break;
    }

    return NULL;
}

static dav_error *carddav_patch_exec(const dav_resource *resource,
                                     const apr_xml_elem *elem,
                                     int operation, void *context,
                                     dav_liveprop_rollback **rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
     * modifiable (writable) live properties. */
    return NULL;
}

static void carddav_patch_commit(const dav_resource *resource, int operation,
                                 void *context,
                                 dav_liveprop_rollback *rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
     * modifiable (writable) live properties. */
}

static dav_error *carddav_patch_rollback(const dav_resource *resource,
                                         int operation, void *context,
                                         dav_liveprop_rollback *rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
     * modifiable (writable) live properties. */
    return NULL;
}

const dav_hooks_liveprop carddav_hooks_liveprop = {
    carddav_insert_prop,
    carddav_is_writable,
    carddav_namespace_uris,
    carddav_patch_validate,
    carddav_patch_exec,
    carddav_patch_commit,
    carddav_patch_rollback,
};

void carddav_gather_propsets(apr_array_header_t *uris)
{
}

int carddav_find_liveprop(const dav_resource *resource, const char *ns_uri,
                          const char *name, const dav_hooks_liveprop **hooks)
{
    /* don't try to find any liveprops if this isn't "our" resource
     * if (resource->hooks != &carddav_hooks_repos)
     *    return 0;
     */
    return dav_do_find_liveprop(ns_uri, name, &carddav_liveprop_group, hooks);
}

void carddav_register_props(apr_pool_t *p)
{
    /* register the namespace URIs */
    dav_register_liveprop_group(p, &carddav_liveprop_group);
}

