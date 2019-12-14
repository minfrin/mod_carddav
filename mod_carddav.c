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

#if 0
LoadModule carddav_module modules/mod_carddav.so

<Location /carddav>
   MaxSize 10000000  /* not used */
   CardDAV on        /* enabled */
</Location>
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "http_core.h"

#include "apr_strings.h"

#include "mod_dav.h"

#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME

#include "config.h"

#include "unixd.h"

#include <glib.h>
#include <glib-object.h>

#include <libxml/tree.h>

#include "mod_carddav.h"
#include "carddav_liveprops.h"
#include "mod_dav_acl.h"
#include "carddav_vcard.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

module AP_MODULE_DECLARE_DATA carddav_module;

#define CARDDAV_FILTER "carddav_filter_in"

/* server configuration data */
typedef struct _carddav_server_cfg {

} carddav_server_cfg;

/* directory configuration data */
typedef struct _carddav_dir_cfg {
    char *max_size;
    int enabled;

    const dav_provider *provider;
} carddav_dir_cfg;

static const char *carddav_xml_escape_uri(apr_pool_t *p, const char *uri)
{
    const char *e_uri = ap_escape_uri(p, uri);

    /* check the easy case... */
    if (ap_strchr_c(e_uri, '&') == NULL)
	return e_uri;

    return apr_xml_quote_string(p, e_uri, 0);
}

static void carddav_send_one_propstat_response(dav_response *response,
                                               apr_bucket_brigade *bb,
                                               ap_filter_t *output,
                                               apr_pool_t *pool)
{
    apr_text *t = NULL;

    if (response->propresult.propstats == NULL) {
	/* use the Status-Line text from Apache.  Note, this will
	 * default to 500 Internal Server Error if first->status
	 * is not a known (or valid) status code.
	 */
	ap_fputstrs(output, bb, "<D:status>HTTP/1.1 ",
		    ap_get_status_line (response->status),
		    "</D:status>" DEBUG_CR, NULL);
    }
    else {
	/* assume this includes <propstat> and is quoted properly */
	for (t = response->propresult.propstats; t; t = t->next)
	    ap_fputs(output, bb, t->text);
    }

    if (response->desc != NULL)
	/*
	 * We supply the description, so we know it doesn't have to
	 * have any escaping/encoding applied to it.
	 */
	ap_fputstrs(output, bb, "<D:responsedescription>",
		    response->desc, "</D:responsedescription>" DEBUG_CR, NULL);
}

static void carddav_send_one_response(dav_response *response,
                                      apr_bucket_brigade *bb,
                                      ap_filter_t *output, apr_pool_t *pool)
{
    apr_text *t = NULL;

    if (response->propresult.xmlns == NULL) {
	ap_fputs(output, bb, "<D:response>");
    }
    else {
	ap_fputs(output, bb, "<D:response");

	for (t = response->propresult.xmlns; t; t = t->next)
	    ap_fputs(output, bb, t->text);

	ap_fputc(output, bb, '>');
    }
    ap_fputstrs(output, bb, DEBUG_CR "<D:href>",
		carddav_xml_escape_uri(pool, response->href),
		"</D:href>" DEBUG_CR, NULL);

    carddav_send_one_propstat_response(response, bb, output, pool);

    ap_fputs(output, bb, "</D:response>" DEBUG_CR);
}

static void carddav_begin_multistatus(apr_bucket_brigade *bb, request_rec *r,
                                      int status,
                                      apr_array_header_t *namespaces)
{
    /* Set the correct status and Content-Type */
    r->status = status;
    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    /* Send the headers and actual multistatus response now... */
    ap_fputs(r->output_filters, bb, DAV_XML_HEADER DEBUG_CR
	     "<D:multistatus xmlns:D=\"DAV:\"");

    if (namespaces != NULL) {
	int i;

	for (i = namespaces->nelts; i--; )
	    ap_fprintf(r->output_filters, bb, " xmlns:ns%d=\"%s\"", i,
			APR_XML_GET_URI_ITEM (namespaces, i));
    }
    ap_fputs(r->output_filters, bb, ">" DEBUG_CR);
}

/* Finish a multistatus response started by dav_begin_multistatus: */
static apr_status_t carddav_finish_multistatus(request_rec *r,
                                               apr_bucket_brigade *bb)
{
    apr_bucket *b;

    ap_fputs(r->output_filters, bb, "</D:multistatus>" DEBUG_CR);

    /* indicate the end of the response body */
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    /* deliver whatever might be remaining in the brigade */
    return ap_pass_brigade(r->output_filters, bb);
}

#if 0
static void
carddav_send_multistatus(request_rec *r, int status,
			 dav_response *first,
			 apr_array_header_t *namespaces)
{
    apr_pool_t *subpool;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool,
						r->connection->bucket_alloc);

    dav_begin_multistatus(bb, r, status, namespaces);

    apr_pool_create(&subpool, r->pool);

    for ( ; first != NULL; first = first->next) {
	apr_pool_clear(subpool);
	carddav_send_one_response(first, bb, r->output_filters, subpool);
    }
    apr_pool_destroy(subpool);

    carddav_finish_multistatus(r, bb);
}
#endif


/* server config create */
static void *carddav_create_server_config(apr_pool_t *p, server_rec *s)
{
    int cb = sizeof(carddav_server_cfg);

    return apr_pcalloc(p, cb ? cb : 1);
}

static void *carddav_create_dir_config(apr_pool_t *p, char *dirspec)
{
    carddav_dir_cfg *conf = apr_pcalloc(p, sizeof(*conf));

    conf->provider = dav_lookup_provider(DAV_DEFAULT_PROVIDER);

    return conf;
}

#define STR_CONF_FUNC(x, val)							\
										\
static const char *carddav_##x(cmd_parms *cmd, void *mconfig, const char *pch)	\
{										\
    carddav_dir_cfg *conf = mconfig;						\
										\
    conf->x = (char *) apr_psprintf(cmd->pool, "%s", pch ? pch : val);		\
										\
    return NULL;								\
}

STR_CONF_FUNC(max_size, "100000000")

#define BOOL_CONF_FUNC(x)						\
static const char *carddav_##x(cmd_parms *cmd, void *config, int arg)	\
{									\
    carddav_dir_cfg *conf = config;					\
    conf->x = arg;							\
    return NULL;							\
}

BOOL_CONF_FUNC(enabled)

#define SDIRECTIVE(n, f, d)					\
    AP_INIT_TAKE1(						\
	n,		/* directive name */			\
	carddav_##f,	/* config action routine */		\
	NULL,		/* argument to include in call */	\
	OR_OPTIONS,	/* where available */			\
	d		/* directive description */		\
      )

#define FDIRECTIVE(n, f, d)					\
    AP_INIT_FLAG(n, carddav_##f, NULL, ACCESS_CONF|RSRC_CONF, d)


/* cmd callbacks */
static const command_rec carddav_cmds[] =
{
    SDIRECTIVE("MaxSize", max_size, "Maximum Size"),
    FDIRECTIVE("CardDAV", enabled, "CardDAV collection"),
	{ NULL }
};

#if 0
/** store resource type for a addressbook collection */
static int
carddav_store_resource_type (request_rec *r, const dav_resource *resource)
{
    dav_db *db;
    dav_namespace_map *map = NULL;
    dav_prop_name restype[1] = {{ NS_DAV, "resourcetype" }};
    apr_xml_elem el_child[1] = {{ 0 }};
    apr_array_header_t *ns;
    apr_text text = { 0 };
    const dav_provider *provider = dav_lookup_provider (DAV_DEFAULT_PROVIDER);
    const dav_hooks_propdb *db_hooks = provider ? provider->propdb : NULL;
    dav_error *err;

    if (!provider || !resource || !db_hooks)
	return -1;

    ns = apr_array_make (resource->pool, 3, sizeof (const char*));
    *(const char**)apr_array_push (ns) = NS_DAV;
    *(const char**)apr_array_push (ns) = NS_CARDDAV;

    el_child->name = "resourcetype";
    el_child->ns = 1;
    el_child->first_cdata.first = &text;
    text.text = "addressbook";

    db_hooks->open (resource->pool, resource, 0, &db);
    if (db) {
	err = db_hooks->map_namespaces (db, ns, &map);
	if (err) {
	    ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "%s  [%d, #%d]",
			   err->desc, err->status, err->error_id);
	    db_hooks->close (db);
	    return -1;
	}
	err = db_hooks->store (db, restype, el_child, map);
	if (err) {
	    ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "%s  [%d, #%d]",
			   err->desc, err->status, err->error_id);
	    db_hooks->close (db);
	    return -1;
	}
	db_hooks->close (db);
	return err ? -1 : 0;
    }
    return -1;
}
#endif

/* generic read for props */
static dav_error *carddav_read_allowed(request_rec *r,
                                       const dav_resource *resource)
{
    const dav_prop_name privs[] = { { NS_DAV, "read" } };

    return dav_acl_check(r, resource, ARRAY(privs));
}

/* allprops */
static dav_error *carddav_prop_allowed(request_rec *r,
                                       const dav_resource *resource,
                                       const dav_prop_name *name,
                                       dav_prop_insert what)
{
    const dav_prop_name privs[] = { { NS_DAV, "read" } };

    return dav_acl_check(r, resource, ARRAY(privs));
}

static dav_acl_provider *carddav_acl_hooks(void)
{
    static dav_acl_provider h =
    {
	.acl_check_read = carddav_read_allowed,
	.acl_check_prop = carddav_prop_allowed
    };

    return &h;
}

/** send properties of a single file */
static void carddav_send_props(apr_bucket_brigade *bb, request_rec *r,
                               request_rec *rf, dav_resource *resource,
                               apr_pool_t *subpool, carddav_search_t *p,
                               xmlNode *prop)
{
    dav_response response = { 0 };
    dav_propdb *propdb = NULL;

    rf->user = r->user;
    rf->per_dir_config = r->per_dir_config;
    rf->server = r->server;
    rf->method_number = r->method_number;

    response.href = rf->uri;

    if (prop) {
	apr_xml_doc *adoc = dav_acl_get_prop_doc(r, prop);

	dav_open_propdb(rf, NULL, resource, 1, adoc->namespaces, &propdb);

	/* store these for dav_get_props callbacks */
	resource->ctx = p;
	resource->acls = carddav_acl_hooks();
	response.propresult = dav_get_props(propdb, adoc);
    }

    apr_pool_clear(subpool);
    carddav_send_one_response(&response, bb, r->output_filters, subpool);

    if (propdb)
	dav_close_propdb(propdb);
}

/** init multistatus response */
static void carddav_init_multistatus(apr_bucket_brigade **bb, request_rec *r)
{
    if (bb == NULL || *bb)
	return;

    *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    carddav_begin_multistatus(*bb, r, HTTP_MULTI_STATUS, NULL);
}

/** send addressbook props from several files */
static void carddav_send_book_props(const char *subdir, int depth,
                                    int depth_current,
                                    apr_bucket_brigade **bb, request_rec *r,
                                    carddav_dir_cfg *conf, apr_pool_t *subpool,
                                    xmlNode *prop, void *p)
{
    const char *directory = subdir ? subdir : r->filename;
    struct dirent entry[offsetof(struct dirent, d_name) +
			pathconf(directory, _PC_NAME_MAX) + 1];
    DIR *dp;

    depth_current++;
    if (depth_current > depth)
	return;

    for (dp = opendir(directory); dp; ) {
	char *file;
	struct dirent *res = NULL;
	struct stat st;
	apr_status_t rc;

	if (readdir_r(dp, entry, &res) != 0 || res == NULL)
	    break;

	/* no current/parent dir or hidden file == .* */
	if (entry->d_name[0] == '.')
	    continue;

	file = apr_pstrcat(subpool, directory, entry->d_name, NULL);
	stat(file, &st);

	if ((st.st_mode & S_IFDIR) == S_IFDIR) {
	    if (depth_current >= depth)
		break;

	    file = apr_pstrcat(subpool, file, "/", NULL);
	    carddav_send_book_props(file, depth, depth_current, bb, r, conf,
				    subpool, prop, p);
	}
	else if ((st.st_mode & S_IFREG) == S_IFREG) {
	    dav_resource *resource = NULL;
	    xmlNode *carddata = NULL, *child = NULL;
	    request_rec *rf = apr_pcalloc(r->pool, sizeof(*rf));

	    rf->filename = file;
	    apr_pool_create(&rf->pool, NULL);
	    rf->uri = apr_pstrcat(rf->pool, r->uri,
				  file + strlen(r->filename), NULL);
	    rc = apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);

	    if (rc == APR_SUCCESS &&
		    conf->provider->repos->
			get_resource(rf, NULL, NULL, 0, &resource) == NULL) {
		carddav_search_t *p = NULL;

		FOR_CHILD(carddata, prop) {
		    if (NODE_NOT_CARDDAV(carddata))
			;
		    else if (NODE_MATCH(carddata, "address-data"))
			break;
		}

		child = prop ? prop->parent : NULL;
		FOR_CHILD(child, child) {
		    if (NODE_NOT_CARDDAV(child))
			;
		    else if (NODE_MATCH(child, "filter"))
			break;
		}

		if (child &&
		    carddav_vcard_search(rf->filename, carddata, child, &p)) {
		    carddav_init_multistatus(bb, r);
		    carddav_send_props(*bb, r, rf, resource, subpool, p, prop);
		}
		carddav_vcard_free(p);
	    }
	    apr_pool_destroy(rf->pool);
	}
    }
    closedir(dp);
}

/** dump multistatus response */
static int carddav_dump(void (*dump_props)(const char *subdir, int depth,
                                           int depth_current,
                                           apr_bucket_brigade **bb,
                                           request_rec *r,
                                           carddav_dir_cfg *conf,
                                           apr_pool_t *subpool,
                                           xmlNode *prop, void *p),
                        dav_resource *resource, request_rec *r,
                        carddav_dir_cfg *conf,
                        xmlNode *node, int depth, void *p)
{
    apr_pool_t *subpool;
    apr_bucket_brigade *bb = NULL;

    apr_pool_create(&subpool, r->pool);

    if (dump_props == carddav_send_book_props) {
	const char *if_none_match;

	dav_acl_last_mtime(NULL, r, subpool, 0);

	if ((if_none_match = apr_table_get(r->headers_in,
					   "If-None-Match")) != NULL) {
	    int cb = strlen(if_none_match);
	    const char *etag = r->mtime ? ap_make_etag(r, 0) : NULL;

	    if ((strcmp (if_none_match, "*") == 0 && etag != NULL) ||
		(if_none_match[0] == '"' && cb > 2 &&
		 if_none_match[cb - 1] == '"' &&
			etag && strcmp(if_none_match, etag) == 0)) {
		r->status_line = ap_get_status_line(r->status = 304);
		apr_pool_destroy(subpool);
		return 0;
	    }
	}
	ap_set_etag(r);
    }
    dump_props(NULL, depth, 0, &bb, r, conf, subpool, node, p);

    if (bb) {
	carddav_finish_multistatus(r, bb);
    }
    else {
	if (dump_props == carddav_send_book_props)
	    apr_table_unset(r->headers_out, "ETag");

	r->status_line = ap_get_status_line(r->status = 404);
    }
    apr_pool_destroy(subpool);

    return 0;
}

/** reply for multiget */
static void carddav_send_multiget(const char *subdir, int depth,
                                  int depth_current,
                                  apr_bucket_brigade **bb, request_rec *r,
                                  carddav_dir_cfg *conf, apr_pool_t *subpool,
                                  xmlNode *prop, void *p)
{
    apr_status_t rc;
    xmlNode *node = NULL;

    if (prop == NULL) {
	dav_handle_err(r, dav_new_error(r->pool, HTTP_NOT_FOUND, 0, APR_SUCCESS,
					"Property <prop> not given"), NULL);
	return;
    }

    if (depth_current >= depth)
	return;

    FOR_CHILD(node, prop->parent) {
	if (NODE_NOT_DAV(node)) {
	    ;
	}
	else if (NODE_MATCH(node, "href")) {
	    carddav_search_t *p = NULL;
	    dav_resource *resource = NULL;
	    dav_lookup_result lookup = { 0 };
	    apr_uri_t uri = { 0 };
	    request_rec *rf = apr_pcalloc(r->pool, sizeof(*rf));
	    xmlChar *pch = xmlNodeGetContent(node);

	    apr_pool_create(&rf->pool, NULL);
	    apr_uri_parse(rf->pool, (char *) pch, &uri);

	    lookup = dav_lookup_uri((char *) pch, r, uri.scheme != NULL);

	    if (lookup.rnew && lookup.rnew->status == HTTP_OK) {
		rf->filename = lookup.rnew->filename;
		rf->uri = lookup.rnew->uri;

		rc = apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);

		if (rc == APR_SUCCESS &&
		    conf->provider->repos->get_resource(rf, NULL, NULL, 0,
							&resource) == NULL) {
		    if (carddav_vcard_search(rf->filename, NULL, NULL, &p)) {
			carddav_init_multistatus(bb, r);
			carddav_send_props(*bb, r, rf, resource,
					   subpool, p, prop);
		    }
		    carddav_vcard_free(p);
		}
	    }
	    if (lookup.rnew)
		ap_destroy_sub_req(lookup.rnew);

	    apr_pool_destroy(rf->pool);
	    xmlFree(pch);
	}
    }
}

static int carddav_process_ctx_list(void (*func)(dav_prop_ctx *ctx),
                                    apr_array_header_t *ctx_list,
                                    int stop_on_error, int reverse)
{
    int i = ctx_list->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *) ctx_list->elts;

    if (reverse)
	ctx += i;

    while (i--) {
	if (reverse)
	    --ctx;

	func(ctx);
	if (stop_on_error && DAV_PROP_CTX_HAS_ERR(*ctx))
	    return 1;

	if (!reverse)
	    ++ctx;
    }

    return 0;
}

static void carddav_log_err(request_rec *r, dav_error *err, int level)
{
    dav_error *errscan;

    /* Log the errors */
    /* ### should have a directive to log the first or all */
    for (errscan = err; errscan != NULL; errscan = errscan->prev) {
        if (errscan->desc == NULL)
            continue;

        ap_log_rerror(APLOG_MARK, level, errscan->aprerr, r, "%s [%d, #%d]",
            errscan->desc, errscan->status, errscan->error_id);
    }
}

static void carddav_prop_log_errors(dav_prop_ctx *ctx)
{
    carddav_log_err(ctx->r, ctx->err, APLOG_ERR);
}

static void carddav_send_mkcol_response(request_rec *r, int status,
                                        dav_response *first,
                                        apr_array_header_t *namespaces)
{
    apr_pool_t *subpool;
    apr_bucket *b;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool,
						r->connection->bucket_alloc);

    /* Set the correct status and Content-Type */
    r->status = status;
    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    /* Send the headers and actual multistatus response now... */
    ap_fputs(r->output_filters, bb, DAV_XML_HEADER DEBUG_CR
	     "<D:mkcol-response xmlns:D=\"DAV:\"");

    if (namespaces != NULL) {
	int i;

	for (i = namespaces->nelts; i--; )
	    ap_fprintf(r->output_filters, bb, " xmlns:ns%d=\"%s\"", i,
			APR_XML_GET_URI_ITEM (namespaces, i));
    }
    ap_fputs(r->output_filters, bb, ">" DEBUG_CR);

    apr_pool_create(&subpool, r->pool);

    for ( ; first != NULL; first = first->next) {
	apr_pool_clear(subpool);

	carddav_send_one_propstat_response(first, bb, r->output_filters, subpool);
    }
    apr_pool_destroy(subpool);

    ap_fputs(r->output_filters, bb, "</D:mkcol-response>" DEBUG_CR);

    /* indicate the end of the response body */
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    /* deliver whatever might be remaining in the brigade */
    ap_pass_brigade(r->output_filters, bb);
}

#define ELEM_MATCHES(e,n,x,y)				\
  (e->name && strcmp(e->name, x) == 0 &&		\
   e->ns < n->nelts &&					\
   strcmp(APR_XML_GET_URI_ITEM(n, e->ns), y) == 0)

static int carddav_mkcol(carddav_dir_cfg *conf, request_rec *r)
{
    dav_response *multi_status;
    int resource_state, result;
    apr_xml_doc *doc;
    dav_auto_version_info av_info;
    const dav_prop_name privs[] = {
	{ NS_DAV, "write" }, { NS_DAV, "bind" } };
    dav_resource *resource = NULL, *parent = NULL;
    dav_error *err = NULL;

    if (conf->provider == NULL)
	return dav_handle_err(r, dav_new_error(r->pool, HTTP_FORBIDDEN, 0, APR_SUCCESS,
			       "Directory path not configured, you need some "
			       "carddav directives !"), NULL);

    if ((err = conf->provider->repos->get_resource(r, NULL, NULL, 0, &resource)))
	return dav_handle_err(r, err, NULL);

    if ((err = conf->provider->repos->get_parent_resource(resource, &parent)))
	return dav_handle_err(r, err, NULL);

    if ((err = dav_acl_check(r, parent, privs, sizeof (privs) / sizeof (privs[0]))))
	return dav_handle_err(r, err, NULL);

    if (resource->exists) {
	err = dav_new_error(r->pool, HTTP_FORBIDDEN, 0, APR_SUCCESS, "Collection exists already");
	err->tagname = "resource-must-be-null";
	return dav_handle_err(r, err, NULL);
    }
    resource_state = dav_get_resource_state(r, resource);

    if ((err = dav_validate_request(r, resource, 0, NULL, &multi_status,
				    resource_state == DAV_RESOURCE_NULL ?
				    DAV_VALIDATE_PARENT :
				    DAV_VALIDATE_RESOURCE, NULL)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, multi_status);
    }
    /* resource->collection = 1; */
    err = resource->hooks->create_collection(resource);

    /* restore modifiability of parent back to what it was */
    dav_auto_checkin(r, NULL, err != NULL, 0, &av_info);

    /* check for errors now */
    if (err != NULL)
	return dav_handle_err(r, err, NULL);
 /*
 <?xml version="1.0" encoding="utf-8" ?>
   <D:mkcol xmlns:D="DAV:"
                 xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:set>
       <D:prop>
         <D:resourcetype>
           <D:collection/>
           <C:addressbook/>
         </D:resourcetype>
         <D:displayname>Lisa's Contacts</D:displayname>
         <C:addressbook-description xml:lang="en">My primary address book.</C:addressbook-description>
       </D:prop>
     </D:set>
   </D:mkcol>

   <?xml version="1.0" encoding="utf-8" ?>
   <D:mkcol-response xmlns:D="DAV:"
                 xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:propstat>
       <D:prop>
         <D:resourcetype/>
         <D:displayname/>
         <C:addressbook-description/>
       </D:prop>
       <D:status>HTTP/1.1 200 OK</D:status>
     </D:propstat>
   </D:mkcol-response>
 */

    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
	resource->hooks->remove_resource(resource, &multi_status);

	err = dav_new_error(r->pool, HTTP_CONFLICT, 0, APR_SUCCESS,
			    "Body could not be parsed !");
	return dav_handle_err(r, err, NULL);
    }
    else if (doc) {
	dav_auto_version_info av_info;
	dav_propdb *propdb;
	dav_prop_ctx *ctx;
	apr_xml_elem *child;
	int failure = 0;
	apr_array_header_t *ctx_list;
	apr_text *propstat_text;
	dav_response resp = { 0 };

	/* make sure the resource can be modified (if versioning repository) */
	if ((err = dav_auto_checkout(r, resource, 0, &av_info)) != NULL) {
	    resource->hooks->remove_resource(resource, &multi_status);

	    /* ### add a higher-level description? */
	    return dav_handle_err(r, err, NULL);
	}
	if ((err = dav_open_propdb(r, NULL, resource, 0, doc->namespaces,
				   &propdb)) != NULL) {
	    resource->hooks->remove_resource(resource, &multi_status);

	    /* undo any auto-checkout */
	    dav_auto_checkin(r, resource, 1, 0, &av_info);

	    err = dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				 apr_psprintf (r->pool,
						"Could not open the property "
						"database for %s.",
						ap_escape_html(r->pool, r->uri)),
				 err);
	    return dav_handle_err(r, err, NULL);
	}
	/* set up an array to hold property operation contexts */
	ctx_list = apr_array_make(r->pool, 10, sizeof (dav_prop_ctx));

	/* do a first pass to ensure that all "remove" properties exist */
	for (child = doc->root->first_child; child; child = child->next) {
	    apr_xml_elem *prop_group, *one;

	    /* Ignore children that are not set/remove */
	    if (!ELEM_MATCHES(child, doc->namespaces, "set", NS_DAV))
		continue;

	    /* make sure that a "prop" child exists for set/remove */
	    if ((prop_group = dav_find_child(child, "prop")) == NULL) {
		dav_close_propdb(propdb);

		/* undo any auto-checkout */
		dav_auto_checkin(r, resource, 1, 0, &av_info);

		/* This supplies additional information for the default message. */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "A \"prop\" element is missing inside "
			      "the propertyupdate command.");
		return HTTP_BAD_REQUEST;
	    }
	    for (one = prop_group->first_child; one; one = one->next) {
		ctx = (dav_prop_ctx *) apr_array_push(ctx_list);
		ctx->propdb = propdb;
		ctx->operation = DAV_PROP_OP_SET;
		ctx->prop = one;
		ctx->r = r;

		if (ELEM_MATCHES(one, doc->namespaces, "resourcetype", "DAV:")) {
		    apr_xml_elem *c;

		    for (c = one->first_child; c; c = c->next )
			if (ELEM_MATCHES(c, doc->namespaces,
					 "addressbook", NS_CARDDAV))
			    break;

		    if (c)
			continue;
		    else
			ctx->err = dav_new_error(r->pool, HTTP_CONFLICT, APR_SUCCESS,
						 DAV_ERR_PROP_NOT_FOUND,
						 "Property not found.");
		}
		else {
		    dav_prop_validate(ctx);
		}

		if (DAV_PROP_CTX_HAS_ERR (*ctx))
		    failure = 1;
	    }
	}
	/* execute all of the operations */
	if (!failure && carddav_process_ctx_list(dav_prop_exec, ctx_list, 1, 0))
	    failure = 1;

	/* generate a failure/success response */
	if (failure) {
	    carddav_process_ctx_list(dav_prop_rollback, ctx_list, 0, 1);
	    propstat_text = dav_failed_proppatch(r->pool, ctx_list);

	    resource->hooks->remove_resource(resource, &multi_status);
	}
	else {
	    carddav_process_ctx_list(dav_prop_commit, ctx_list, 0, 0);
	    propstat_text = dav_success_proppatch(r->pool, ctx_list);
	}
	/* make sure this gets closed! */
	dav_close_propdb(propdb);

	/* complete any auto-versioning */
	dav_auto_checkin(r, resource, failure, 0, &av_info);

	/* log any errors that occurred */
	carddav_process_ctx_list(carddav_prop_log_errors, ctx_list, 0, 0);

	apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

	resp.href = resource->uri;
	/* ### should probably use something new to pass along this text... */
	resp.propresult.propstats = propstat_text;
	carddav_send_mkcol_response(r, !failure ? HTTP_CREATED : HTTP_CONFLICT,
				    &resp, doc->namespaces);

	if (!failure && (resource->acls = dav_get_acl_providers("acl")) &&
		resource->acls->acl_post_processing)
	    resource->acls->acl_post_processing(r, resource, 1);
	return DONE;
    }
    return DECLINED;
}

/** REPORT for carddav */
static int carddav_report(carddav_dir_cfg *conf, request_rec *r)
{
    dav_resource *resource = NULL;
    xmlDoc *doc = NULL;
    dav_error *err = NULL;
    ap_filter_t *inf;
    dav_buffer *buffer = NULL;
    int rc = 0;
    xmlNode *node;
    int depth;

    /* acl checks on individual reports */
    if (conf->provider) {
	conf->provider->repos->get_resource(r, NULL, NULL, 0, &resource);
    }
    else {
	err = dav_new_error(r->pool, HTTP_FORBIDDEN, 0, APR_SUCCESS,
			    "Directory path not configured, you need some "
			    "carddav directives !");
	return dav_handle_err(r, err, NULL);
    }

    /* read the body content from the buffer if it was consumed already by
     * another client */
    for (inf = r->input_filters; inf; inf = inf->next) {
	if (inf->frec && inf->frec->name &&
		strcmp(inf->frec->name, CARDDAV_FILTER) == 0) {
	    dav_acl_input_filter_t *f = inf->ctx;

	    if (f && f->r == r) {
		inf->ctx = NULL;
		buffer = &f->buffer;
		ap_remove_input_filter(inf);
		break;
	    }
	}
    }
    if (buffer == NULL) /* actually an internal error !!! */
	return DECLINED;

    if (buffer->cur_len == 0)
	rc = dav_acl_read_body(r, buffer);

    if (rc < 0 || !(doc = xmlReadMemory(buffer->buf, buffer->cur_len,
					NULL, NULL, XML_PARSE_NOWARNING)))
	return DECLINED;

    for (node = doc->children; node; node = node->next) {
	int query;

	if (NODE_NOT_CARDDAV(node)) {
	    if (node->type == XML_ELEMENT_NODE) {
		xmlFreeDoc(doc);
		return DECLINED;
	    }
	}
	else if ((query = NODE_MATCH(node, "addressbook-query")) ||
		     (NODE_MATCH(node, "addressbook-multiget"))) {
	    xmlNode *child = NULL;

	    if ((depth = dav_get_depth(r, 0)) < 0)
		goto error;

	    FOR_CHILD(child, node) {
		if (NODE_NOT_DAV(child))
		    ;
		else if (NODE_MATCH(child, "prop"))
		    break;
	    }
	    carddav_dump(query ? carddav_send_book_props : carddav_send_multiget,
			 resource, r, conf, child, depth, NULL);
	    break;
	}
	else if (node->type == XML_ELEMENT_NODE) {
	    xmlFreeDoc(doc);
	    return DECLINED;
	}
    }
    if (node == NULL) {
	xmlFreeDoc(doc);
	return DECLINED;
    }

    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");
    xmlFreeDoc(doc);

    return OK;

error:
    xmlFreeDoc(doc);
    err = dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, APR_SUCCESS,
			"Depth-header value incorrect");

    return dav_handle_err(r, err, NULL);
}

/* carddav request handler callback */
static int carddav_handler(request_rec *r)
{
    carddav_dir_cfg *conf =
	ap_get_module_config(r->per_dir_config, &carddav_module);
    const char *len;

    if (conf == NULL || conf->enabled == FALSE)
	return DECLINED;

    if (r->method_number == M_MKCOL &&
	(len = apr_table_get(r->headers_in, "Content-Length")) &&
		atoi (len) > 0)
	return carddav_mkcol(conf, r);
    else if (r->method_number == M_REPORT)
	return carddav_report(conf, r);
    else
	return DECLINED;
}

static void carddav_initialize_child(apr_pool_t *p, server_rec *s)
{
}

/** module init */
static int carddav_initialize_module(apr_pool_t *p, apr_pool_t *plog,
                                     apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *key = "carddav_start";

    /**
     * initialize_acl_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
#if !GLIB_CHECK_VERSION(2,35,0)
    g_type_init();
#endif

    apr_pool_userdata_get(&data, key, s->process->pool);
    if (data == NULL)
	apr_pool_userdata_set((const void *) 1, key,
			       apr_pool_cleanup_null, s->process->pool);
    return OK;
}

/** dav header callback in options request */
static dav_error *carddav_options_dav_header(request_rec *r,
                                             const dav_resource *resource,
                                             apr_text_header *phdr)
{
    apr_text_append(r->pool, phdr, "addressbook");

    return NULL;
}

/** method callback for options request */
static dav_error *carddav_options_dav_method(request_rec *r,
                                             const dav_resource *resource,
                                             apr_text_header *phdr)
{
    apr_text_append(r->pool, phdr, "REPORT");

    return NULL;
}

static
#if APACHE_PATCH
dav_hooks_options
#else
dav_options_provider
#endif
options =
{
    carddav_options_dav_header,
    carddav_options_dav_method,
    NULL
};

/** reponse for addressbook resource type */
static int carddav_get_resource_type(const dav_resource *resource,
                                     const char **name, const char **uri)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    carddav_dir_cfg *conf =
	ap_get_module_config(r->per_dir_config, &carddav_module);
    dav_prop_name prop = { "DAV:", "resourcetype" };
    const char *pch = dav_acl_get_prop(r, resource, conf->provider, &prop);

    if (pch && strstr(pch, "addressbook")) {
	*name = "addressbook";
	*uri = NS_CARDDAV;
	return 0;
    }

    *name = *uri = NULL;
    return -1;
}

static
#if APACHE_PATCH
dav_hooks_resource
#else
dav_resource_type_provider
#endif
res_hooks =
{
    carddav_get_resource_type
};

static void carddav_add_input_filter(request_rec *r)
{
    carddav_dir_cfg *conf;

    if (r->method_number == M_REPORT) {
	conf = ap_get_module_config(r->per_dir_config, &carddav_module);

	if (conf->enabled) {
	    dav_acl_input_filter_t *pctx = apr_pcalloc(r->pool, sizeof(*pctx));

	    pctx->r = r;
	    ap_add_input_filter(CARDDAV_FILTER, pctx, r, r->connection);
	}
    }
#if 0
    else if (r->method_number == M_MKCOL) {
	conf = ap_get_module_config(r->per_dir_config, &carddav_module);
	if (conf->enabled)
	    ap_add_output_filter(CARDDAV_FILTER, NULL, r, r->connection);
    }
#endif
}

#if 0
static apr_status_t carddav_output_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbOut;

    pbbOut = apr_brigade_create (r->pool, c->bucket_alloc);
    for (pbktIn = APR_BRIGADE_FIRST (pbbIn);
	 pbktIn != APR_BRIGADE_SENTINEL (pbbIn);
	 pbktIn = APR_BUCKET_NEXT (pbktIn)) {

	const char *data;
	apr_size_t len;
	char *buf;
	apr_bucket *pbktOut;

	if (APR_BUCKET_IS_EOS (pbktIn)) {
	    apr_bucket *pbktEOS = apr_bucket_eos_create (c->bucket_alloc);
	    APR_BRIGADE_INSERT_TAIL (pbbOut, pbktEOS);
	    continue;
	}
	apr_bucket_read (pbktIn, &data, &len, APR_BLOCK_READ);

	buf = apr_bucket_alloc (len, c->bucket_alloc);
	memcpy (buf, data, len);

	pbktOut = apr_bucket_heap_create (buf, len, apr_bucket_free, c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL (pbbOut, pbktOut);
    }

    if (r->status == 201 && r->method_number == M_MKCOL) {
	carddav_dir_cfg *conf = ap_get_module_config (r->per_dir_config, &carddav_module);

	if (conf->provider) {
	    dav_resource *resource = NULL;

	    conf->provider->repos->get_resource (r, NULL, NULL, 0, &resource);
	    if (!resource->collection) {
		resource->collection = TRUE;
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r,
			       "%s not a collection ??? forced to be one !!!", r->filename);
	    }
	    carddav_store_resource_type (r, resource);
	}
	else
	    ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r,
			   "addressbook resource-type could not be set for a resource (MKCOL request)");
    }

    /* XXX: is there any advantage to passing a brigade for each bucket? */
    return ap_pass_brigade (f->next, pbbOut);
}
#endif

/* initialize hooks */
static void carddav_register_hooks(apr_pool_t *p)
{
    static const char *const dav[] = { "mod_dav.c", NULL };

    ap_hook_insert_filter(carddav_add_input_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_input_filter(CARDDAV_FILTER, dav_acl_input_filter, NULL, AP_FTYPE_RESOURCE);
    // ap_register_output_filter (CARDDAV_FILTER, carddav_output_filter, NULL, AP_FTYPE_RESOURCE);

    ap_hook_post_config(carddav_initialize_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(carddav_handler, NULL, dav, APR_HOOK_MIDDLE);
    ap_hook_child_init(carddav_initialize_child, NULL, NULL, APR_HOOK_MIDDLE);

    /* live property handling */
    dav_hook_gather_propsets(carddav_gather_propsets, NULL, NULL, APR_HOOK_MIDDLE);
    dav_hook_find_liveprop(carddav_find_liveprop, NULL, NULL, APR_HOOK_MIDDLE);
    carddav_register_props(p);
#if APACHE_PATCH
    dav_options_register_hooks(p, "carddav", &options);

    dav_resource_register_hooks(p, "carddav", &res_hooks);
#else
    dav_options_provider_register(p, "carddav", &options);

    dav_resource_type_provider_register(p, "carddav", &res_hooks);
#endif
}

module AP_MODULE_DECLARE_DATA carddav_module =
{
    STANDARD20_MODULE_STUFF,
    carddav_create_dir_config,		/* per-directory config creator */
    NULL,				/* dir config merger */
    carddav_create_server_config,	/* server config creator */
    NULL, 				/* server config merger */
    carddav_cmds,			/* command table */
    carddav_register_hooks,		/* set up other request processing hooks */
};

