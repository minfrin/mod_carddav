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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <glib.h>
#include <libebook/libebook.h>

#include <libxml/tree.h>
#include "mod_carddav.h"

/** parse a vcard file */
static EVCard *parse_vcard(const char *file)
{
    EVCard *c = NULL;
    char *str;
    gsize length;

    if (g_file_get_contents(file, &str, &length, NULL)) {
        c = e_vcard_new_from_string(str);
        g_free(str);
    }

    return c;
}

static char *endswith(const char *s1, const char *s2,
                      char * (*fn)(const char *a, const char *b))
{
    char *p;

    if ((p = fn(s1, s2)) && (strlen(p) == strlen(s2)))
        return p;
    else
        return NULL;
}

static char *beginswith(const char *s1, const char *s2,
                        char * (*fn)(const char *a, const char *b))
{
    char *p;

    if ((p = fn(s1, s2)) && (p == s1))
        return p;
    else
        return NULL;
}

static char *contains(const char *s1, const char *s2,
                      char * (*fn)(const char *a, const char *b))
{
    return fn(s1, s2);
}

typedef char *fn_s(const char *a, const char *b);

/** text match checkings */
static int text_matches(xmlNode *node, const char *pch)
{
    xmlChar *collation = xmlGetProp(node, (const xmlChar *) "collation");
    xmlChar *invert = xmlGetProp(node, (const xmlChar *) "negate-condition");
    xmlChar *match_type = xmlGetProp(node, (const xmlChar *) "match-type");
    xmlChar *value = xmlNodeGetContent(node);
    int rc = 0, feq = FALSE;
    fn_s *fn;
    int (*eq) (const xmlChar *a, const xmlChar *b);
    char * (*cmp) (const char *a, const char *b, fn_s *fn) = NULL;

    if (match_type == NULL || strcasecmp((char *) match_type, "contains") == 0)
        cmp = contains;
    else  if (strcasecmp((char *) match_type, "equals") == 0)
        feq = TRUE;
    else if (strcasecmp((char *) match_type, "starts-with") == 0)
        cmp = beginswith;
    else if (strcasecmp((char *) match_type, "ends-with") == 0)
        cmp = endswith;

    if (collation == NULL ||
        strcasecmp((char *) collation, "i;unicode-casemap") == 0 ||
                strcasecmp((char *) collation, "i;ascii-casemap") == 0) {
        fn = (fn_s *) xmlStrcasestr;
        eq = xmlStrcasecmp;
    }
    else {
        fn = (fn_s *) xmlStrstr;
        eq = xmlStrcmp;
    }

    if (feq)
        rc = (value && pch) ? eq((xmlChar *) pch, value) == 0 : 0;
    else if (cmp)
        rc = (value && pch) ? cmp(pch, (char *) value, fn) != NULL : 0;

    if ((feq || cmp) && invert && strcasecmp((char *) invert, "yes") == 0)
        rc = !rc;

    xmlFree(value);
    xmlFree(match_type);
    xmlFree(invert);
    xmlFree(collation);

    return rc;
}

/** parameter tests */
static int param_matches(xmlNode *node, EVCardAttribute *attr)
{
    xmlChar *pch = xmlGetProp(node, (const xmlChar *) "name");
    GList *p;

    if (pch == NULL)
        return FALSE;

    p = e_vcard_attribute_get_params(attr);

    for ( ; p; p = p->next) {
        EVCardAttributeParam *param = p->data;
        const char *name = e_vcard_attribute_param_get_name(param);

        if (name && strcasecmp(name, (char *) pch) == 0) {
            xmlNode *prop;

            FOR_CHILD(prop, node) {
                if (NODE_NOT_CARDDAV(prop)) {
                    ;
                }
                else if (NODE_MATCH(prop, "is-not-defined")) {
                    xmlFree(pch);
                    return FALSE;
                }
                else if (NODE_MATCH(prop, "text-match")) {
                    GList *v = e_vcard_attribute_param_get_values(param);

                    for ( ; v; v = v->next) {
                        if (text_matches(prop, v->data)) {
                            xmlFree(pch);
                            return TRUE;
                        }
                    }
                }
                else if (prop->type == XML_ELEMENT_NODE) {
                    /* rule not understood !!! */
                    xmlFree(pch);
                    return FALSE;
                }
            }
        }
    }
    xmlFree(pch);

    return FALSE;
}

static int attr_match(xmlNode *node, EVCardAttribute *attr)
{
    xmlNode *param;
    int ret = TRUE;
    xmlChar *allof = xmlGetProp(node, (const xmlChar *) "test");
    int and = (allof && strcasecmp((char *) allof, "allof") == 0);

    xmlFree(allof), allof = NULL;

    FOR_CHILD(param, node) {
        int rc = TRUE;

        if (NODE_NOT_CARDDAV(param)) {
            if (param->type == XML_ELEMENT_NODE)
                rc = FALSE;
            else
                continue;
        }
        else if (NODE_MATCH(param, "is-not-defined")) {
            rc = (attr == NULL);
        }
        else if (NODE_MATCH(param, "param-filter")) {
            rc = (attr && param_matches(param, attr)) == TRUE;
        }
        else if (NODE_MATCH(param, "text-match")) {
            GList *v = attr ? e_vcard_attribute_get_values(attr) : NULL;

            for (rc = FALSE; v; v = v->next) {
                if (text_matches(param, v->data)) {
                    rc = TRUE;
                    break;
                }
            }
        }
        else if (param->type == XML_ELEMENT_NODE) {
            rc = FALSE;
        }

        if ((and && rc == FALSE) || (and == FALSE && rc))
            return rc;

        ret = rc;
    }

    return ret;
}

/**
 * vcard search based on <filter> rules
 */
static int carddav_vcard_matches(EVCard *c, xmlNode *filter)
{
    xmlNode *node;
    int ret = TRUE, and;
    xmlChar *allof = xmlGetProp(filter, (const xmlChar *) "test");

    and = (allof && strcasecmp((char *) allof, "allof") == 0);
    xmlFree(allof), allof = NULL;

    for (node = filter ? filter->children : NULL; node; node = node->next) {
        if (NODE_NOT_CARDDAV(node)) {
            if (node->type == XML_ELEMENT_NODE && and)
                return FALSE;
            else
                continue;
        }
        else if (NODE_MATCH(node, "prop-filter")) {
            xmlChar *pch = xmlGetProp(node, (const xmlChar *) "name");
            int rc = FALSE;
            GList *l;

            if (pch == NULL)
                return FALSE;

            for (l = e_vcard_get_attributes(c); l; l = l->next) {
                EVCardAttribute *attr = l->data;
                const char *name = e_vcard_attribute_get_name(attr);

                if (name && strcasecmp((char *) pch, name) == 0) {
                    rc = attr_match(node, attr);

                    if (rc == TRUE)
                        break;
                }
            }
            xmlFree(pch);

            if ((and && rc == FALSE) || (and == FALSE && rc))
                return rc;

            ret = rc;
        }
        else if (node->type == XML_ELEMENT_NODE) {
            /* rule not understood !!! */
            if (and)
                return FALSE;
        }
    }

    return ret;
}

/* dump VCard contents after filtering */
static char *carddav_vcard_dump_query(EVCard *c, xmlNode *carddata)
{
    int all_props = -1;
    xmlNode *n = NULL;

    FOR_CHILD(n, carddata) {
        if (NODE_NOT_CARDDAV(n))
            ;
        else if (NODE_MATCH(n, "prop"))
            all_props = FALSE;
        else if (NODE_MATCH(n, "allprop"))
            all_props = TRUE;
    }

    if (all_props == FALSE) {
        GList *l = e_vcard_get_attributes(c);

        for ( ; l; ) {
            EVCardAttribute *attr = l->data;
            int f = FALSE;

            FOR_CHILD(n, carddata) {
                if (NODE_NOT_CARDDAV(n)) {
                    ;
                }
                else if (NODE_MATCH(n, "prop")) {
                    xmlChar *pch = xmlGetProp(n, (const xmlChar *) "name");
                    const char *name = e_vcard_attribute_get_name(attr);

                    if (pch && name && strcasecmp((char *) pch, name) == 0) {
                        f = TRUE;
                        break;
                    }
                    xmlFree(pch);
                }
            }

            if (f == FALSE) {
                GList *t = l->next;

                e_vcard_remove_attribute(c, attr);
                l = t;
            }
            else {
                xmlChar *val = xmlGetProp(n, (const xmlChar *) "novalue");

                if (val && strcasecmp((char *) val, "yes") == 0) {
                    e_vcard_attribute_remove_params(attr);
                    e_vcard_attribute_remove_values(attr);
                }
                xmlFree(val);

                l = l->next;
            }
        }
    }

    return e_vcard_to_string(c, EVC_FORMAT_VCARD_30);
}

/** local search structure */
struct carddav_search_s
{
    xmlNode *addressdata, *filter;
    EVCard *root;
};

/**
 * check if search criterias fit with this resource
 * allows request handler to omit this resource
 */
int carddav_vcard_search(const char *file, xmlNode *addressdata,
                         xmlNode *filter, carddav_search_t **pp)
{
    carddav_search_t *p = *pp = calloc(1, sizeof (*p));

    p->root = parse_vcard(file);
    p->addressdata = addressdata;
    p->filter = filter;

    if (filter == NULL)
        return 1;

    return carddav_vcard_matches(p->root, filter);
}

/** return vcard stuff for all requested reports */
char *carddav_vcard_dump(carddav_search_t *p)
{
    if (p == NULL)
        return NULL;

    /* dump full content */
    if (p->filter == NULL)
        return p->root ? e_vcard_to_string(p->root, EVC_FORMAT_VCARD_30) : NULL;

    /* dump selected components only */
    return carddav_vcard_dump_query(p->root, p->addressdata);
}

/** free resources for search/query */
int carddav_vcard_free(carddav_search_t *p)
{
    if (p == NULL)
        return -1;

    if (p->root) {
        g_object_unref(p->root);
        p->root = NULL;
    }

    free(p);

    return 0;
}
