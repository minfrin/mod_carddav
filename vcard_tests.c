/*
 * Test cases for carddav search
 * This is part of a mod_carddav library.
 *
 * Copyright (C) 2011 Nokia Corporation.
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

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

#include <glib.h>
#include <libebook/libebook.h>
#include <glib/gstdio.h>

#include <libxml/tree.h>

#include "mod_carddav.h"
#include "carddav_vcard.h"

#define NS_DAV        "DAV:"


struct state {
        int dump;
} state[1] = {{ 0 }};


static void get_nodes(xmlDoc *doc, xmlNode **s, xmlNode **f)
{
    xmlNode *prop = NULL, *node = doc ? doc->children : NULL,
               *carddata = NULL, *filter = NULL;

    for ( ; node; node = node->next) {
        if (NODE_NOT_CARDDAV(node)) {
            ;
        }
        else if (NODE_MATCH(node, "addressbook-query")) {
            FOR_CHILD(prop, node) {
                if (NODE_NOT_DAV(prop))
                    ;
                else if (NODE_MATCH(prop, "prop"))
                    break;
            }
            break;
        }
    }

    FOR_CHILD(carddata, prop) {
        if (NODE_NOT_CARDDAV(carddata))
            ;
        else if (NODE_MATCH(carddata, "address-data"))
            break;
    }

    filter = prop ? prop->parent : NULL;

    FOR_CHILD(filter, filter) {
        if (NODE_NOT_CARDDAV(filter))
            ;
        else if (NODE_MATCH(filter, "filter"))
            break;
    }

    *s = carddata;
    *f = filter;
}

static int search(const char *tmp, xmlDoc *doc, xmlNode *carddata,
                  xmlNode *filter, int ret)
{
    carddav_search_t *p;
    int rc;

    if ((rc = carddav_vcard_search(tmp, carddata, filter, &p))) {
        char *pch = NULL;

        if (state->dump)
            printf("%s\n", pch = carddav_vcard_dump(p));
        free(pch);
    }
    else if (ret) {
        fprintf(stderr, "search did not find anything\n");
    }

    carddav_vcard_free(p);

    xmlFreeDoc(doc);
    g_unlink(tmp);

    return rc;
}

static int test(const char *buf, const char *vcard, int ret)
{
    xmlDoc *doc = xmlReadMemory(buf, strlen (buf), NULL, NULL,
                                XML_PARSE_NOWARNING);
    xmlNode *carddata = NULL, *filter = NULL;
    char tmp[] = "/tmp/vcard-XXXXXX";

    g_mkstemp(tmp);
    g_assert(g_file_set_contents(tmp, vcard, strlen(vcard), NULL) == TRUE);

    get_nodes(doc, &carddata, &filter);
    g_assert(carddata != NULL);

    g_assert(search(tmp, doc, carddata, filter, ret) == ret);

    return 0;
}

static const char vcard1[] =
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "FN:Cyrus Daboo\r\n"
        "N:Daboo;Cyrus\r\n"
        "ADR;TYPE=POSTAL:;2822 Email HQ;Suite 2821;RFCVille;PA;15213;USA\r\n"
        "EMAIL;TYPE=INTERNET,PREF:cyrus@example.com\r\n"
        "NICKNAME:foo,me\r\n"
        "NOTE:Example VCard.\r\n"
        "ORG:Self Employed\r\n"
        "TEL;TYPE=WORK,VOICE:412 605 0499\r\n"
        "TEL;TYPE=FAX:412 605 0705\r\n"
        "URL:http://www.example.com\r\n"
        "UID:1234-5678-9000-1\r\n"
        "END:VCARD\r\n";

static const char vcard2[] =
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "REV:2008-02-18T10:44:26Z\r\n"
        "UID:47B9618A00000004\r\n"
        "TEL;TYPE=CELL:123400002\r\n"
        "N:Pheckc;Jjsccj;;;\r\n"
        "PHOTO;TYPE=\"X-EVOLUTION-UNKNOWN\";ENCODING=b:/9j/4AAQSkZJRgABAQEARwBHAAD//gAXQ3JlYXRlZCB3aXRoIFRoZSBHSU1Q/9sAQwAIBgYHBgUIBwcHCQkICgwUDQwLCwwZEhMPFB0aHx4dGhwcICQuJyAiLCMcHCg3KSwwMTQ0NB8nOT04MjwuMzQy/9sAQwEJCQkMCwwYDQ0YMiEcITIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy/8AAEQgAMgAyAwEiAAIRAQMRAf/EABsAAQACAwEBAAAAAAAAAAAAAAAHCAQFBgID/8QAMBAAAgEDAQYEBQQDAAAAAAAAAQIDAAQRBQYSEyExQQdhcYEiI0JRkRQVMqFiguH/xAAaAQADAQEBAQAAAAAAAAAAAAAABAUCBgED/8QAIxEAAgICAQQCAwAAAAAAAAAAAAECAwQRQRITITEUYQUiUf/aAAwDAQACEQMRAD8An+sHUtWtNKjVrmQ7754cajLvjrgfbzPIdzWdVfds9pJb3XdQkMrcFZGj+HqY0bdVV9Tz/wBia+N9vbjvkaxMb5E9N6SJB1HxLEEjJaWsUjD6QzSMPXdGB7E1zV74t63HINy1s4F7CWCTn77wrA0TY86jY3N1qsUk6wxBxBDvYjLHkoUH4j3JP/a0V3s1CvF/QM9tKpw0THeU+TLkj8VLnmzT8y0n9FujBx5bioba/rZLWx3iPZ7RzLp95GtnqRGVTezHNjruH7/4n+67iqpq7Qi3uYWMMsNynfnE6sM8/Lr6VamFi0KMepUE1Sx7XZHbI+fjxos1H0z3SlKYEjzISI2I64OKqsyu8sck2QYrmPjBvpIYg598Vauoh8VtlY7JW2isoBwpPl6hGByZTyD+o6E+h7UtlVOcPHA/+PyI1Wal6Zp7vaC/06wnTTLtEeUDiKwzu4H8vI9AM9Tiuctkng1Nnk1G5cOoYifB4nI/jB7VjWuoT21qPmwXUCHKlphHKvqG5N6g0/cLi/Rg88FhbkbxlaUSu3kqpnn6kDzqGqbNdPB0XyK4/svZr9RVntL50GePdcKEDqzhVBx7sKtPpayppNosxzKIlDHzxUFeG2zo2n2kivWhK6PpHwwoTnfk65J7kZyT9z5VYADAwKuYtfRA5zPv7tnjgUpSmREV8bq1hvbWW1uY1khlUo6MMhgeor7UoAje18FtmLe9eeQT3EXPcglkJRPbv71EWu7Dajp2o3MGmlRCkjKQ30jPUe1WlrlNW0RptTleNB84DnjkD0P9VlxT4Nqck9pmn8JuFp2zo0cgCWFi2e7555/NSHXLadso2m3sU0NxlV65HM+VdTW3rgwvsUpSvAFKUoAUxSlAClKUAKUpQB//2Q==\r\n"
        "CALURI:http://example.com/foo/2\r\n"
        "X-EVOLUTION-FILE-AS:Toshok\\, Chris\r\n"
        "FN:Jjsccj Pheckc\r\n"
        "EMAIL;TYPE=INTERNET:toshok@ximian.com\r\n"
        "ORG:Ximian\\, Inc.;\r\n"
        "END:VCARD\r\n";

static void nickname(void)
{
    const char buf[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<C:addressbook-query xmlns:D=\"DAV:\""
        "  xmlns:C=\"urn:ietf:params:xml:ns:carddav\">"
        "  <D:prop>"
        "    <D:getetag/>"
        "    <C:address-data>"
        "      <C:prop name=\"VERSION\"/>"
        "      <C:prop name=\"UID\"/>"
        "      <C:prop name=\"NICKNAME\"/>"
        "      <C:prop name=\"EMAIL\"/>"
        "      <C:prop name=\"FN\"/>"
        "    </C:address-data>"
        "  </D:prop>"
        "  <C:filter>"
        "    <C:prop-filter name=\"NICKNAME\">"
        "      <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"equals\""
        "       >me</C:text-match>"
        "    </C:prop-filter>"
        "  </C:filter>"
        "</C:addressbook-query>";

    test(buf, vcard1, FALSE);
    test(buf, vcard2, FALSE);
}

static void cell(void)
{
    const char buf[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<C:addressbook-query xmlns:D=\"DAV:\""
        "  xmlns:C=\"urn:ietf:params:xml:ns:carddav\">"
        "  <D:prop>"
        "    <D:getetag/>"
        "    <C:address-data>"
        "      <C:prop name=\"VERSION\"/>"
        "      <C:prop name=\"UID\"/>"
        "      <C:prop name=\"NICKNAME\"/>"
        "      <C:prop name=\"EMAIL\"/>"
        "      <C:prop name=\"FN\"/>"
        "      <C:prop name=\"TEL\"/>"
        "    </C:address-data>"
        "  </D:prop>"
        "  <C:filter test=\"allof\">"
        "    <C:prop-filter name=\"TEL\">"
        "       <C:param-filter name=\"TYPE\">"
        "             <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"equals\""
        "       >CELL</C:text-match>"
        "       </C:param-filter>"
        "    </C:prop-filter>"
        "  </C:filter>"
        "</C:addressbook-query>";

    test(buf, vcard1, FALSE);
    test(buf, vcard2, TRUE);
}

static void dual(void)
{
    const char buf[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<C:addressbook-query xmlns:D=\"DAV:\""
        "  xmlns:C=\"urn:ietf:params:xml:ns:carddav\">"
        "  <D:prop>"
        "    <D:getetag/>"
        "    <C:address-data>"
        "      <C:prop name=\"VERSION\"/>"
        "      <C:prop name=\"UID\"/>"
        "      <C:prop name=\"NICKNAME\"/>"
        "      <C:prop name=\"EMAIL\"/>"
        "      <C:prop name=\"FN\"/>"
        "      <C:prop name=\"NOTE\"/>"
        "    </C:address-data>"
        "  </D:prop>"
        "  <C:filter test=\"allof\">"
        "    <C:prop-filter name=\"NICKNAME\">"
        "      <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"starts-with\""
        "       >foo</C:text-match>"
        "    </C:prop-filter>"
        "    <C:prop-filter name=\"NOTE\">"
        "     <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"contains\""
        "       >xample</C:text-match>"
        "    </C:prop-filter>"
        "  </C:filter>"
        "</C:addressbook-query>";

    test(buf, vcard1, TRUE);
    test(buf, vcard2, FALSE);
}

static void param_text(void)
{
    const char buf[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<C:addressbook-query xmlns:D=\"DAV:\""
        "  xmlns:C=\"urn:ietf:params:xml:ns:carddav\">"
        "  <D:prop>"
        "    <D:getetag/>"
        "    <C:address-data>"
        "      <C:prop name=\"VERSION\"/>"
        "      <C:prop name=\"UID\"/>"
        "      <C:prop name=\"NICKNAME\"/>"
        "      <C:prop name=\"EMAIL\"/>"
        "      <C:prop name=\"FN\"/>"
        "      <C:prop name=\"TEL\"/>"
        "    </C:address-data>"
        "  </D:prop>"
        "  <C:filter test=\"allof\">"
        "    <C:prop-filter name=\"TEL\" test=\"allof\">"
        "       <C:param-filter name=\"TYPE\">"
        "             <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"equals\""
        "       >CELL</C:text-match>"
        "              </C:param-filter>"
        "        <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"contains\""
        "       >1234</C:text-match>"
        "    </C:prop-filter>"
        "  </C:filter>"
        "</C:addressbook-query>";

    test(buf, vcard1, FALSE);
    test(buf, vcard2, TRUE);
}

static void anyof(void)
{
    const char buf[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<C:addressbook-query xmlns:D=\"DAV:\""
        "  xmlns:C=\"urn:ietf:params:xml:ns:carddav\">"
        "  <D:prop>"
        "    <D:getetag/>"
        "    <C:address-data>"
        "      <C:prop name=\"VERSION\"/>"
        "      <C:prop name=\"UID\"/>"
        "      <C:prop name=\"NICKNAME\"/>"
        "      <C:prop name=\"EMAIL\"/>"
        "      <C:prop name=\"FN\"/>"
        "      <C:prop name=\"TEL\"/>"
        "    </C:address-data>"
        "  </D:prop>"
        "  <C:filter test=\"allof\">"
        "    <C:prop-filter name=\"TEL\" test=\"anyof\">"
        "       <C:param-filter name=\"TYPE\">"
        "             <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"equals\""
        "       >FAX</C:text-match>"
        "              </C:param-filter>"
        "        <C:text-match collation=\"i;unicode-casemap\""
        "                    match-type=\"contains\""
        "       >1234</C:text-match>"
        "    </C:prop-filter>"
        "  </C:filter>"
        "</C:addressbook-query>";

    test(buf, vcard1, TRUE);
    test(buf, vcard2, TRUE);
}

static void empty(void)
{
    const char buf[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<C:addressbook-query xmlns:D=\"DAV:\""
        "  xmlns:C=\"urn:ietf:params:xml:ns:carddav\">"
        "  <D:prop>"
        "    <D:getetag/>"
        "    <C:address-data/>"
        "  </D:prop>"
        "  <C:filter>"
        "    <C:prop-filter name=\"UID\"/>"
        "  </C:filter>"
        "</C:addressbook-query>";

    test(buf, vcard1, TRUE);
    test(buf, vcard2, TRUE);
}


int main(int argc, char *argv[])
{
    int ret, opt_index;

    static const struct option opt_tbl[] = {
        { "dump",        no_argument, NULL, 'g' },
        { "help",        no_argument, NULL, 'h' },
        { 0 }
    };

#if !GLIB_CHECK_VERSION(2,35,0)
    g_type_init();
#endif

    g_test_init(&argc, &argv, NULL);

    while ((ret = getopt_long(argc, argv, "gh", opt_tbl, &opt_index)) != -1)
        switch (ret) {
        case 'g':
            state->dump = TRUE;
            break;

        case 'h':
        default:
            printf(
                "Usage: %s [options]\n"
                "    options:\n"
                "       -g (--dump) dump searched content to stdout\n"
                "\n"
                "to see g_test parameter options: run with option -? (--help)\n",
            argv[0]);
            return EXIT_SUCCESS;
        }

    g_test_add_func("/testvcard/anyof", anyof);
    g_test_add_func("/testvcard/nickname", nickname);
    g_test_add_func("/testvcard/dual", dual);
    g_test_add_func("/testvcard/cell", cell);
    g_test_add_func("/testvcard/param_text", param_text);
    g_test_add_func("/testvcard/empty", empty);

    return g_test_run();
}
