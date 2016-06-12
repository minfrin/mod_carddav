#
# A CardDAV module.
#
# Copyright (C) 2009 Nokia Corporation.
#
# Contact: Jari Urpalainen <jari.urpalainen@nokia.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

lib_LTLIBRARIES = mod_carddav.la

# Define the source file for the module
mod_carddav_la_SOURCES = mod_carddav.c carddav_liveprops.c carddav_vcard.c

# Define that an include directory is required.
mod_carddav_la_CPPFLAGS = $(APACHE_INC) $(DEPS_MOD_CFLAGS)

# module lib deps
mod_carddav_la_LIBADD = $(DEPS_MOD_LIBS)

# dlopened
mod_carddav_la_LDFLAGS = -avoid-version -module

libdir = @libdir@/$(APACHE_MODULE_DIR)

carddavdir = $(sysconfdir)/$(APACHE_CONFIG_DIR)
carddav_DATA = dav_carddav.conf dav_carddav.load

TESTS = carddav_tests
noinst_SCRIPTS = carddav_tests

test: check

check_PROGRAMS = testvcard vcardtests
testvcard_SOURCES = test_carddav.c carddav_vcard.c
testvcard_CFLAGS = $(DEPS_TEST_CFLAGS)
testvcard_LDADD = $(DEPS_TEST_LIBS)

vcardtests_SOURCES = vcard_tests.c carddav_vcard.c
vcardtests_CFLAGS = $(DEPS_TEST_CFLAGS)
vcardtests_LDADD = $(DEPS_TEST_LIBS)

