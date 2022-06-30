# -*- coding: utf-8 -*-
# vim:expandtab:autoindent:tabstop=4:shiftwidth=4:filetype=python:textwidth=0:
# License: GPL2 or later see COPYING

import os.path
import sys

# all of the variables below are substituted by the build system
VERSION="3.0"
SYSCONFDIR="/etc"
PYTHONDIR="/usr/lib/python3.6/site-packages"
PKGPYTHONDIR="/usr/lib/python3.6/site-packages/mockbuild"
MOCKCONFDIR = os.path.join(SYSCONFDIR, "mock")
# end build system subs
