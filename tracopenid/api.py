# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
"""
"""
from __future__ import absolute_import

from trac.core import Interface
from trac.web.auth import LoginModule
from trac.web.api import IAuthenticator


class ILoginManager(Interface):
    """Store authentication state.
    """
    def remember_user(req, authname):
        """ Set the current user to ``authname``.
        This should set a cookie, or do whatever is necessary to
        remember the fact that the current user has been authenticated
        as the user ``authname``.
        """

    def forget_user(req):
        """ Forget the current user.
        This logs the current user out.
        """
