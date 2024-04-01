# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 D.C. Noye
#
"""TracOpenidplugin
"""
from __future__ import absolute_import
import re
from contextlib import contextmanager
from itertools import chain, count
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import parse_qs

from trac.util.html import tag
from trac.util.translation import _, tag_
from trac.core import implements, Component, ExtensionPoint, Interface
from trac.perm import PermissionSystem
from trac.util.translation import _
from trac.web.api import IAuthenticator, IRequestHandler
from trac.web.auth import LoginModule
from trac.web.chrome import add_warning, INavigationContributor, Chrome
from trac.web.session import DetachedSession
from trac.config import BoolOption, IntOption, Option
from requests_oauthlib import OAuth2Session

from .compat import db_query, is_component_enabled, logout_link
from .api import ILoginManager

class TracOpenidPlugin(Component):
    """ Auth via OpenID
    """
    implements(INavigationContributor, IRequestHandler)

    login_managers = ExtensionPoint(ILoginManager)

    ignore_case = BoolOption('trac', 'ignore_auth_case', 'false',""" """)
    auth_cookie_domain = Option('trac', 'auth_cookie_domain', '',""" """)
    auth_cookie_lifetime = IntOption('trac', 'auth_cookie_lifetime', 0,""" """)
    auth_cookie_path = Option('trac', 'auth_cookie_path', '',""" """)

    def __init__(self):
        self.trac_base_url = self.config.get('trac', 'base_url', '')
        self.show_logout_link = not is_component_enabled(self.env, LoginModule)
        self.userdb = UserDatabase(self.env)

    def get_active_navigation_item(self, req):
        return 'login'

    def get_navigation_items(self, req):
        openid_href = req.href.tracopenid
        path_qs = req.path_info
        self.env.log.debug("get_nav")
        self.env.log.debug(openid_href)
        self.env.log.debug(path_qs)
        if req.query_string:
            path_qs += '?' + req.query_string
        if req.is_authenticated and self.show_logout_link:
            yield ('metanav', 'tracopenid', tag_("logged in as %(user)s",
                   user=Chrome(self.env).authorinfo(req, req.authname)))
            yield ('metanav', 'logout',
                   tag.a(_('Logout'), href=req.href.logout()))
        else:
            yield ('metanav', 'login',
                   tag.a(_('Login'), href=req.href.login()))

    def match_request(self, req):
        return re.match('/(login|logout|authorize)/?$', req.path_info)

    def process_request(self, req):
        if req.path_info.endswith('/logout'):
            return_url = self._get_return_url(req)
            self._forget_user(req, return_url)
        elif req.path_info.endswith('/login'):
            self._do_oauth2_login(req)
        elif req.path_info.endswith('/authorize'):
            self._do_authorize(req)

    def _do_oauth2_login(self, req):
        redirect_uri = self.trac_base_url + '/authorize'
        client_id = self.config.get('tracopenid', 'client_id', '')
        scope = self.config.get('tracopenid', 'scope', '')
        authorize_url = self.config.get('tracopenid', 'authorize_url', '')

        session = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)
        authorization_url, state = session.authorization_url(
            authorize_url,
            access_type="offline", prompt="select_account")

        # Used to prevent CSRF.
        req.session['OAUTH_STATE'] = state
        req.redirect(authorization_url)


    def _do_authorize(self, req):
        client_id = self.config.get('tracopenid', 'client_id', '')
        client_secret = self.config.get('tracopenid', 'client_secret', '')
        userinfo_endpoint = self.config.get('tracopenid', 'userinfo_endpoint', '')
        authorized_domains = self.config.get('tracopenid', 'authorized_domains', '').split()

        token_url = self.config.get('tracopenid', 'token_url', '')
        redirect_uri = self.trac_base_url + '/authorize'
        session = OAuth2Session(client_id, redirect_uri=redirect_uri,
                                state=req.session['OAUTH_STATE'])

        try:
            # Parse the authorization code from the query string
            code = parse_qs(req.query_string)["code"][0]
            # Exchange the authorization code for an access token
            token = session.fetch_token(token_url=token_url,
                                        client_secret=client_secret,
                                        code=code)
            req.environ["oauth_token"] = token

            # Get user information from the userinfo endpoint
            r = session.get(userinfo_endpoint)
            json_response = r.json()
            authname = json_response['email']

            # Check if the domain of the user's email is in the authorized domains
            if authname.split("@")[1] in authorized_domains:
                authname = authname.split("@")[0]
                req.environ["REMOTE_USER"] = authname
                LoginModule._do_login(self, req)
            else:
                self.env.log.warning("Unauthorized domain for user: {0}".format(authname))
                add_warning(req, _("Authorization Failed: unauthorized domain"))
                return req.redirect(self.trac_base_url)

        except Exception as e:
            self.env.log.error("Authentication failed: {0}".format(e))
            add_warning(req, _("Authorization Failed: {0}").format(e))
            return req.redirect(self.trac_base_url)

        return req.redirect(self.trac_base_url)

    def _remember_user(self, req, authname):
        for lm in self.login_managers:
            lm.remember_user(req, authname)

    def _forget_user(self, req, return_url):
        for lm in self.login_managers:
            lm.forget_user(req)

        return req.redirect(return_url)

    @staticmethod
    def _get_return_url(req):
        return_to = req.args.getfirst('return_to', '/')
        # We expect return_to to be a URL relative to the trac's base_path.
        # Be paranoid about this.
        scheme, netloc, path, query, anchor = urlsplit(return_to)
        if scheme or netloc or '..' in path.split('/') or anchor:
            # return url looks suspicious, ignore it.
            return req.abs_href()
        return_url = req.abs_href(path)
        if query:
            return_url += '?' + query
        return return_url

class AuthCookieManager(LoginModule):
    """Manage the authentication cookie.

    This handles setting the trac authentication cookie and updating
    the ``auth_cookie`` table in the trac db.

    """
    implements(IAuthenticator, ILoginManager)
    def remember_user(self, req, authname):
        with _temporary_environ(req, REMOTE_USER=authname):
            self._do_login(req)  # LoginModule._do_login

    def forget_user(self, req):
        with _temporary_environ(req, REQUEST_METHOD='POST'):
            self._do_logout(req)

    # More hackage: override INavigationContributor and
    # IRequestHandler methods inherited from LoginModule.

    def get_active_navigation_item(self, req):
        pass

    def get_navigation_items(self, req):
        return ()

    def match_request(self, req):
        return False

    def process_request(self, req):
        pass                    # pragma: NO COVER


@contextmanager
def _temporary_environ(req, **kwargs):
    """ A context manager used to teporarily modify ``req.environ``.
    """
    environ = req.environ
    req.environ = environ.copy()
    req.environ.update(kwargs)
    try:
        yield req.environ
    finally:
        req.environ = environ




class UserDatabase(Component):
    """Map Oauth2 identities to trac usernames.

    """
    abstract = True

    SUBJECT_SKEY = 'tracopenid.subject'
    IDENTITY_URL_SKEY = 'openid_session_identity_url_data'

    def __init__(self):
        self.helper = SessionHelper(self.env)

    def find_session(self, id_token):
        """ Find existing authenticated session corresponding to identity.

        Returns the session id, or ``None`` if no corresponding authenticated
        session is found.

        """
        iss, sub = id_token['iss'], id_token['sub']
        identity_url = id_token.get('openid_id')

        authname = self.find_session_by_openid_subject(iss, sub)
        if not authname and identity_url:
            authname = self.find_session_by_openid_id(identity_url)
            if authname:
                self.log.info(
                    "Claiming session %s with oid identity %s for (%s, %s)",
                    authname, identity_url, iss, sub)
                self.associate_session(authname, iss, sub)
        return authname

    def create_session(self, id_token):
        """ Create a brand new authenticated session for identity

        """
        subject_id = self.subject_uri(id_token['iss'], id_token['sub'])
        preferred_username = self.preferred_username(id_token)
        attributes = {self.SUBJECT_SKEY: subject_id}
        attributes.update(self.default_attributes(id_token))
        authname = self.helper.create_session(preferred_username, attributes)
        self.log.info(
            "Created new authenticated session for %s with attributes %r",
            authname, attributes)
        return authname

    def find_session_by_openid_subject(self, iss, sub):
        subject_id = self.subject_uri(iss, sub)
        sids = self.helper.find_session_by_attr(self.SUBJECT_SKEY, subject_id)
        if len(sids) > 1:
            self.log.warning(
                "Multiple users share the same openid iss=%r, sub=%r: %s",
                iss, sub, ', '.join(map(repr, sids)))
        return sids[0] if sids else None

    def find_session_by_openid_id(self, openid_id):
        sids = self.helper.find_session_by_attr(self.IDENTITY_URL_SKEY,
                                                openid_id)
        if len(sids) > 1:
            self.log.warning(
                "Multiple users share the same openid url %s: %s",
                openid_id, ', '.join(map(repr, sids)))
        return sids[0] if sids else None

    def associate_session(self, authname, iss, sub):
        ds = DetachedSession(self.env, authname)
        ds[self.SUBJECT_SKEY] = self.subject_uri(iss, sub)
        ds.save()

    @staticmethod
    def preferred_username(id_token):
        """Get the preferred username for the user.
        """
        sub = id_token['sub']
        assert sub
        return (
            id_token.get('preferred_username')
            or id_token.get('email')
            or id_token.get('name')
            or sub)

    @staticmethod
    def default_attributes(id_token):
        """Get extra attributes to be set on newly created sessions.
        """
        return {
            'name': id_token.get('name', ''),
            'email': id_token.get('email', ''),
            }

    @staticmethod
    def subject_uri(iss, sub):
        """Return a subject identifier.

        The subject identifier is a single string which combines the
        issuer (``iss``) and subject (``sub``) from the OpenID Connect
        id_token.

        Note that, AFAIK, this method of combining ``iss`` and ``sub``
        into a single string is not in any specification — I just made it
        up.

        """
        if '://' not in iss:
            # Normalize google's iss. See
            # http://openid.net/specs/openid-connect-core-1_0.html#GoogleIss
            iss = 'https://%s' % iss
        query_string = urlencode({'sub': sub})
        return '%s?%s' % (iss, query_string)


class SessionHelper(Component):
    """Helper for searching/manipulating the user database.

    Note that in trac, the user account/profile database is
    implemented as part of the session state storage.  User accounts
    are refered to as "authenticated sessions".  The “username” is
    referred to as the *session id* or ``sesssion.sid``.  It is also
    called the *authname* (e.g. ``req.authname``.)

    """
    abstract = True

    def __init__(self):
        self.permissions = PermissionSystem(self.env)

    def find_session_by_attr(self, attr_name, attr_value):
        """ Find an authenticated session which contain a specific attribute.

        """
        rows = db_query(self.env,
                        "SELECT session.sid"
                        " FROM session"
                        " INNER JOIN session_attribute AS attr"
                        "                  USING(sid, authenticated)"
                        " WHERE session.authenticated=%s"
                        "       AND attr.name=%s AND attr.value=%s"
                        " ORDER BY session.last_visit DESC",
                        (1, attr_name, attr_value))
        return [row[0] for row in rows]

    def create_session(self, authname_base, attributes):
        """Create a new authenticated session.

        (In trac, authenticated sessions are, essentially “user accounts”,
        so this creates a new account or “login” on the trac.)

        If possible, the session is created with an ``sid`` of
        ``authname_base``.  If a session already exists with that
        ``sid``, then a suffix is added to make the ``sid`` unique.

        The attributes of the new session are initialized from the
        ``attributes`` argument, if any.

        The ``sid`` of the new session is returned.

        """
        if not attributes:
            raise ValueError("Attributes required for new session")

        for suffix in self.uniquifier_suffixes():
            authname = authname_base + suffix
            if self.permission_exists_for(authname):
                continue
            ds = DetachedSession(self.env, authname)
            # At least in 0.12.2, this means no session exists.
            is_new = ds.last_visit == 0 and len(ds) == 0
            if is_new:
                break
        for key, value in attributes.items():
            ds[key] = value or ''
        ds.save()
        return authname

    def uniquifier_suffixes(self):
        """ Suffixes used to generate unique authnames.
        """
        return chain([""], (" (%d)" % n for n in count(2)))

    def permission_exists_for(self, authname):
        return any(authname == user
                   for user, perm in self.permissions.get_all_permissions())
