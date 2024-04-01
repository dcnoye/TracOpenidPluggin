import sys
from trac.core import Component, implements
from trac.web.api import IRequestFilter
from trac.config import BoolOption
from trac.perm import PermissionError
import inspect  # Import the inspect module

class Oauth2Filter(Component):
    """ A filter to redirect unauthenticated """
    implements(IRequestFilter)

    redirect_login = BoolOption('permredirect', 'redirect_login', 'true', """ """)

    def pre_process_request(self, req, handler):
        return handler

    def post_process_request(self, req, template, data, content_type):
        if not self.redirect_login:
            return template, data, content_type

        if req.authname != 'anonymous':
            return template, data, content_type

        exctype, exc = sys.exc_info()[0:2]

        # Check if exctype is a class and is a subclass of PermissionError
        if exctype is not None and inspect.isclass(exctype) and issubclass(exctype, PermissionError):
            login_url = req.href.login()
            req.redirect(login_url)

        return template, data, content_type

