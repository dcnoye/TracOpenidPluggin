=============================
OpenID / Oauth2 for Trac 1.6
=============================

|trac versions|

***********
Description
***********


Oauth2 plugin for Trac 1.6


Prerequisites
=============

python3 trac 1.6

Installation
============

|    python -mpip install requests_oauthlib
|    python setup.py bdist_egg
|    cp dist/tracopenid-0.0.1.dev0-py3.11.egg /var/lib/trac/plugins


Configuration
=============

Add to your ``trac.ini``::

  [components]
  trac.web.auth.loginmodule = disabled

  [tracopenid]
  client_id = XXXXXXXXXXX
  client_secret = XXXXXXXXXXXXXXX
  scope = openid email profile
  authorize_url = https://accounts.google.com/o/oauth2/auth
  userinfo_endpoint = https://openidconnect.googleapis.com/v1/userinfo
  token_url = https://accounts.google.com/o/oauth2/token
  authorized_domains = gmail.com
  authorized_emails = dc@example.com, alex@example.com


  [trac]
  base_url = https://example.com


*****
To Do
*****

Add to pypi
Add documentation
Add references

.. |trac versions| image::
      https://img.shields.io/badge/trac-1.6-blue.svg
   :target: http://trac.edgewall.org/
