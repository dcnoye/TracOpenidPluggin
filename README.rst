=============================
OpenID / Oauth2 for Trac 1.5+
=============================



Installation
============
python3 setup.py bdist_egg
cp tracopenid-0.0.1.dev0dev-py3.6.egg plugins/


    Add to trac.ini:

|    [tracopenid]
|    client_id = XXXXXXXXXXX
|    client_secret = XXXXXXXXXXXXXXX
|    scope = openid email profile
|    authorize_url = https://accounts.google.com/o/oauth2/auth
|    userinfo_endpoint = https://openidconnect.googleapis.com/v1/userinfo
|    token_url = https://accounts.google.com/o/oauth2/token


|        [trac]
|        base_url = https://example.com
