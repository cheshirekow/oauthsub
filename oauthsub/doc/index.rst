========
oauthsub
========

.. image:: https://travis-ci.com/cheshirekow/oauthsub.svg?branch=master
    :target: https://travis-ci.com/cheshirekow/oauthsub

.. image:: https://readthedocs.org/projects/oauthsub/badge/
    :target: https://oauthsub.readthedocs.io

Simple oauth2 subrequest handler for reverse proxy configurations


.. toctree::
   :maxdepth: 2

   installation
   usage
   examples/index
   systemd
   changelog
   todo
   modules

-------
Purpose
-------

The goal of ``oauthsub`` is to enable simple and secure Single Sign On by
deferring authentication to an ``oauth2`` provider (like google, github,
microsoft, etc).

``oauthsub`` does not provide facilities for access control. The program is
very simple and if you wanted to implement authentication *and* access control,
feel free to use it as a starting point. It was created, however, to provide
authentication for existing services that already do their own access control.

-------
Details
-------


``oauthsub`` implements client authentication subrequest handling for reverse
proxies, and provides ``oauth2`` redirect endpoints for doing the whole
``oauth2`` dance. It can provide authentication services for:

* NGINX (via `http_auth_request`__)
* Apache (via mod_perl and `Authen::Simple::HTTP`__, `backup link`__)
* HA-Proxy (via `a lua extension`__, `backup link`__)

.. __: http://nginx.org/en/docs/http/ngx_http_auth_request_module.html
.. __: https://metacpan.org/pod/release/CHANSEN/Authen-Simple-HTTP-0.2/lib/Authen/Simple/HTTP.pm
.. __: https://stackoverflow.com/a/38033113/141023
.. __: https://bl.duesterhus.eu/20180119/
.. __: https://serverfault.com/a/898145

The design is basically this:

* For each request, the reverse proxy makes a subrequest to ``oauthsub``
  with the original requested URI
* ``oauthsub`` uses a session cookie to keep track of authenticated users.
  If the user's session has a valid authentication token, it returns HTTP
  status 200. Otherwise it returns HTTP status 401.
* If the user is not authenticated, the reverse proxy redirects them to the
  ``oauthsub`` login page, where they can start the dance with an ``oauth2``
  provider. You can choose to enable multiple providers if you'd like.
* The ``oauth2`` provider bounces the user back to the ``oauthsub`` callback
  page where the authentication dance is completed and the users credentials
  are stored. ``oauthsub`` sets a session cookie and redirects the user back
  to the original URL they were trying to access.
* This time when they access the URL the subrequest handler will return
  status 200.

Oauthsub will also pass the authenticated username back to the reverse-proxy
through a response header. This can be forwarded to the proxied service as a
Remote User Token for access control.

---------------------
Application Specifics
---------------------


``oauthsub`` is a flask application with the following routes:

    * ``/auth/login``: start of oauth dance
    * ``/auth/callback``: oauth redirect handler
    * ``/auth/logout``: clears user session
    * ``/auth/query_auth``: subrequest handler
    * ``/auth/forbidden``: optional redirect target for 401's

The ``/auth/`` route prefix can be changed via configuration.

``oauthsub`` uses the flask session interface. You can configure the session
backend however you like (see configuration options). If you share the session
key between ``oauthsub`` and another flask application behind the same nginx
instance then you can access the ``oauthsub`` session variables directly
(including the ``oauth`` token object).



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
