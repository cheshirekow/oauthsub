========
oauthsub
========

Simple oauth2 subrequest handler for nginx

A simple authentication service which can authenticate google/gsuite users
using oauth2. The service is intended to provide the interface required by
``nginx`` ``mod_auth``, serving subrequests that authenticate/authorize users.

``oauthsub`` is a flask application with the following routes:

    * ``<route_prefix>/login``: start of oauth dance
    * ``<route_prefix>/callback``: oauth redirect handler
    * ``<route_prefix>/logout``: clears user session
    * ``<route_prefix>/query_auth``: nginx subrequest handler

where ``<route_prefix>`` is a configuration option (default ``/auth``).

``oauthsub`` uses the flask session interface. You can configure the session
backend however you like (see configuration options). If you share the session
key between ``oauthsub`` and another flask application behind the same nginx
instance then you can access the ``oauthsub`` session variables directly
(including google credentials object). Otherwise ``oauthsub`` can forward the
username through an HTTP request header.

------------
Installation
------------

Install through pip with::

  pip install oauthsub

or::

  pip install --user oauthsub

-----
Usage
-----

::

    usage: oauthsub [-h] [--dump-config] [-v] [-l {debug,info,warning,error}]
                    [-c CONFIG_FILE] [--rooturl ROOTURL]
                    [--allowed-domains [ALLOWED_DOMAINS [ALLOWED_DOMAINS ...]]]
                    [--secrets SECRETS] [--flask-debug [FLASK_DEBUG]]
                    [--port PORT] [--host HOST] [--logdir LOGDIR]
                    [--response-header RESPONSE_HEADER]
                    [--flask-privkey FLASK_PRIVKEY]

    This lightweight web service performs authentication. All requests that reach
    this service should be proxied through nginx. See:
    https://developers.google.com/api-client-library/python/auth/web-app

    optional arguments:
      -h, --help            show this help message and exit
      --dump-config         Dump configuration and exit
      -v, --version         show program's version number and exit
      -l {debug,info,warning,error}, --log-level {debug,info,warning,error}
                            Increase log level to include info/debug
      -c CONFIG_FILE, --config-file CONFIG_FILE
                            use a configuration file
      --rooturl ROOTURL     The root URL for browser redirects
      --allowed-domains [ALLOWED_DOMAINS [ALLOWED_DOMAINS ...]]
                            List of domains that we allow in the `hd` field of
                            thegoogle response. Set this to your company gsuite
                            domains.
      --secrets SECRETS     The location of client_secrets.json
      --flask-debug [FLASK_DEBUG]
                            Enable flask debugging for testing
      --port PORT           The port to listen on
      --host HOST           The address to listening on
      --logdir LOGDIR       Directory where we store resource files
      --response-header RESPONSE_HEADER
                            If specified, the authenticated user's ``username``
                            will be passed as a response header with this key.
      --flask-privkey FLASK_PRIVKEY
                            Secret key used to sign cookies


``oauthsub`` is configurable through a configuration file in python (the file
is ``exec``ed). Each configuration variable can also be specified on the
command line (use ``oauthsub --help`` to see a list of options). If you'd
like to dump a configuration file containing default values use::

    oauthsub --dump-config

Which outputs something like::

    # The root URL for browser redirects
    rooturl = 'http://localhost'

    # The location of client_secrets.json
    secrets = '/tmp/client_secrets.json'

    # Enable flask debugging for testing
    flask_debug = False

    # Secret key used to sign cookies
    flask_privkey = 'UH8y1vcJ4dW1ax+7RTchmRmfBaXALJ7S'

    # If specified, the authenticated user's ``username`` will be passed as a
    # response header with this key.
    response_header = None

    # List of domains that we allow in the `hd` field of thegoogle response. Set
    # this to your company gsuite domains.
    allowed_domains = ['gmail.com']

    # The address to listening on
    host = '0.0.0.0'

    # The port to listen on
    port = 8081

    # Directory where we store resource files
    logdir = '/tmp/oauthsub/logs'

    # Flask configuration options. Set session config here.
    flaskopt = {
      "SESSION_FILE_DIR": "/tmp/oauthsub/session_data",
      "PERMANENT_SESSION_LIFETIME": 864000,
      "SESSION_TYPE": "filesystem"
    }

-----------
Basic setup
-----------

The nginx server will serve anything under ``public`` or ``auth`` without
authentication or authorization. For any other request, nginx will forward
the http headers to the authentication service over http. The authentication
service will return an HTTP status code of 200 if the user is
authenticated/authorized, and 401 if they are not. All users with who login
with an account that is within the authorized domain list is authorized.

The nginx server proxies all requests rooted at ``auth/`` to the authentication
service which is a python flask application. The auth service uses a session
(persisted through a cookie) to store the user's authenticated credentials
(email address reported by google). If the user is not authenticated or
is not authorized, the 401 error page is served by the authentication service
to provide some info about why the request was denied (i.e. what they are
currently logged in as). There is also a link on that page to login if they are
not.

----------------
Configure Google
----------------

Go to the Google `Developer Dashboard`_ and create a new project. Under the
"credentials" page enable oauth. Under the list of authorized redirects add
the following:

  * For testing:

    * http://localhost:8081/auth/callback
    * https://localhost:8443/auth/callback

  * For deployment:

    * https://server.yoursite.com/auth/callback


.. _`Developer Dashboard`: https://console.developers.google.com/apis/credentials


---------------
Configure nginx
---------------

::

  location / {
      # Use ngx_http_auth_request_module to auth the user, sending the
      # request to the /auth/query_auth URI which will return an http
      # error code of 200 if approved or 401 if denied.
      auth_request /auth/query_auth;

      # First attempt to serve request as file, then
      # as directory, then fall back to displaying a 404.
      try_files $uri $uri/ =404;
    }


    # The authentication service exposes a few other endpoints, all starting
    # with the uri prefix /auth. These endpoints are for the oauth2 login page,
    # callback, logout, etc
    location /auth {
      auth_request off;
      proxy_pass http://localhost:8081;
      proxy_pass_request_body on;
    }

    # the /auth/query URI is proxied to the authentication service, which will
    # return an http code 200 if the user is authorized, or 401 if they are
    # not
    location = /auth/query_auth {
      proxy_pass http://localhost:8081;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
      proxy_set_header X-Original-URI $request_uri;
    }

    # if the server is using letsencrypt  certbot then we'll want this
    # directory to be accessible publicly
    location /.well-known {
      auth_request off;
    }

    # we may want to keep some uri's available without authentication
    location /public {
      auth_request off;
    }

    # the auth service can serve a simple "permission denied page" with a
    # link to login that conveniently redirects the user to the original
    # page after doing the oauth dance.
    location = /public/401 {
      proxy_pass http://localhost:8081;
      proxy_set_header X-Original-URI $request_uri;
    }

    # for 401 (not authorized) redirect to the auth service which will kick
    # the user over to google's oauth
    error_page 401 /public/401;

If you want ``oauthsub`` to forward the username through a header variable then
set the ``request_header`` configuration variable and add the following to your
`nginx`_ configuration. In this example the ``request_header`` is ``X-User``
and ``nginx`` is reverse-proxying a second service listening on 8085.::

    location / {
        auth_request      /auth/query_auth;
        auth_request_set $user $upstream_x_user;
        proxy_set_header x-user $user;
        proxy_pass       http://localhost:8085;
    }

.. _`nginx`: https://www.nginx.com/resources/admin-guide/restricting-access-auth-request/

-------------------
Add a systemd unit
-------------------

For linux servers using systemd, you can add
``/etc/systemd/system/oauthsub.service``, an example which is given below
assuming we want the service to run as user ``ubuntu`` and the configuration
file is in ``/etc/oauthsub.py``.

::

    [Unit]
    Description=oauthsub service
    After=nginx.service

    [Service]
    Type=simple
    ExecStart=/usr/local/bin/oauthsub -c /etc/oauthsub.py
    User=ubuntu
    Restart=on-abort

    [Install]
    WantedBy=multi-user.target

-------------------
Testing the service
-------------------

Test the service directly on localhost, you can use the default configuration
but point to your ``client_secrets.json`` (assuming you've enabled ``http://localhost:8081/auth/callback`` as an authorized redirect on google)::

    oauthsub --flask-debug \
               --secrets /tmp/client_secrets.json

And then navigate to ``http://localhost:8081/auth`` from your browser.

To test the service behind nginx on localhost, with nginx running on port 8081
(again assuming you've enabled ``http://localhost:8081/auth/callback`` as an
authorized redirect on google). Save this file as ``/tmp/nginx.conf``::

    daemon off;
    worker_processes auto;
    pid /tmp/nginx.pid;

    events {
      worker_connections 768;
    }

    http {
      sendfile on;
      tcp_nopush on;
      tcp_nodelay on;
      keepalive_timeout 65;
      types_hash_max_size 2048;
      include /etc/nginx/mime.types;
      default_type application/octet-stream;
      ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
      ssl_prefer_server_ciphers on;
      access_log /tmp/nginx-access.log;
      error_log /tmp/nginx-error.log;
      gzip on;
      gzip_disable "msie6";

      server {
        listen 8081 default_server;
        listen [::]:8081 default_server;

        index index.html index.htm index.nginx-debian.html;
        server_name example.com;
        root /tmp/testroot

         location / {
            auth_request /auth/query_auth;
            try_files $uri $uri/ =404;
          }

          location /auth {
            auth_request off;
            proxy_pass http://localhost:8082;
            proxy_pass_request_body on;
          }

          location = /auth/query_auth {
            proxy_pass http://localhost:8082;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
          }

          location /public {
            auth_request off;
          }

          location = /public/401 {
            proxy_pass http://localhost:8082;
            proxy_set_header X-Original-URI $request_uri;
          }

      }
    }

    error_page 401 /public/401;

Start simple auth with::

    oauthsub --flask-debug \
               --secrets /tmp/client_secrets.json \
               --port 8082
               --rooturl http://localhost:8081

Start nginx with::

    nginx -c /tmp/nginx.conf -g "error_log /tmp/nginx-error.log;"

And navigate to "http://localhost:8081/" with your browser. You should be
initially denied, required to login, and then directed to the default
"welcome to nginx" page (unless you've written something else to your
default webroot).
