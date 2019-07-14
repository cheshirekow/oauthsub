===================
NGINX configuration
===================

Here is an nginx configuration that should illustrate the foundation
of working with ``oauthsub``. See the comments inline for additional
information.

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

.. dynamic: site.conf-begin

.. code:: text

    location / {
      # Use ngx_http_auth_request_module to auth the user, sending the
      # request to the /auth/query_auth URI which will return an http
      # error code of 200 if approved or 401 if denied.
      auth_request /auth/query_auth;

      # First attempt to serve request as file, then
      # as directory, then fall back to displaying a 404.
      try_files $uri $uri/ =404;
    }

    # Whether we have one or not, browsers are going to ask for this so we
    # probably shouldn't plumb it through auth.
    location = /favicon.ico {
      auth_request off;
      try_files $uri $uri/ =404;
    }

    # The authentication service exposes a few other endpoints, all starting
    # with the uri prefix /auth. These endpoints are for the oauth2 login page,
    # callback, logout, etc
    location /auth {
      auth_request off;
      proxy_pass http://localhost:8081;
      proxy_pass_request_body on;
      proxy_set_header X-Original-URI $request_uri;
    }

    # the /auth/query URI is proxied to the authentication service, which will
    # return an http code 200 if the user is authorized, or 401 if they are
    # not
    location = /auth/query_auth {
      proxy_pass http://localhost:8081;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
      proxy_set_header X-Original-URI $request_uri;
      proxy_pass_header X-OAuthSub-Bypass-Key;
      proxy_pass_header X-OAuthSub-Bypass-User;
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

    # for 401 (not authorized) redirect to the auth service which will include
    # the original URI in it's oauthflow and redirect back to the originally
    # requested page after auth
    error_page 401 /auth/forbidden;

.. dynamic: site.conf-end

------------------
Remote User Tokens
------------------

If you want ``oauthsub`` to forward the username through a header variable then
set the ``request_header`` configuration variable for ``oauthsub`` and add the
following to your `nginx`__ configuration. In this example the
``request_header`` is ``X-User`` and the protected service service listening on
8082.::

    location / {
        auth_request      /auth/query_auth;
        auth_request_set $user $upstream_x_user;
        proxy_set_header x-user $user;
        proxy_pass       http://localhost:8082;
    }

In this case the protected service will need to be configure to accept the
username in the `X-User` request header.

.. warning::

   Pay particular attention to such protected services when making changes
   to your nginx configuration. If you remove the ``auth_request`` but don't
   change the underlying service configuration anyone will be able to spoof
   arbitrary user identities by simply providing the correct `X-User`
   header.


.. __: https://www.nginx.com/resources/admin-guide/restricting-access-auth-request/

-------------------
Testing the service
-------------------

While doing development and testing it can be troublesome to edit system level
configurations and start/stop root-owned services. You can run NGINX in the
foreground as an unpriviledged user.

To execute in foreground add the following to the nginx config::

    daemon off;

On an ubuntu system, for example, you can copy ``/etc/nginx/nginx.conf`` and
then add ``daemon off;`` to the top. You can then embed your testing site
configuration, in which case you will end up with a file like this

.. dynamic: nginx.conf-begin

.. code:: text

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

        listen 8080 default_server;
        listen [::]:8080 default_server;

        index index.html index.htm index.nginx-debian.html;
        server_name cheshiresoft;
        root /tmp/webroot;

        location / {
          auth_request /auth/query_auth;
          try_files $uri $uri/ =404;
        }

        location = /favicon.ico {
          auth_request off;
          try_files $uri $uri/ =404;
        }

        location /auth {
          auth_request off;
          proxy_pass http://localhost:8081;
          proxy_pass_request_body on;
          proxy_set_header X-Original-URI $request_uri;
        }

        location = /auth/query_auth {
          proxy_pass http://localhost:8081;
          proxy_pass_request_body off;
          proxy_set_header Content-Length "";
          proxy_set_header X-Original-URI $request_uri;
          proxy_pass_header X-OAuthSub-Bypass-Key;
          proxy_pass_header X-OAuthSub-Bypass-User;
        }

        location /public {
          auth_request off;
        }

        error_page 401 /auth/forbidden;
      }
    }

.. dynamic: nginx.conf-end

You can then run nginx as follows::

    nginx -p <prefix> -c <prefix>/nginx.conf \
      -g "error_log <prefix>/nginx-error-log"

Note that the ``-g "error_log...`` part is required to work-around the fact
that nginx tries to write the error log to a root-owned location even before
reading in the configuration file.

---------
Executing
---------

Write your client secrets to ``/tmp/config.py`` and then start simple auth
with::

    oauthsub --flask-debug \
               --config /tmp/config.py \
               --port 8081 \
               --rooturl http://localhost:8080

Write the above configuration to ``/tmp/nginx.conf`` and start nginx with::

    nginx -c /tmp/nginx.conf -g "error_log /tmp/nginx-error.log;"

And navigate to "http://localhost:8080/" with your browser. You should be
initially denied, required to login, and then directed to the default
"welcome to nginx" page (unless you've written something else to your
default webroot).
