======
Gerrit
======

Gerrit provides git-based code hosting and code review services. It can be
configured to accept the Remote User Token from ``oauthsub``. There are a few
relevant sections of ``gerrit.config``. First, with gerrit sitting behind
a reverse proxy you must tell gerrit what it's URL is so that it can properly
contruct links. For our testing configuration we'll use the following::

    [gerrit]
      canonicalWebUrl = http://lvh.me:8080/gerrit/

Secondly, we need to tell gerrit which port to listen on for http connections.
We'll setup gerrit to listen on 8082::

    [httpd]
      listenUrl = http://*:8082/gerrit/

.. note::

   For a production server, consider using
   ``proxy-http://127.0.0.1:8082/gerrit/`` instead of ``http://``

Lastly, we need to tell gerrit to enable HTTP header authentication, and
which header to look in. For our example setup, that gives us::

    [auth]
      type = HTTP
      httpHeader = X-Gsuite-User
      emailFormat = {0}@example.com

And now that gerrit is configured, we need to update the nginx configuration
to proxy it. Add the following to your nginx site configuration::

    location = /gerrit {
      return 302 /gerrit/;
    }

    location /gerrit/ {
      auth_request /auth/query_auth;
      auth_request_set $user $upstream_http_x_gsuite_user;
      proxy_set_header X-Gsuite-User $user;

      proxy_pass http://localhost:8082;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }

Note that nginx behaves differently depending on whether or not the
``proxy_pass`` URL ends in a slash. Without the trailing slash, as we have
done here, will forward the whole URI down to the proxied service. In this
case that means that all requests that gerrit sees will be prefixed by the
``gerrit/`` path. As alternative configuration, we could configure nginx to
forward only the relative URI (i.e. strip the ``gerrit/`` prefix) and then
we would change the gerrit config to ``listenUrl = http://*:8082/``.
