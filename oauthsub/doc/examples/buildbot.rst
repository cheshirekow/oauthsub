===============
Buildbot Master
===============

Buildbot is a continuous integration framework in python. We can configure
the master to run behind nginx and to consume Remote User Tokens from
``oauthsub``.

In our example setup we will have buildbot listen on port 8083. In your
buildbot master configuration (``master.cfg``) add the following::

    c['www'] = {
        "port": 8083,
        "plugins": {
            "waterfall_view": {},
            "console_view": {},
            "grid_view": {},
        },
        "auth": util.RemoteUserAuth(
            header="X-Gsuite-User",
            headerRegex=r"(?P<username>[^ @]+)@?(?P<realm>[^ @]+)?"),
    }

Then in your nginx configuration::

    location = /buildbot {
      return 302 /buildbot/;
    }

    location /buildbot/ {
      auth_request /auth/query_auth;
      auth_request_set $user $upstream_http_x_gsuite_user;
      proxy_set_header X-Gsuite-User $user;

      proxy_pass http://localhost:8083/;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header X-Forwarded-Server  $host;
      proxy_set_header X-Forwarded-Host  $host;
    }

    location /buildbot/sse/ {
        # proxy buffering will prevent sse to work
        proxy_buffering off;
        proxy_pass http://localhost:8083/sse/;
    }

    # required for websocket
    location /buildbot/ws {
        proxy_pass http://localhost:8083/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Origin "";

        # raise the proxy timeout for the websocket
        proxy_read_timeout 6000s;
    }
