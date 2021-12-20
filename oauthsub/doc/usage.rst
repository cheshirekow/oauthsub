=====
Usage
=====

.. dynamic: usage-begin

.. code:: text

    usage: oauthsub [-h] [--dump-config] [-v] [-l {debug,info,warning,error}]
                    [-c CONFIG_FILE] [-s {flask,gevent,twisted}]
                    [--rooturl ROOTURL] [--flask-debug [FLASK_DEBUG]]
                    [--response-header RESPONSE_HEADER]
                    [--allowed-domains [ALLOWED_DOMAINS [ALLOWED_DOMAINS ...]]]
                    [--host HOST] [--port PORT] [--logdir LOGDIR]
                    [--route-prefix ROUTE_PREFIX]
                    [--session-key-prefix SESSION_KEY_PREFIX]
                    [--bypass-key BYPASS_KEY] [--custom-template CUSTOM_TEMPLATE]
                    [--enable-forbidden [ENABLE_FORBIDDEN]]

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
      -s {flask,gevent,twisted}, --server {flask,gevent,twisted}
                            Which WGSI server to use
      --rooturl ROOTURL     The root URL for browser redirects
      --flask-debug [FLASK_DEBUG]
                            Enable flask debugging for testing
      --response-header RESPONSE_HEADER
                            If specified, the authenticated user's ``username``
                            will be passed as a response header with this key.
      --allowed-domains [ALLOWED_DOMAINS [ALLOWED_DOMAINS ...]]
                            List of domains that we allow in the `hd` field of
                            thegoogle response. Set this to your company gsuite
                            domains.
      --host HOST           The address to listening on
      --port PORT           The port to listen on
      --logdir LOGDIR       Directory where we store resource files
      --route-prefix ROUTE_PREFIX
                            All flask routes (endpoints) are prefixed with this
      --session-key-prefix SESSION_KEY_PREFIX
                            All session keys are prefixed with this
      --bypass-key BYPASS_KEY
                            Secret string which can be used to bypass
                            authorization if provided in an HTTP header
                            `X-OAuthSub-Bypass`
      --custom-template CUSTOM_TEMPLATE
                            Path to custom jinja template
      --enable-forbidden [ENABLE_FORBIDDEN]
                            If true, enables the /forbidden endpoint, to which you
                            can redirect 401 errors from your reverse proxy. This
                            page is a simple message with active template but
                            includes login links that will redirect back to the
                            forbidden page after a successful auth.

.. dynamic: usage-end

-------------
Configuration
-------------

``oauthsub`` is configurable through a configuration file in python (the file
is ``exec``ed). Each configuration variable can also be specified on the
command line (use ``oauthsub --help`` to see a list of options). If you'd
like to dump a configuration file containing default values use::

    oauthsub --dump-config

Which outputs something like::

.. dynamic: config-begin

.. code:: python

    # The root URL for browser redirects
    rooturl = 'http://localhost'

    # Enable flask debugging for testing
    flask_debug = False

    # Secret key used to sign cookies
    flask_privkey = b'8vUKCV8C8x+4eCgCJ7eLbE/9Aqxtglmv'

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
      "PERMANENT_SESSION_LIFETIME": 864000,
      "SESSION_FILE_DIR": "/tmp/oauthsub/session_data",
      "SESSION_TYPE": "filesystem"
    }

    # All flask routes (endpoints) are prefixed with this
    route_prefix = '/auth'

    # All session keys are prefixed with this
    session_key_prefix = 'oauthsub-'

    # Secret string which can be used to bypass authorization if provided in an HTTP
    # header `X-OAuthSub-Bypass`
    bypass_key = None

    # Dictionary mapping oauth privider names to the client secrets for that
    # provider.
    client_secrets = {}

    # Path to custom jinja template
    custom_template = None

    # If true, enables the /forbidden endpoint, to which you can redirect 401 errors
    # from your reverse proxy. This page is a simple message  with active template
    # but includes login links that will redirect back to the forbidden page after a
    # successful auth.
    enable_forbidden = True

    # Which WGSI server to use (flask, gevent, twisted)
    server = 'flask'


    # This is not used internally, but is used to implement our user lookup
    # callback below
    _user_map = {
        "alice@example.com": "alice",
        "bob@example.com": "bob"
    }

    # This is a callback used to lookup the user identity based on the credentials
    # provided by the authenticator.
    def user_lookup(authenticator, parsed_response):
      if authenticator.type == "GOOGLE":
        # Could also use `id` to lookup based on google user id
        return _user_map.get(parsed_response.get("email"))

      return None

.. dynamic: config-end
