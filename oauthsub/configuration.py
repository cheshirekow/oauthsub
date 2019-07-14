
import base64
import inspect
import logging
import os
import sys

logger = logging.getLogger("oauthsub")


def default_user_lookup(_, parsed_content):  # pylint: disable=W0613
  """
  Default username resolution just returns the email address reported by
  the provider.
  """
  return parsed_content.get("email")


def get_default(obj, default):
  """
  If obj is not `None` then return it. Otherwise return default.
  """
  if obj is None:
    return default

  return obj


class Configuration(object):
  """
  Simple configuration object. Holds named members for different configuration
  options. Can be serialized to a dictionary which would be a valid kwargs
  for the constructor.
  """

  # pylint: disable=too-many-arguments
  # pylint: disable=too-many-instance-attributes
  def __init__(self, rooturl=None,
               flask_debug=False, flask_privkey=None, response_header=None,
               allowed_domains=None, host=None, port=None, logdir=None,
               flaskopt=None, route_prefix=None, session_key_prefix=None,
               bypass_key=None, user_lookup=None, client_secrets=None,
               custom_template=None, enable_forbidden=True, server=None,
               **kwargs):
    self.rooturl = get_default(rooturl, 'http://localhost')
    self.flask_debug = flask_debug
    random_key = base64.b64encode(os.urandom(24)).decode("utf-8")
    self.flask_privkey = get_default(flask_privkey, random_key)
    self.response_header = response_header
    self.allowed_domains = get_default(allowed_domains, ['gmail.com'])
    self.host = get_default(host, '0.0.0.0')
    self.port = get_default(port, 8081)
    self.logdir = get_default(logdir, '/tmp/oauthsub/logs')
    self.flaskopt = get_default(flaskopt, {
        'SESSION_TYPE': 'filesystem',
        'SESSION_FILE_DIR': '/tmp/oauthsub/session_data',
        'PERMANENT_SESSION_LIFETIME': 864000
    })
    self.route_prefix = get_default(route_prefix, '/auth')
    self.session_key_prefix = get_default(session_key_prefix, 'oauthsub-')
    self.bypass_key = bypass_key
    self.user_lookup = get_default(user_lookup, default_user_lookup)
    self.client_secrets = get_default(client_secrets, {})
    self.custom_template = custom_template
    self.enable_forbidden = enable_forbidden
    self.server = get_default(server, "flask")

    extra_opts = []
    for key, kwargval in kwargs.items():
      if key.startswith('_'):
        continue
      if inspect.ismodule(kwargval):
        continue
      extra_opts.append(key)

    if extra_opts:
      logger.warning("Ignoring extra configuration options:\n  %s",
                     "\n  ".join(extra_opts))

  @classmethod
  def get_fields(cls):
    """
    Return a list of field names in constructor order.
    """
    # NOTE(josh): args[0] is `self`
    if sys.version_info < (3, 5, 0):
      # pylint: disable=W1505
      return inspect.getargspec(cls.__init__).args[1:]

    sig = getattr(inspect, 'signature')(cls.__init__)
    return [field for field, _ in list(sig.parameters.items())[1:-1]
            if field not in ["user_lookup"]]

  def serialize(self):
    """
    Return a dictionary describing the configuration.
    """
    return {field: getattr(self, field)
            for field in self.get_fields()}


VARDOCS = {
    "rooturl": "The root URL for browser redirects",
    "flask_debug": "Enable flask debugging for testing",
    "flask_privkey": "Secret key used to sign cookies",
    "response_header": (
        "If specified, the authenticated user's ``username`` "
        "will be passed as a response header with this key."),
    "allowed_domains": (
        "List of domains that we allow in the `hd` field of the"
        "google response. Set this to your company gsuite "
        "domains."),
    "host": "The address to listening on",
    "port": "The port to listen on",
    "logdir": "Directory where we store resource files",
    "flaskopt": "Flask configuration options. Set session config here.",
    "route_prefix": "All flask routes (endpoints) are prefixed with this",
    "session_key_prefix": "All session keys are prefixed with this",
    "bypass_key": (
        "Secret string which can be used to bypass authorization"
        " if provided in an HTTP header `X-OAuthSub-Bypass`"),
    "client_secrets": (
        "Dictionary mapping oauth privider names to the client"
        " secrets for that provider."),
    "custom_template": "Path to custom jinja template",
    "enable_forbidden": (
        "If true, enables the /forbidden endpoint, to which you can redirect"
        " 401 errors from your reverse proxy. This page is a simple message "
        " with active template but includes login links that will redirect back"
        " to the forbidden page after a successful auth."),
    "server": (
        "Which WGSI server to use (flask, gevent, twisted)"
    )
}
