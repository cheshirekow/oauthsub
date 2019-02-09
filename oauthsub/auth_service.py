"""
This lightweight web service performs authentication. All requests that reach
this service should be proxied through nginx.

See: https://developers.google.com/api-client-library/python/auth/web-app
"""

from __future__ import print_function
from __future__ import unicode_literals

import base64
import inspect
import os
import json
import logging
import logging.handlers
import sys
import urllib
import zipfile

import flask
import jinja2
import oauth2client.client
import requests
import oauthsub


logger = logging.getLogger("oauthsub")

if sys.version_info < (3, 0, 0):
  # pylint: disable=E1101
  quote_plus = urllib.quote_plus
  urlencode = urllib.urlencode
else:
  # pylint: disable=E1101
  quote_plus = urllib.parse.quote_plus
  urlencode = urllib.parse.urlencode


class ZipfileLoader(jinja2.BaseLoader):

  def __init__(self, zipfile_path, directory):
    self.zip = zipfile.ZipFile(zipfile_path, mode='r')
    self.dir = directory

  def __del__(self):
    self.zip.close()

  def get_source(self, environment, template):
    # NOTE(josh): not os.path because zipfile uses forward slash
    tplpath = '{}/{}'.format(self.dir, template)
    with self.zip.open(tplpath, 'r') as infile:
      source = infile.read().decode('utf-8')

    return source, tplpath, lambda: True


def get_parent_path():
  """
  Return the parent path of the oauthsub package.
  """
  modpath = os.path.dirname(oauthsub.__file__)
  return os.path.dirname(modpath)


def get_zipfile_path():
  """
  If our module is loaded from a zipfile (e.g. a wheel or egg) then return
  the pair (zipfile_path, module_relpath) where zipfile_path is the path to
  the zipfile and module_relpath is the relative path within that zipfile.
  """
  modparent = get_parent_path()
  zipfile_parts = modparent.split(os.sep)
  module_parts = []

  while zipfile_parts:
    zipfile_path = os.sep.join(zipfile_parts)
    relative_path = "/".join(module_parts)
    if os.path.exists(zipfile_path) and zipfile.is_zipfile(zipfile_path):
      return zipfile_path, relative_path
    module_parts.insert(0, zipfile_parts.pop(-1))

  return None, None


def default_user_lookup(parsed_content):
  """
  Lookup user name from auth JSON. Return None if cannot auth.
  """
  return parsed_content.get("email")


def flow_from_clientsecrets(client_info, scope, redirect_uri=None,
                            login_hint=None, device_uri=None,
                            pkce=None, code_verifier=None, prompt=None):
  """
  Create a Flow from a clientsecrets json.
  See oauth2client.client.flow_from_client_secrets

  Will create the right kind of Flow based on the contents of the
  clientsecrets file or will raise InvalidClientSecretsError for unknown
  types of Flows.

  Args:
      filename: string, File name of client secrets.
      scope: string or iterable of strings, scope(s) to request.
      redirect_uri: string, Either the string 'urn:ietf:wg:oauth:2.0:oob' for
                    a non-web-based application, or a URI that handles the
                    callback from the authorization server.
  Returns:
      A Flow object.

  Raises:
      UnknownClientSecretsFlowError: if the file describes an unknown kind of
                                     Flow.
      clientsecrets.InvalidClientSecretsError: if the clientsecrets file is
                                               invalid.
  """
  constructor_kwargs = {
      "redirect_uri": redirect_uri,
      "auth_uri": client_info["auth_uri"],
      "token_uri": client_info["token_uri"],
      "login_hint": login_hint,
  }
  revoke_uri = client_info.get("revoke_uri")
  if revoke_uri is not None:
    constructor_kwargs["revoke_uri"] = revoke_uri
  if device_uri is not None:
    constructor_kwargs["device_uri"] = device_uri
  if pkce is not None:
    constructor_kwargs["pkce"] = pkce
  if code_verifier is not None:
    constructor_kwargs["code_verifier"] = code_verifier
  if prompt is not None:
    constructor_kwargs["prompt"] = prompt

  return oauth2client.client.OAuth2WebServerFlow(
      client_info["client_id"],
      client_info["client_secret"],
      scope, **constructor_kwargs)


class Application(object):
  """
  Main application context. Exists as a class to keep things local... even
  though flask is all about the global state.
  """

  def __init__(self, config):
    """Configure jinja, beaker, etc."""
    # TODO(josh): validate config.client_secrets
    self.config = config

    zipfile_path, package_path = get_zipfile_path()
    if self.config.custom_template:
      logger.info('Using FilesystemLoader for templates')
      template_loader = jinja2.FileSystemLoader(
          os.path.dirname(self.config.custom_template))
    elif zipfile_path:
      logger.info('Using ZipfileLoader for templates')
      template_loader = ZipfileLoader(zipfile_path,
                                      package_path + '/templates')
    else:
      logger.info('Using PackageLoader for templates')
      template_loader = jinja2.PackageLoader('oauthsub', 'templates')
    self.jinja = jinja2.Environment(loader=template_loader)
    self.jinja.globals.update(url_encode=quote_plus)

    self.flask = flask.Flask(__name__)
    self.flask.secret_key = config.flask_privkey
    self.flask.debug = self.config.flask_debug
    for key, value in config.flaskopt.items():
      self.flask.config[key] = value

    self.flask.add_url_rule(config.route_prefix, 'hello', self.hello)

    self.flask.add_url_rule('{}/login'.format(config.route_prefix),
                            'login', self.login)
    self.flask.add_url_rule('{}/logout'.format(config.route_prefix),
                            'logout', self.logout)
    self.flask.add_url_rule('{}/callback'.format(config.route_prefix),
                            'callback', self.callback)
    self.flask.add_url_rule('{}/get_session'.format(config.route_prefix),
                            'get_session', self.get_session)
    self.flask.add_url_rule('{}/query_auth'.format(config.route_prefix),
                            'query_auth', self.query_auth)

    if self.config.enable_forbidden:
      self.flask.add_url_rule('{}/forbidden'.format(config.route_prefix),
                              'forbidden', self.forbidden)

  def run(self, *args, **kwargs):
    """Just runs the flask app."""
    self.flask.run(*args, **kwargs)

  def render_message(self, message, *args, **kwargs):
    # pylint: disable=no-member
    original_uri = kwargs.pop("original_uri", None)
    tplargs = {
        "session": flask.session,
        "message": message.format(*args, **kwargs),
        "providers": sorted(self.config.client_secrets.keys()),
        "original_uri": original_uri,
        "route_prefix": self.config.route_prefix
    }

    if self.config.custom_template:
      template = os.path.basename(self.config.custom_template)
    else:
      template = "message.html.tpl"

    return self.jinja.get_template(template).render(**tplargs)

  def hello(self):
    """A more or less empty endpoint."""

    # pylint: disable=no-member
    return self.jinja.get_template('message.html.tpl').render(
        session=flask.session, message='Hello')

  def query_auth(self):
    """
    This is the main endpoint used by nginx to check authorization. If this
    is an nginx request the X-Original-URI will be passed as an http header.
    """
    original_uri = flask.request.headers.get('X-Original-URI')
    if original_uri:
      logger.debug('Doing auth for original URI: %s, session %s',
                   original_uri, flask.session.get('id', None))

      # If bypass key is present and matches configured, then bypass the
      # auth-check and assume the user identity
      if self.config.bypass_key is not None:
        if ('X-OAuthSub-Bypass-Key' in flask.request.headers
            and 'X-OAuthSub-Bypass-User' in flask.request.headers):
          logger.debug("bypass headers are present")

          if(flask.request.headers['X-OAuthSub-Bypass-Key'] ==
             self.config.bypass_key):

            username = flask.request.headers["X-OAuthSub-Bypass-User"]
            logger.debug("admin bypass, setting user to %s", username)
            self.session_set("user", username)
          else:
            logger.warning("admin bypass key doesn't match")

      # NOTE(josh): we don't do any whitelisting here, we'll let the nginx
      # config decide which urls to reqest auth for
      if self.session_get('user', None) is not None:
        response = flask.make_response("", 200, {})
        if self.config.response_header:
          response.headers[self.config.response_header] \
              = self.session_get('user')
        return response

      # NOTE(josh): since nginx will return a 401, it will not pass the
      # Set-Cookie header to the client. This session will not be associated
      # with the client unless they already have a cookie for this site.
      # There's not much point in dealing with the X-Original-URI here since
      # we can't realiably maintain any context.
      return flask.make_response("", 401, {})

    flask.abort(401)
    return None

  def forbidden(self):
    """
    The page served when a user isn't authorized. We'll just set the return
    path if it's available and then kick them through oauth2.
    """
    original_uri = flask.request.headers.get('X-Original-URI')
    logger.info('Serving forbidden, session %s, original uri: %s',
                flask.session.get('id', None), original_uri)

    # NOTE(josh): it seems we can't do a redirect from the 401 page, or else it
    # might be on the browser side, but we get stuck at some google text saying
    # that the page should automatically redirect but it doesn't. Let's just
    # print the message and let them login. If they login it will return them
    # to where they wanted to go in the first place.
    if original_uri is not None and original_uri.endswith("favicon.ico"):
      return flask.make_response("", 401, {})

    html = self.render_message('Permission denied. Are you logged in?',
                               original_uri=original_uri)
    return flask.make_response(html)

  def get_flow(self, provider):
    """
    Return the oauth2client flow object
    """

    redirect_uri = '{}{}/callback'.format(self.config.rooturl,
                                          self.config.route_prefix)
    query_params = {"provider": provider}

    # NOTE(josh): as of 2019 google requires all redirect URIs to be explicit,
    # and will not accept additional query parameters in the URI. We'll need to
    # use some kind of cookie or token matching to get this back
    # original_uri = flask.request.args.get('original_uri', None)
    # if original_uri is not None:
    #   query_params["original_uri"] = original_uri

    redirect_uri += '?' + urlencode(query_params)

    # Construct a 'flow' object which helps us step through the oauth handshake
    # TODO(josh): need to protect against invalid provider strings
    return flow_from_clientsecrets(
        self.config.client_secrets.get(provider),
        scope='https://www.googleapis.com/auth/userinfo.email',
        redirect_uri=redirect_uri)

  def session_get(self, key, default=None):
    """
    Return the value of the session variable `key`, using the prefix-qualifed
    name for `key`
    """
    qualified_key = '{}{}'.format(self.config.session_key_prefix, key)
    return flask.session.get(qualified_key, default)

  def session_set(self, key, value):
    """
    Set the value of the session variable `key`, using the prefix-qualifed
    name for `key`
    """
    qualified_key = '{}{}'.format(self.config.session_key_prefix, key)
    flask.session[qualified_key] = value

  def login(self):
    """
    The login page. Start of the oauth dance. Construct a flow, get redirect,
    bounce the user.
    """

    if self.session_get('user') is not None:
      return self.render_message("You are already logged in as {}",
                                 self.session_get('user'))

    provider = flask.request.args.get("provider")
    if provider is None:
      return flask.make_response(
          self.render_message("No provider!"), 403, {})

    if provider not in self.config.client_secrets:
      message = "Invalid provider: {}".format(provider)
      html = self.render_message(message)
      response = flask.make_response(html, 403, {})
      return response

    self.session_set(
        "original_uri", flask.request.args.get("original_uri"))

    flow = self.get_flow(provider)
    auth_uri = flow.step1_get_authorize_url()
    return flask.redirect(auth_uri)

  def callback(self):
    """
    Handle oauth bounce-back.
    """

    # If we didn't received a 'code' in the query parameters then this
    # definately not a redirect back from google.  Assume this is a user meaning
    # to use the /login endpoint and punt them to the start of the dance.
    if 'code' not in flask.request.args:
      return self.login()

    if 'provider' not in flask.request.args:
      return self.login()

    provider = flask.request.args.get("provider")
    flow = self.get_flow(provider)
    auth_code = flask.request.args.get('code')

    # Exchange the code that google gave us for an actual credentials object,
    # and store those credentials in the session for this user.

    # NOTE(josh): We don't actually do anything persistent with the credentials
    # right now, other than to store them as a certificate that the user is
    # authenticated. In the normal use case we would need access to the
    # credentials in the future in order to hit google API's on behalf of the
    # user.
    credentials = flow.step2_exchange(auth_code)

    # Use the credentials that we have in order to get the users information
    # from google. We only need one request to get the user's email address
    # and name.
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json; charset=UTF-8'}

    if provider == "google":
      request_url = "https://www.googleapis.com/userinfo/v2/me?alt=json"
      headers["Authorization"] = "Bearer {}".format(credentials.access_token)
    elif provider == "github":
      request_url = "https://api.github.com/user"
      headers["Authorization"] = "token {}".format(credentials.access_token)
    else:
      message = 'Invalid provider: {}'.format(provider)
      return flask.make_response(self.render_message(message), 401, {})

    response = requests.get(request_url, headers=headers)

    if response.status_code != 200:
      message = 'Failed to query {}: [{}]'.format(provider, response.status)
      return flask.make_response(self.render_message(message), 500, {})

    # We'll store the users email, name, and 'given_name' from google's
    # reponse. This is just to help the user understand which google identity
    # they currently have activated.
    content_str = response.content.decode("utf-8")
    print(content_str)
    parsed_content = json.loads(content_str)

    # If the user logged in with an email domain other than <??> the we want
    # to warn them that they are probably not doing what they wanted to do.
    # TODO(josh): move into google-specific auth function
    if (self.config.allowed_domains
        and (parsed_content.get('hd') not in self.config.allowed_domains)):
      content = self.render_message('You did not login with the right account!')
      return flask.make_response(content, 401, {})

    username = self.config.user_lookup(provider, parsed_content)
    if username is None:
      logger.warning("user lookup failed: %s",
                     json.dumps(parsed_content, indent=2, sort_keys=True))
      content = "Failed user lookup"
      return flask.make_response(content, 401, {})
    self.session_set('user', username)

    # At this point the user is authed
    self.session_set('credentials', credentials.to_json())
    for key in ['email', 'name', 'given_name']:
      self.session_set(key, parsed_content.get(key, "unknown"))

    # If we are logging-in due to attempt to access an auth-requiring page,
    # then go to back to that page
    original_uri = self.session_get('original_uri', None)
    if original_uri is None:
      logger.info('Finished auth, no original_uri in request')
      return flask.redirect(self.config.rooturl)

    logger.debug('Finished auth, redirecting to: %s', original_uri)
    return flask.redirect(self.config.rooturl + original_uri)

  def logout(self):
    """
    Delete the user's session, effectively logging them out.
    """
    flask.session.clear()
    return self.render_message('Logged out')

  def get_session(self):
    """
    Return the user's session as a json object. Can be used to retrieve user
    identity within other frontend services, or for debugging.
    """

    session_dict = {key: self.session_get(key)
                    for key in ['email', 'name', 'given_name', 'user']}
    return flask.jsonify(session_dict)


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
    self.flask_privkey = get_default(flask_privkey,
                                     base64.b64encode(os.urandom(24)))
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
    for key, _ in kwargs.items():
      if not key.startswith('_'):
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
    "secrets": "The location of client_secrets.json",
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
        " to the forbidden page after a successful auth.")
}
