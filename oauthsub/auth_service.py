"""
This lightweight web service performs authentication. All requests that reach
this service should be proxied through nginx.

See: https://developers.google.com/api-client-library/python/auth/web-app
"""

from __future__ import print_function
from __future__ import unicode_literals

import inspect
import os
import json
import logging
import logging.handlers
import sys

import flask
import jinja2
from requests_oauthlib import OAuth2Session

import oauthsub
from oauthsub import util

logger = logging.getLogger("oauthsub")

if sys.version_info < (3, 0, 0):
  # pylint: disable=E1101
  import urllib as parse
else:
  # pylint: disable=E1101
  from urllib import parse


def strip_settings(settings_dict):
  """
  Return a copy of the settings dictionary including only the kwargs
  expected by OAuth2Session
  """

  # NOTE(josh): args[0] is `self`
  if sys.version_info < (3, 5, 0):
    # pylint: disable=W1505
    fields = inspect.getargspec(OAuth2Session.__init__).args[1:]
  else:
    sig = getattr(inspect, 'signature')(OAuth2Session.__init__)
    fields = [field for field, _ in list(sig.parameters.items())[1:-1]]

  return {k: v for k, v in settings_dict.items() if k in fields}


def login():
  """
  The login page. Start of the oauth dance. Construct a flow, get redirect,
  bounce the user.
  """

  app = flask.current_app
  if app.session_get('user') is not None:
    return app.render_message("You are already logged in as {}",
                              app.session_get('user'))

  provider = flask.request.args.get("provider")
  if provider is None:
    return flask.make_response(
        app.render_message("No provider!"), 403, {})

  if provider not in app.app_config.client_secrets:
    message = "Invalid provider: {}".format(provider)
    html = app.render_message(message)
    response = flask.make_response(html, 403, {})
    return response

  app.session_set(
      "original_uri", flask.request.args.get("original_uri"))

  logger.debug("Requesting auth from provider: %s", provider)
  settings = app.app_config.client_secrets[provider]
  kwargs = strip_settings(settings)
  client = OAuth2Session(**kwargs)
  auth_uri, csrf_token = client.authorization_url(
      settings["authorize_uri"], prompt="login")
  app.session_set("csrf_token", csrf_token)
  return flask.redirect(auth_uri)


def logout():
  """
  Delete the user's session, effectively logging them out.
  """
  app = flask.current_app
  flask.session.clear()
  return app.render_message('Logged out')


def callback():
  """
  Handle oauth bounce-back.
  """

  app = flask.current_app
  # If we didn't received a 'code' in the query parameters then this
  # definately not a redirect back from google.  Assume this is a user meaning
  # to use the /login endpoint and punt them to the start of the dance.
  if 'code' not in flask.request.args:
    return app.login()

  if 'provider' not in flask.request.args:
    return app.login()

  provider = flask.request.args.get("provider")
  if provider not in app.app_config.client_secrets:
    message = "Invalid provider: {}".format(provider)
    html = app.render_message(message)
    response = flask.make_response(html, 403, {})
    return response

  logger.debug("Fetching token from provider: %s", provider)
  settings = app.app_config.client_secrets[provider]
  kwargs = strip_settings(settings)
  kwargs["state"] = app.session_get("csrf_token")
  client = OAuth2Session(**kwargs)

  # Exchange the code that the provider gave us for an actual credentials
  # object, and store those credentials in the session for this user.
  kwargs = {key: settings[key]
            for key in ("token_uri", "client_secret")}
  kwargs["token_url"] = kwargs.pop("token_uri", None)
  kwargs["authorization_response"] = flask.request.url
  token = client.fetch_token(**kwargs)

  # Use the credentials that we have in order to get the users information
  # from the provider. We only need one request to get the user's email
  # address and name.
  if provider == "google":
    request_url = "https://www.googleapis.com/userinfo/v2/me?alt=json"
  elif provider == "github":
    request_url = "https://api.github.com/user"
  else:
    message = 'Invalid provider: {}'.format(provider)
    return flask.make_response(app.render_message(message), 401, {})

  response = client.get(request_url)
  if response.status_code != 200:
    message = 'Failed to query {}: [{}]'.format(provider, response.status)
    return flask.make_response(app.render_message(message), 500, {})

  # We'll store the users email, name, and 'given_name' from the provider's
  # reponse. This is just to help the user understand which identity
  # they currently have authenticated against.
  content_str = response.content.decode("utf-8")
  parsed_content = json.loads(content_str)

  # If the user logged in with an email domain other than <??> then we want
  # to warn them that they are probably not doing what they wanted to do.
  # TODO(josh): move into google-specific auth function
  if (app.app_config.allowed_domains
      and (parsed_content.get('hd') not in app.app_config.allowed_domains)):
    content = app.render_message('You did not login with the right account!')
    return flask.make_response(content, 401, {})

  username = app.app_config.user_lookup(provider, parsed_content)
  if username is None:
    logger.warning("user lookup failed: %s",
                   json.dumps(parsed_content, indent=2, sort_keys=True))
    content = "Failed user lookup"
    return flask.make_response(content, 401, {})
  app.session_set('user', username)
  app.session_set("token", json.dumps(token, indent=2, sort_keys=True))

  # At this point the user is authed
  for key in ['email', 'name', 'given_name']:
    app.session_set(key, parsed_content.get(key, "unknown"))

  # If we are logging-in due to attempt to access an auth-requiring page,
  # then go to back to that page
  original_uri = app.session_get('original_uri', None)
  if original_uri is None:
    logger.info('Finished auth, no original_uri in request')
    return flask.redirect(app.app_config.rooturl)

  logger.debug('Finished auth, redirecting to: %s', original_uri)
  return flask.redirect(app.app_config.rooturl + original_uri)


def query_auth():
  """
  This is the main endpoint used by nginx to check authorization. If this
  is an nginx request the X-Original-URI will be passed as an http header.
  """
  app = flask.current_app

  original_uri = flask.request.headers.get('X-Original-URI')
  if original_uri:
    logger.debug('Doing auth for original URI: %s, session %s',
                 original_uri, flask.session.get('id', None))

    # If bypass key is present and matches configured, then bypass the
    # auth-check and assume the user identity
    if app.app_config.bypass_key is not None:
      if ('X-OAuthSub-Bypass-Key' in flask.request.headers
          and 'X-OAuthSub-Bypass-User' in flask.request.headers):
        logger.debug("bypass headers are present")

        if(flask.request.headers['X-OAuthSub-Bypass-Key'] ==
           app.app_config.bypass_key):

          username = flask.request.headers["X-OAuthSub-Bypass-User"]
          logger.debug("admin bypass, setting user to %s", username)
          app.session_set("user", username)
        else:
          logger.warning("admin bypass key doesn't match")

    # NOTE(josh): we don't do any whitelisting here, we'll let the nginx
    # config decide which urls to request auth for
    if app.session_get('user', None) is not None:
      response = flask.make_response("", 200, {})
      if app.app_config.response_header:
        response.headers[app.app_config.response_header] \
            = app.session_get('user')
      return response

    # NOTE(josh): since nginx will return a 401, it will not pass the
    # Set-Cookie header to the client. This session will not be associated
    # with the client unless they already have a cookie for this site.
    # There's not much point in dealing with the X-Original-URI here since
    # we can't realiably maintain any context.
    return flask.make_response("", 401, {})

  flask.abort(401)
  return None


def forbidden():
  """
  The page served when a user isn't authorized. We'll just set the return
  path if it's available and then kick them through oauth2.
  """
  app = flask.current_app
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

  html = app.render_message('Permission denied. Are you logged in?',
                            original_uri=original_uri)
  return flask.make_response(html)


def get_session():
  """
  Return the user's session as a json object. Can be used to retrieve user
  identity within other frontend services, or for debugging.
  """

  app = flask.current_app
  session_dict = {
      key: app.session_get(key)
      for key in ('email', 'name', 'given_name', 'user')
  }
  return flask.jsonify(session_dict)


class Application(flask.Flask):
  """
  Main application context. Exists as a class to keep things local... even
  though flask is all about the global state.
  """

  def __init__(self, app_config):
    """
    Configure jinja, beaker, etc.
    """

    super(Application, self).__init__("oauthsub")

    # TODO(josh): validate config.client_secrets
    self.app_config = app_config

    # TODO(josh): move this to main() and pass in the template loader
    module_path = os.path.dirname(oauthsub.__file__)
    zipfile_path, package_path = util.get_zipfile_path(module_path)
    if self.app_config.custom_template:
      logger.info('Using FilesystemLoader for templates')
      template_loader = jinja2.FileSystemLoader(
          os.path.dirname(self.app_config.custom_template))
    elif zipfile_path:
      logger.info('Using ZipfileLoader for templates')
      template_loader = util.ZipfileLoader(zipfile_path,
                                           package_path + '/templates')
    else:
      logger.info('Using PackageLoader for templates')
      template_loader = jinja2.PackageLoader('oauthsub', 'templates')
    self.jinja = jinja2.Environment(loader=template_loader)
    self.jinja.globals.update(url_encode=parse.quote_plus)

    self.secret_key = app_config.flask_privkey
    self.debug = app_config.flask_debug
    for key, value in app_config.flaskopt.items():
      self.config[key] = value

    self.add_url_rule('{}/login'.format(app_config.route_prefix),
                      'login', login)
    self.add_url_rule('{}/logout'.format(app_config.route_prefix),
                      'logout', logout)
    self.add_url_rule('{}/callback'.format(app_config.route_prefix),
                      'callback', callback)
    self.add_url_rule('{}/get_session'.format(app_config.route_prefix),
                      'get_session', get_session)
    self.add_url_rule('{}/query_auth'.format(app_config.route_prefix),
                      'query_auth', query_auth)

    if app_config.enable_forbidden:
      self.add_url_rule('{}/forbidden'.format(app_config.route_prefix),
                        'forbidden', forbidden)

  def route(self, rule, **options):
    return super(Application, self).route(
        "{}/{}".format(self.app_config.route_prefix, rule),
        **options)

  def render_message(self, message, *args, **kwargs):
    # pylint: disable=no-member
    original_uri = kwargs.pop("original_uri", None)
    tplargs = {
        "session": flask.session,
        "message": message.format(*args, **kwargs),
        "providers": sorted(self.app_config.client_secrets.keys()),
        "original_uri": original_uri,
        "route_prefix": self.app_config.route_prefix
    }

    if self.app_config.custom_template:
      template = os.path.basename(self.app_config.custom_template)
    else:
      template = "message.html.tpl"

    return self.jinja.get_template(template).render(**tplargs)

  def session_get(self, key, default=None):
    """
    Return the value of the session variable `key`, using the prefix-qualifed
    name for `key`
    """
    qualified_key = '{}{}'.format(self.app_config.session_key_prefix, key)
    return flask.session.get(qualified_key, default)

  def session_set(self, key, value):
    """
    Set the value of the session variable `key`, using the prefix-qualifed
    name for `key`
    """
    qualified_key = '{}{}'.format(self.app_config.session_key_prefix, key)
    flask.session[qualified_key] = value
