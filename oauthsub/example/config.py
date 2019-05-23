"""
Example configuration
"""

# The root URL for browser redirects
rooturl = 'http://localhost:8081'

# Enable flask debugging for testing.
flask_debug = True

# Secret key used to sign cookies
flask_privkey = "3zoo1dUSUY7CI1k3UMe9I49FyH8hO0Fx"

# If specified, the authenticated user's ``username`` will be passed as a
# response header with this key.
response_header = 'X-Gsuite-User'

# List of domains that we allow in the `hd` field of the google response.
# Set this to your company gsuite domains.
allowed_domains = [
    'example.io',
    'example.com'
]

# The address and port that we are listening on
host = '0.0.0.0'
port = 8081

# Directory where we store resource files
logdir = '/tmp/auth_service/logs'

# Flask configuration options
# -Each session data is stored inside a file located in the specified directory
# -The cookie expires after 10 days
flaskopt = {
    'SESSION_TYPE': 'filesystem',
    'SESSION_FILE_DIR': '/tmp/auth_services/session_data',
    'PERMANENT_SESSION_LIFETIME': 864000
}

# All routes are prefixed with this
route_prefix = '/auth'

# All session keys are prefixed with this
session_key_prefix = 'oauthsub-'

# Secret string which can be used to bypass authorization if proviededin an HTTP
# header `X-OAuthSub-Bypass`
bypass_key = '1cb024c8-2b03-11e9-be04-cb71b148e418'

# These are the credentials we use to access various oauth provider APIs
# You can often get these from "client_secrets.json"
client_secrets = {
  "google": {
    "client_id": ("000000000000-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                  ".apps.googleusercontent.com"),
    "authorize_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_secret": "xxxxxxxxxx-xxxxxxxxxxxxx",
    "redirect_uri": "http://lvh.me:8080/auth/callback?provider=google",
  },
  "github": {
    "client_id": "xxxxxxxxxxxxxxxxxxxx",
    "authorize_uri": "https://github.com/login/oauth/authorize",
    "token_uri": "https://github.com/login/oauth/access_token",
    "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "redirect_uris": "http://lvh.me:8080/auth/callback"
  }
}

# Path to custom jinja template
custom_template = None

# Enables the /forbidden endpoint, to which you can redirect 401 errors from
# your reverse proxy. This page is a simple message with the active template
# but includes login links that will redirect back to the forbidden page after
# a successful auth
enable_forbidden = True

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
