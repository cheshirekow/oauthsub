"""
Example configuration
"""

# The root URL for browser redirects
rooturl = 'http://localhost:8081'

# The location of client_secrets.json, or the raw JSON dictionary itself
secrets = '/tmp/client_secrets.json'

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
  'SESSION_TYPE' : 'filesystem',
  'SESSION_FILE_DIR' : '/tmp/auth_services/session_data',
  'PERMANENT_SESSION_LIFETIME' : 864000
}

# All routes are prefixed with this
route_prefix = '/auth'

# All session keys are prefixed with this
session_key_prefix = 'oauthsub-'
