import argparse
import io
import json
import logging
import os
import pprint
import sys
import textwrap

import oauthsub
from oauthsub import auth_service
from oauthsub import configuration

logger = logging.getLogger("oauthsub")

if sys.version_info < (3, 0, 0):
  STRING_TYPES = (str, unicode)
else:
  STRING_TYPES = (str,)


def parse_bool(string):
  """
  Parse a string into a boolean.
  """

  if string.lower() in ('y', 'yes', 't', 'true', '1', 'yup', 'yeah', 'yada'):
    return True

  if string.lower() in ('n', 'no', 'f', 'false', '0', 'nope', 'nah', 'nada'):
    return False

  logger.warning("Ambiguous truthiness of string '%s' evalutes to 'FALSE'",
                 string)
  return False


def dump_config(config, outfile):
  """
  Dump configuration to the output stream
  """
  ppr = pprint.PrettyPrinter(indent=2)
  for key in configuration.Configuration.get_fields():
    helptext = configuration.VARDOCS.get(key, None)
    if helptext:
      for line in textwrap.wrap(helptext, 78):
        outfile.write('# ' + line + '\n')
    value = getattr(config, key)
    if isinstance(value, dict):
      outfile.write('{} = {}\n\n'.format(key, json.dumps(value, indent=2)))
    else:
      outfile.write('{} = {}\n\n'.format(key, ppr.pformat(value)))


def setup_parser(parser, config_dict):
  """
  Configure argparse instance
  """

  parser.add_argument('--dump-config', action='store_true',
                      help='Dump configuration and exit')
  parser.add_argument('-v', '--version', action='version',
                      version=oauthsub.VERSION)
  parser.add_argument('-l', '--log-level', default='info',
                      choices=['debug', 'info', 'warning', 'error'],
                      help='Increase log level to include info/debug')
  parser.add_argument('-c', '--config-file',
                      help='use a configuration file')
  parser.add_argument("-s", "--server", default=None,
                      choices=["flask", "gevent", "twisted"],
                      help="Which WGSI server to use")

  for key in configuration.Configuration.get_fields():
    if key in ("server",):
      continue

    value = config_dict[key]
    helptext = configuration.VARDOCS.get(key, None)
    # NOTE(josh): argparse store_true isn't what we want here because we want
    # to distinguish between "not specified" = "default" and "specified"
    if isinstance(value, bool):
      parser.add_argument('--' + key.replace('_', '-'), nargs='?', default=None,
                          const=True, type=parse_bool, help=helptext)
    elif isinstance(value, STRING_TYPES + (int, float)):
      parser.add_argument('--' + key.replace('_', '-'), type=type(value),
                          help=helptext)
    elif value is None:
      parser.add_argument('--' + key.replace('_', '-'), type=type(value),
                          help=helptext)
    # NOTE(josh): argparse behavior is that if the flag is not specified on
    # the command line the value will be None, whereas if it's specified with
    # no arguments then the value will be an empty list. This exactly what we
    # want since we can ignore `None` values.
    elif isinstance(value, (list, tuple)):
      parser.add_argument('--' + key.replace('_', '-'), nargs='*',
                          help=helptext)


def main():
  # This is necessary for testing with non-HTTPS localhost
  # Remove this if deploying to production
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # This is necessary because Azure does not guarantee
  # to return scopes in the same case and order as requested
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
  os.environ['OAUTHLIB_IGNORE_SCOPE_CHANGE'] = '1'

  logging.basicConfig(level=logging.DEBUG, filemode='w')
  parser = argparse.ArgumentParser(
      prog='oauthsub', description=auth_service.__doc__)

  config_dict = configuration.Configuration().serialize()
  setup_parser(parser, config_dict)
  args = parser.parse_args()

  if args.dump_config:
    dump_config(configuration.Configuration(), sys.stdout)
    sys.exit(0)

  if args.config_file:
    configpath = os.path.expanduser(args.config_file)
    config_dict["__file__"] = os.path.realpath(configpath)
    with io.open(configpath, 'r', encoding='utf8') as infile:
      # pylint: disable=W0122
      exec(infile.read(), config_dict)
    config_dict.pop("__file__")

  for key, value in vars(args).items():
    if key in config_dict and value is not None:
      config_dict[key] = value
  config = configuration.Configuration(**config_dict)

  # Create directory for logs if it doesn't exist
  if not os.path.exists(config.logdir):
    os.makedirs(config.logdir)

  # We'll add a handler which puts log events in an actual file for review as
  # needed. We'll put the log file on a rotation where each log may grow up to
  # 1 megabyte with up to 10 backups
  filelog = logging.handlers.RotatingFileHandler(
      os.path.join(config.logdir, 'oauthsub.log'),
      maxBytes=int(1e6), backupCount=10)

  # We'll add a timestamp to the format for this log
  format_str = ('%(asctime)s %(levelname)-4s %(filename)s [%(lineno)-3s] :'
                ' %(message)s')
  filelog.setFormatter(logging.Formatter(format_str))
  logging.getLogger("").addHandler(filelog)

  config_dict = config.serialize()
  config_dict.pop('secrets', None)
  config_dict.pop('client_secrets', None)
  logging.info(
      'Configuration: %s',
      json.dumps(config_dict, indent=2, sort_keys=True))

  # NOTE(josh): hack to deal with jinja's failure to resolve relative imports
  # to absolute paths
  oauthsub.__file__ = os.path.abspath(oauthsub.__file__)
  app = auth_service.Application(config)

  if config.server == "flask":
    app.run(threaded=True, host=config.host, port=config.port)
  elif config.server == "gevent":
    from gevent.pywsgi import WSGIServer
    WSGIServer((config.host, config.port), app).serve_forever()
  elif config.server == "twisted":
    from twisted.web import server
    from twisted.web.wsgi import WSGIResource
    from twisted.python.threadpool import ThreadPool
    from twisted.internet import reactor

    thread_pool = ThreadPool()
    thread_pool.start()
    reactor.addSystemEventTrigger('after', 'shutdown', thread_pool.stop)
    resource = WSGIResource(reactor, thread_pool, app)
    factory = server.Site(resource)
    reactor.listenTCP(config.port, factory)
    reactor.run()


if __name__ == '__main__':
  main()
