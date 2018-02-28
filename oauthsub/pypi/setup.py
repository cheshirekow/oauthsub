import io
from setuptools import setup

GITHUB_URL = 'https://github.com/cheshirekow/oauthsub'
VERSION = '0.1.0'

with io.open('README.rst', encoding='utf8') as infile:
  long_description = infile.read()

setup(
    name='oauthsub',
    packages=['oauthsub'],
    version=VERSION,
    description="Simple oauth2 subrequest handler for nginx",
    long_description=long_description,
    author='Josh Bialkowski',
    author_email='josh.bialkowski@gmail.com',
    url=GITHUB_URL,
    download_url='{}/archive/{}.tar.gz'.format(GITHUB_URL, VERSION),
    keywords=['cmake', 'format'],
    classifiers=[],
    entry_points={
        'console_scripts': ['oauthsub=oauthsub.__main__:main'],
    },
    install_requires=[
      'Flask',
      'jinja2',
      'oauth2client',
      'requests',
    ]
)
