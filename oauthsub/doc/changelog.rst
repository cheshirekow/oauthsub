=========
Changelog
=========

-----------
v0.2 series
-----------

v0.2.0
------

* ported to from oauth2client (deprecated) to oauthlib
* slight refactoring into utils/appliation
* refactored application logic into a more flask-familiar layout

-----------
v0.1 series
-----------

v0.1.3
------

* python3 compatability
* add bypass option for debugging in a local environment
* cleanup package organization a bit
* add github provider support
* allow custom jinja template
* use gevent or twisted for production mode

v0.1.2
------

* Fix setup.py pointing to wrong main module, wrong keywords, missing
  package data
* Add Manifest.in
* Fix wrong config variable in main()

v0.1.1
------

* Fix setup.py description string

v0.1.0
------

Initial public commit

* Authenticates with google, authorizes anyone who has an email address
  that is part of a configurable list of domains.
* Only works with google as an identity provider
* Configuration through python config file, or command line arguments
* Includes example nginx and oauthsub configuration files
* Module directory can be zipped into an executable zipfile and distributed
  as a single file.
