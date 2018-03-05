=========
Changelog
=========

------
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

v0.1.1
------

* Fix setup.py description string

v0.1.2
------

* Fix setup.py pointing to wrong main module, wrong keywords, missing
  package data
* Add Manifest.in
* Fix wrong config variable in main()
