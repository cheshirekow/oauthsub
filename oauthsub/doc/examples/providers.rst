=========
Providers
=========

In order to take advantage of a public ``oauth2`` provider you must do some
setup. This usually involves registering an application and getting an
API token (a ``client_secret``). This section will walk you through the
process of registering with various popular providers.

In order to be explicit, we'll configure the client information for the
test setup that we've configured:

* ``nginx`` on ``localhost:8080``
* ``oauthsub`` on ``localhost:8081``

You will need to adapt these instructions for your production setup.

.. toctree::

   google
   github
   microsoft
   atlassian
