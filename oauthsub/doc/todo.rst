====
TODO
====

* Replace `auth/callback` endpoint with per-service endpoings `callback_google`
  and `callback_github`. Start by just adding `callback_github` and making
  that work.
* Use flask.request.path to get the path of the callback that was called.
* Use the base url configuration parameter in the layout template, rather than
  hardcoding `auth/`.
* Replace oauth2client since google has deprecated it and is not longer
  supporting it. Replace with oauthlib_ maybe.
* Decide whether or not to support custom redirects. Instead of serving up
  jinja renderings we could redirect to user-configured webpages. We can provide
  messages or additional data in cookies by adding the `Set-Cookie` header
  to the response before sending it out. The user defined pages can then do
  whatever they want with the cookie information.

.. _oauthlib: https://oauthlib.readthedocs.io/en/v3.0.0/oauth2/oauth2.html
