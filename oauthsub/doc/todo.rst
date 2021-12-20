====
TODO
====

* Use the base url configuration parameter in the layout template, rather than
  hardcoding `auth/`.
* Decide whether or not to support custom redirects. Instead of serving up
  jinja renderings we could redirect to user-configured webpages. We can
  provide messages or additional data in cookies by adding the `Set-Cookie`
  header to the response before sending it out. The user defined pages can
  then do whatever they want with the cookie information.
