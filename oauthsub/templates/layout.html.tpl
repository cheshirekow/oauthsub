<html>
  <head>
  <title>Simple Auth Service</title>
  <style type="text/css">
  </style>
  </head>
  <body>
  <div class="navigation">
    <ul>
    {% if original_uri -%}
    <li> <a href="/auth/login?original_uri={{url_encode(original_uri)}}">login{redirect}</a> </li>
    {%- else -%}
    <li> <a href="/auth/login">login</a> </li>
    {%- endif %}
    <li> <a href="/auth/logout">logout</a> </li>

    </ul>
  </div>
  <div class="content">
  {% block content %}
  {% endblock %}
  </div>
  </body>
</html>
