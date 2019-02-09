<html>
  <head>
  <title>Simple Auth Service</title>
  <style type="text/css">
  </style>
  </head>
  <body>
  <div class="navigation">
    <ul>
    {% for provider in providers %}
      {% if original_uri -%}
      <li><a href=
        "{{route_prefix}}/login?provider={{provider}}&original_uri={{url_encode(original_uri)}}">
        login ({{provider}})</a>  - redirect </li>
      {%- else -%}
      <li><a href=
        "{{route_prefix}}/login?provider={{provider}}">
        login ({{provider}}) </a> </li>
      {%- endif %}
    {% endfor %}
    <li> <a href="{{route_prefix}}/logout">logout</a> </li>
    </ul>
  </div>
  <div class="content">
  {% block content %}
  {% endblock %}
  </div>
  </body>
</html>
