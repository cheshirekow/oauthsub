=====
PHPbb
=====

phpbb is a bulletin board service written in php. In our example setup we will
run it through ``fpm`` as a fast-cgi gateway.

Add the following to your nginx configuration::

    location ~ \.php(/|$) {
      auth_request /auth/query_auth;

      auth_request_set $user $upstream_http_x_gsuite_user;
      fastcgi_param REMOTE_USER $user;

      # -- include /etc/nginx/snippets/fastcgi-php.conf;
      fastcgi_split_path_info ^(.+\.php)(/?.+)$;
      try_files $fastcgi_script_name =404;
      set $path_info $fastcgi_path_info;
      fastcgi_param PATH_INFO $path_info;
      fastcgi_index index.php;
      include /etc/nginx/fastcgi.conf;
      # -- end of snippets/fastcgi-php.conf

      fastcgi_pass unix:/workdir/php7.0-fpm.sock;
    }

In order to take advantage of ``oauthsub`` as the authenticator, we need to
install the `Remote User`__ plugin (phpbb `forum page`__).

.. __: https://github.com/cheshirekow/phpbb_remoteuser
.. __: https://www.phpbb.com/community/viewtopic.php?f=456&t=2503666&p=15205231#p15205231

Download the zip file, and extract it to
``phpBB/ext/cheshirekow/remoteuseauth``. Once installed, go to the
administrator control panel and activate it (see the github README for
screenshots).
