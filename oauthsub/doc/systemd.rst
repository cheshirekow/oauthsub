------------
Systemd Unit
------------

For linux servers using systemd, you can add
``/etc/systemd/system/oauthsub.service``, an example which is given below
assuming we want the service to run as user ``ubuntu`` and the configuration
file is in ``/etc/oauthsub.py``.

.. dynamic: oauthsub.service-begin

.. code:: text

    [Unit]
    Description=oauthsub service
    After=nginx.service

    [Service]
    Type=simple
    ExecStart=/usr/local/bin/oauthsub --config /etc/oauthsub.py
    User=ubuntu
    Restart=on-abort

    [Install]
    WantedBy=multi-user.target

.. dynamic: oauthsub.service-end
