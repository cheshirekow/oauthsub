============
Installation
============

Install with pip
================

The easiest way to install ``oauthsub`` is from `pypi.org`_
using `pip`_. For example::

    pip install oauthsub

If you're on a linux-type system (such as ubuntu) the above command might not
work if it would install into a system-wide location. If that's what you
really want you might need to use :code:`sudo`, e.g.::

    sudo pip install oauthsub

In general though I wouldn't really recommend doing that though since things
can get pretty messy between your system python distributions and your
:code:`pip` managed directories. Alternatively you can install it for your user
with::

    pip install --user oauthsub

which I would probably recommend for most users.

.. _`pypi.org`: https://pypi.org/project/oauthsub/
.. _pip: https://pip.pypa.io/en/stable/

Install from source
===================

You can also install from source with pip. You can download a release_ package
from github and then install it directly with pip. For example::

  pip install v0.1.0.tar.gz

.. _release: https://github.com/cheshirekow/oauthsub/releases

Note that the release packages are automatically generated from git tags which
are the same commit used to generate the corresponding version package on
``pypi.org``. So whether you install a particular version from github or
pypi shouldn't matter.

Pip can also install directly from github. For example::

    pip install git+https://github.com/cheshirekow/oauthsub.git

If you wish to test a pre-release or dev package from a branch called
``foobar`` you can install it with::

    pip install "git+https://github.com/cheshirekow/oauthsub.git@foobar"

