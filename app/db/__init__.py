"""app.db — database foundations: the declarative ``Base`` and the async session.

Import-side-effect free on purpose: importing this package must NOT create the
engine or read ``DATABASE_URL`` — that happens only when :mod:`app.db.session` is
imported. Consumers import the submodule they need (``app.db.base`` for the model
``Base``/mixins, ``app.db.session`` for the ``get_session`` request dependency).
"""
