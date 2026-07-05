"""Shared schema primitives.

Kept dependency-free (only pydantic + typing) so every other schema module and
the routers can import :class:`Page` without pulling in models.
"""

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """A single page of results.

    Constructed directly by the API routers, e.g.::

        Page[EngagementRead](items=[...], total=total, limit=limit, offset=offset)

    ``total`` is the full unpaginated count; ``limit``/``offset`` echo the query
    window that produced ``items``.
    """

    items: list[T]
    total: int
    limit: int
    offset: int
