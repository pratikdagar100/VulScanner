"""Shared schema building blocks."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Message(BaseModel):
    detail: str


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class ScanProfileInfo(BaseModel):
    name: str
    description: str
    collectors: list[str] = Field(default_factory=list)


class CollectorInfo(BaseModel):
    name: str
    category: str
    description: str
    requires_admin: bool
    profiles: list[str]
