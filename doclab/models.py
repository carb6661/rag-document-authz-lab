from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Principal(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    user_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    tenant_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    role: Literal["reader", "editor", "tenant_admin"]


class Document(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    tenant_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    owner_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    title: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=10_000)
    version: int = Field(default=1, ge=1, strict=True)


class DocumentPatch(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    text: str | None = Field(default=None, min_length=1, max_length=10_000)
    expected_version: int = Field(ge=1, strict=True)

    @field_validator("title", "text")
    @classmethod
    def nonblank(cls, value):
        if value is not None and (not value.strip() or "\x00" in value):
            raise ValueError("content must be nonblank and contain no NUL")
        if value is not None:
            try:
                value.encode("utf-8")
            except UnicodeError:
                raise ValueError("invalid Unicode") from None
        return value


class RetrievalRequest(StrictModel):
    query: str = Field(min_length=1, max_length=128)
    top_k: int = Field(default=5, ge=1, le=10, strict=True)

    @field_validator("query")
    @classmethod
    def query_valid(cls, value):
        DocumentPatch.nonblank(value)
        if len(set(value.casefold().split())) > 8:
            raise ValueError("at most eight whitespace-separated terms")
        return value
