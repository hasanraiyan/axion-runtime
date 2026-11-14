from typing import List, Type
from beanie import Document
from app.models.user import User, UserRole

# Registry of all Beanie document models for initialization.
DOCUMENT_MODELS: List[Type[Document]] = [
    User,
]

__all__ = [
    "User",
    "UserRole",
    "DOCUMENT_MODELS",
]
