from typing import List, Type
from beanie import Document

# Registry of all Beanie document models for initialization.
# Domain document models will be registered here.
DOCUMENT_MODELS: List[Type[Document]] = []
