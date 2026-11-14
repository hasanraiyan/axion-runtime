"""
Generic Base Repository providing standardized CRUD operations for Beanie Documents.
"""
from typing import Any, Generic, List, Mapping, Optional, Type, TypeVar
from beanie import Document, PydanticObjectId
from beanie.odm.queries.find import FindMany
from bson import ObjectId

T = TypeVar("T", bound=Document)


class BaseRepository(Generic[T]):
    """
    Abstract base repository encapsulating Beanie ODM operations.
    Isolates database queries from business logic in the service layer.
    """

    def __init__(self, model_class: Type[T]) -> None:
        self.model_class = model_class

    def is_db_ready(self) -> bool:
        """Check whether the underlying PyMongo collection is connected and initialized."""
        try:
            settings = self.model_class.get_settings()
            return settings.pymongo_collection is not None
        except Exception:
            return False

    def get_collection(self) -> Any:
        """Return the underlying Motor/PyMongo collection."""
        if hasattr(self.model_class, "get_motor_collection"):
            return self.model_class.get_motor_collection()
        if hasattr(self.model_class, "get_pymongo_collection"):
            return self.model_class.get_pymongo_collection()
        settings = self.model_class.get_settings()
        return settings.pymongo_collection

    def _to_object_id(self, id_val: str | PydanticObjectId | ObjectId) -> ObjectId:
        """Safely convert string or PydanticObjectId to BSON ObjectId."""
        if isinstance(id_val, ObjectId):
            return id_val
        try:
            return ObjectId(str(id_val))
        except Exception as exc:
            raise ValueError(f"Invalid ObjectId format: {id_val}") from exc

    async def get_by_id(self, id: str | PydanticObjectId | ObjectId) -> Optional[T]:
        """Fetch a single document by its primary key ID."""
        if not self.is_db_ready():
            return None
        try:
            oid = self._to_object_id(id)
            return await self.model_class.get(oid)
        except Exception:
            return None

    async def find_one(self, *expressions: Mapping[str, Any] | bool, **kwargs: Any) -> Optional[T]:
        """Find a single document matching criteria."""
        if not self.is_db_ready():
            return None
        return await self.model_class.find_one(*expressions, **kwargs)

    async def find_many(
        self,
        *expressions: Mapping[str, Any] | bool,
        skip: int = 0,
        limit: int = 100,
        sort: Optional[Any] = None,
        **kwargs: Any,
    ) -> List[T]:
        """Query multiple documents with pagination and sorting."""
        if not self.is_db_ready():
            return []
        query: FindMany[T] = self.model_class.find(*expressions, **kwargs).skip(skip).limit(limit)
        if sort is not None:
            query = query.sort(sort)
        return await query.to_list()

    async def count(self, *expressions: Mapping[str, Any] | bool, **kwargs: Any) -> int:
        """Count documents matching criteria."""
        if not self.is_db_ready():
            return 0
        return await self.model_class.find(*expressions, **kwargs).count()

    async def exists(self, *expressions: Mapping[str, Any] | bool, **kwargs: Any) -> bool:
        """Check whether at least one matching document exists."""
        count = await self.count(*expressions, **kwargs)
        return count > 0

    async def create(self, document: T, session: Optional[Any] = None) -> T:
        """Insert a new document into MongoDB."""
        if session is not None:
            await document.insert(session=session)
        else:
            await document.insert()
        return document

    async def update(self, document: T, session: Optional[Any] = None) -> T:
        """Save changes to an existing document."""
        if session is not None:
            await document.save(session=session)
        else:
            await document.save()
        return document

    async def delete(self, document: T, session: Optional[Any] = None) -> None:
        """Delete a document from MongoDB."""
        if session is not None:
            await document.delete(session=session)
        else:
            await document.delete()

    async def delete_by_id(self, id: str | PydanticObjectId | ObjectId) -> bool:
        """Delete a document by ID. Returns True if deleted, False if not found."""
        doc = await self.get_by_id(id)
        if doc is not None:
            await self.delete(doc)
            return True
        return False
