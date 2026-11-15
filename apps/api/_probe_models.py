import asyncio


async def main() -> None:
    from pymongo import AsyncMongoClient

    from app.core.config import settings

    client = AsyncMongoClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB_NAME]

    async for p in db["project_providers"].find({}, {"name": 1, "provider_type": 1, "base_url": 1, "status": 1}):
        print("provider:", p.get("name"), p.get("provider_type"), p.get("base_url"), p.get("status"))

    print("---- project_models ----")
    async for m in db["project_models"].find(
        {},
        {
            "model_id": 1,
            "display_name": 1,
            "max_input_tokens": 1,
            "max_output_tokens": 1,
            "default_temperature": 1,
            "supports_streaming": 1,
            "model_type": 1,
            "revision": 1,
            "created_at": 1,
            "updated_at": 1,
            "is_deleted": 1,
        },
    ).limit(80):
        print(
            f"{m.get('model_id')!s:45} in={m.get('max_input_tokens')!s:>8} out={m.get('max_output_tokens')!s:>7} "
            f"temp={m.get('default_temperature')!s:>5} stream={m.get('supports_streaming')!s:>5} type={m.get('model_type')} "
            f"upd={m.get('updated_at')}"
        )
    print("total models:", await db["project_models"].count_documents({}))
    await client.close()


asyncio.run(main())
