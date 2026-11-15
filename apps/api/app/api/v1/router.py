from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth,
    credentials,
    end_users,
    health,
    integrations,
    models,
    projects,
    providers,
    secrets,
    tool_runtime,
    tools,
)

api_v1_router = APIRouter()

api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(projects.router, prefix="/projects", tags=["Projects"])
api_v1_router.include_router(secrets.router, prefix="/projects/{project_id}/secrets", tags=["Secrets"])
api_v1_router.include_router(credentials.router, prefix="/projects/{project_id}/credentials", tags=["Project Credentials"])
api_v1_router.include_router(providers.router, prefix="/projects/{project_id}/providers", tags=["Providers"])
api_v1_router.include_router(models.router, prefix="/projects/{project_id}/models", tags=["Models"])
api_v1_router.include_router(integrations.router, prefix="/projects/{project_id}", tags=["Integrations"])
api_v1_router.include_router(tools.router, prefix="/projects/{project_id}", tags=["Tools"])
api_v1_router.include_router(tool_runtime.router, prefix="/projects/{project_id}", tags=["Tool Runtime"])
api_v1_router.include_router(end_users.router, prefix="/projects/{project_id}", tags=["End Users"])
