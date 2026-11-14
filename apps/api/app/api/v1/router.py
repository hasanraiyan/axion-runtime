from fastapi import APIRouter
from app.api.v1.endpoints import auth, credentials, health, projects, secrets

api_v1_router = APIRouter()

api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(projects.router, prefix="/projects", tags=["Projects"])
api_v1_router.include_router(secrets.router, prefix="/projects/{project_id}/secrets", tags=["Secrets"])
api_v1_router.include_router(credentials.router, prefix="/projects/{project_id}/credentials", tags=["Project Credentials"])
