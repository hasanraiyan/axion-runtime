from typing import List, Type
from beanie import Document
from app.models.user import User, UserRole
from app.models.project import (
    Project,
    ProjectMember,
    ProjectAuditLog,
    ProjectStatus,
    ProjectRole,
    ProjectAuditAction,
    ProjectSettings,
)
from app.models.secret import (
    ProjectSecret,
    EncryptedEnvelope,
)
from app.models.credential import (
    ProjectCredential,
    CredentialStatus,
)
from app.models.project_provider import (
    HealthcheckStatus,
    ProjectProvider,
    ProviderStatus,
    ProviderType,
)
from app.models.project_model import (
    ModelType,
    ProjectModel,
)
from app.models.project_routing_policy import (
    ProjectRoutingPolicy,
)

from app.models.integration import Integration, IntegrationStatus, IntegrationType  # noqa: E402
from app.models.tool import ToolBinding, ToolDefinition, ToolSetting  # noqa: E402
from app.models.end_user import ProjectEndUser  # noqa: E402
from app.models.tool_invocation import ToolInvocation  # noqa: E402
from app.models.connection import (  # noqa: E402
    ConnectSession,
    IntegrationConnection,
    IntegrationOAuthClient,
    ProjectToolPolicy,
)

# Registry of all Beanie document models for initialization.
DOCUMENT_MODELS: List[Type[Document]] = [
    User,
    Project,
    ProjectMember,
    ProjectAuditLog,
    ProjectSecret,
    ProjectCredential,
    ProjectProvider,
    ProjectModel,
    ProjectRoutingPolicy,
    Integration,
    ToolDefinition,
    ToolSetting,
    ToolBinding,
    ProjectEndUser,
    ToolInvocation,
    IntegrationConnection,
    ConnectSession,
    IntegrationOAuthClient,
    ProjectToolPolicy,
]

__all__ = [
    "User",
    "UserRole",
    "Project",
    "ProjectMember",
    "ProjectAuditLog",
    "ProjectStatus",
    "ProjectRole",
    "ProjectAuditAction",
    "ProjectSettings",
    "ProjectSecret",
    "EncryptedEnvelope",
    "ProjectCredential",
    "CredentialStatus",
    "ProjectProvider",
    "ProviderType",
    "ProviderStatus",
    "HealthcheckStatus",
    "ProjectModel",
    "ModelType",
    "ProjectRoutingPolicy",
    "Integration",
    "IntegrationType",
    "IntegrationStatus",
    "ToolDefinition",
    "ToolSetting",
    "ToolBinding",
    "ProjectEndUser",
    "ToolInvocation",
    "IntegrationConnection",
    "ConnectSession",
    "IntegrationOAuthClient",
    "ProjectToolPolicy",
    "DOCUMENT_MODELS",
]
