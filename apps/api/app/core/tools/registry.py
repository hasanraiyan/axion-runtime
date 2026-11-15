"""
Registries (Open/Closed): the only place that maps a type key to its implementation.
Services never branch on integration type or auth type; adding one means adding a
class and a registration line.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from app.core.exceptions import BadRequestError
from app.core.tools.ports import AuthStrategy, ConfigDescriptor
from app.models.integration import AuthType, Integration, IntegrationType


def adapter_key(integration_type: IntegrationType, config: Optional[Dict[str, Any]] = None) -> str:
    """Registry key for an integration type; custom integrations select by ``config.kind``."""
    if integration_type == IntegrationType.CUSTOM:
        return f"custom:{(config or {}).get('kind', '')}"
    return integration_type.value


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: Dict[str, Any] = {}

    def register(self, adapter: Any) -> None:
        key = getattr(adapter, "key", None)
        if not key:
            raise ValueError("Adapter must define a non-empty 'key'")
        if key in self._adapters:
            raise ValueError(f"Adapter already registered for '{key}'")
        if not isinstance(adapter, ConfigDescriptor):
            raise ValueError(f"Adapter '{key}' must implement ConfigDescriptor")
        self._adapters[key] = adapter

    def get(self, key: str) -> Any:
        adapter = self._adapters.get(key)
        if adapter is None:
            raise BadRequestError(f"Unsupported integration type '{key}'")
        return adapter

    def for_integration(self, integration: Integration) -> Any:
        return self.get(adapter_key(integration.type, integration.config))

    def keys(self) -> list[str]:
        return sorted(self._adapters)


class AuthStrategyRegistry:
    def __init__(self) -> None:
        self._strategies: Dict[AuthType, AuthStrategy] = {}

    def register(self, strategy: AuthStrategy) -> None:
        if strategy.auth_type in self._strategies:
            raise ValueError(f"Auth strategy already registered for '{strategy.auth_type.value}'")
        self._strategies[strategy.auth_type] = strategy

    def get(self, auth_type: AuthType) -> AuthStrategy:
        strategy = self._strategies.get(auth_type)
        if strategy is None:
            raise BadRequestError(f"Authentication type '{auth_type.value}' is not supported yet")
        return strategy

    def types(self) -> list[AuthType]:
        return sorted(self._strategies, key=lambda t: t.value)
