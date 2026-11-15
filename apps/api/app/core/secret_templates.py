"""
``{{secrets.NAME}}`` template parsing. Pure string handling, so it lives in ``core`` and can be used by
services and integration adapters alike without either depending on the other.
"""
import re
from typing import Dict, List


class SecretTemplateParser:
    """
    Dedicated parser for extracting placeholders and interpolating secrets
    into {{secrets.VAR_NAME}} configuration templates.
    """

    PLACEHOLDER_REGEX = re.compile(r"\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}")

    @classmethod
    def extract_placeholders(cls, template_str: str) -> List[str]:
        """Extract all unique {{secrets.VAR_NAME}} variable names from a template string."""
        matches = cls.PLACEHOLDER_REGEX.findall(template_str)
        return sorted(list(set(matches)))

    @classmethod
    def interpolate(cls, template_str: str, secrets_map: Dict[str, str]) -> str:
        """
        Replace {{secrets.VAR_NAME}} placeholders with their decrypted values.
        If a key is missing from secrets_map, leaves the placeholder untouched.
        """
        return cls.PLACEHOLDER_REGEX.sub(
            lambda m: secrets_map.get(m.group(1), m.group(0)),
            template_str,
        )
