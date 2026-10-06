from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from csp.constants import NONCE
from csp.utils import DIRECTIVES_T


@dataclass
class PolicyParts:
    config: DIRECTIVES_T | None = None
    update: DIRECTIVES_T | None = None
    replace: DIRECTIVES_T | None = None
    nonce: str | None = None


@dataclass
class PolicyPartsCollection:
    enforced: list[PolicyParts] = field(default_factory=list)
    report_only: list[PolicyParts] = field(default_factory=list)

    @staticmethod
    def _to_serializable(value: Any) -> Any:
        if value is NONCE:
            return {"__csp_type__": "nonce"}
        if isinstance(value, dict):
            return {key: PolicyPartsCollection._to_serializable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            type_name = "set" if isinstance(value, set) else "tuple" if isinstance(value, tuple) else "list"
            return {
                "__csp_type__": type_name,
                "values": [PolicyPartsCollection._to_serializable(item) for item in value],
            }
        return value

    @staticmethod
    def _from_serializable(value: Any) -> Any:
        if isinstance(value, dict) and "__csp_type__" in value:
            type_name = value["__csp_type__"]
            if type_name == "nonce":
                return NONCE
            items = [
                PolicyPartsCollection._from_serializable(item)
                for item in value.get("values", [])
            ]
            if type_name == "set":
                return set(items)
            if type_name == "tuple":
                return tuple(items)
            return items
        if isinstance(value, dict):
            return {
                key: PolicyPartsCollection._from_serializable(item)
                for key, item in value.items()
            }
        return value

    @classmethod
    def _policy_to_dict(cls, policy: PolicyParts) -> dict[str, Any]:
        return {
            "config": cls._to_serializable(policy.config),
            "update": cls._to_serializable(policy.update),
            "replace": cls._to_serializable(policy.replace),
            "nonce": policy.nonce,
        }

    @classmethod
    def _policy_from_dict(cls, data: dict[str, Any]) -> PolicyParts:
        return PolicyParts(
            config=cls._from_serializable(data.get("config")),
            update=cls._from_serializable(data.get("update")),
            replace=cls._from_serializable(data.get("replace")),
            nonce=data.get("nonce"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enforced": [self._policy_to_dict(policy) for policy in self.enforced],
            "report_only": [self._policy_to_dict(policy) for policy in self.report_only],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyPartsCollection:
        return cls(
            enforced=[cls._policy_from_dict(policy) for policy in data.get("enforced", [])],
            report_only=[cls._policy_from_dict(policy) for policy in data.get("report_only", [])],
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> PolicyPartsCollection:
        return cls.from_dict(json.loads(value))
