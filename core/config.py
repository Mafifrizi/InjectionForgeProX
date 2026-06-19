import json
from pathlib import Path
from typing import Any, Dict


def _simple_yaml_load(text: str) -> Dict[str, Any]:
    """Small YAML subset parser used when PyYAML is unavailable.

    Supports top-level key/value pairs and simple nested dictionaries through
    indentation. For complex YAML, install PyYAML.
    """
    data: Dict[str, Any] = {}
    current_parent = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")) and line.endswith(":"):
            current_parent = line[:-1].strip()
            data[current_parent] = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"\'')
        parsed: Any = value
        if value.lower() in {"true", "false"}:
            parsed = value.lower() == "true"
        else:
            try:
                parsed = int(value)
            except ValueError:
                try:
                    parsed = float(value)
                except ValueError:
                    parsed = value
        if raw_line.startswith((" ", "\t")) and current_parent:
            data.setdefault(current_parent, {})[key] = parsed
        else:
            data[key] = parsed
            current_parent = None
    return data


def load_profile(path: str) -> Dict[str, Any]:
    profile_path = Path(path).expanduser().resolve()
    if not profile_path.exists():
        raise FileNotFoundError(f"Profile file not found: {profile_path}")
    text = profile_path.read_text(encoding="utf-8")
    suffix = profile_path.suffix.lower()
    if suffix == ".json":
        return json.loads(text)
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
            loaded = yaml.safe_load(text) or {}
            if not isinstance(loaded, dict):
                raise ValueError("Profile YAML root must be an object")
            return loaded
        except ImportError:
            return _simple_yaml_load(text)
    raise ValueError("Profile must be .json, .yaml, or .yml")


def _profile_to_arg_name(key: str) -> str:
    return key.replace("-", "_")


def apply_profile(args: Any, profile: Dict[str, Any]) -> Any:
    """Apply profile values only where the CLI kept the parser default/None.

    Explicit CLI flags win over profile values. Profiles may include a top-level
    `headers` object, which is converted to the JSON string expected by forge_x.
    """
    defaults = {
        "target": "auto", "method": "POST", "language": "auto", "analysis_mode": "balanced",
        "rounds": 10, "category": "basic", "workers": 4, "delay": 1.0, "timeout": 30,
        "format": "json", "bypass_waf": "none", "tls_fingerprint": "none",
        "rate_limit": 0.0, "burst": 1, "authorized": False, "redact": True,
        "offline": False, "light": False, "audit": False, "mutate": False, "aggressive": False,
        "adaptive": False, "multi_stage": False, "attack_tree": False, "ai_payloads": False,
        "adaptive_agent": False, "diff": False, "stealth": False, "insecure": False,
        "discover": False, "waf_detect": False, "graphql_introspect": False, "headless": False,
    }
    for raw_key, value in profile.items():
        key = _profile_to_arg_name(raw_key)
        if not hasattr(args, key):
            continue
        current = getattr(args, key)
        default = defaults.get(key, None)
        should_apply = current is None or current == default
        if not should_apply:
            continue
        if key == "headers" and isinstance(value, dict):
            value = json.dumps(value)
        setattr(args, key, value)
    return args
