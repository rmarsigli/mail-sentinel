"""Load and validate config.ini into typed dataclasses.

Everything is validated up front so a typo fails at startup, not at 3 a.m.
when the first alert should have gone out.
"""
import configparser
import dataclasses
import os
import stat
from dataclasses import dataclass, field
from typing import Dict, List


class ConfigError(Exception):
    pass


@dataclass
class ServerCfg:
    name: str = ""
    maillog: str = "/var/log/maillog"
    exim_mainlog: str = "/var/log/exim_mainlog"
    state_dir: str = "/var/lib/mail-sentinel"
    log_file: str = "/var/log/mail-sentinel.log"


@dataclass
class ProviderCfg:
    kind: str = "brevo"
    api_key_file: str = "/etc/mail-sentinel/api.key"
    sender: str = ""  # the "from" key; renamed because "from" is a keyword


@dataclass
class RecipientsCfg:
    critical: List[str] = field(default_factory=list)
    high: List[str] = field(default_factory=list)
    medium: List[str] = field(default_factory=list)

    def for_severity(self, severity: str) -> List[str]:
        return list(getattr(self, severity))


@dataclass
class BruteForceCfg:
    min_failures: int = 20
    window_minutes: int = 15


@dataclass
class LockedOutCfg:
    min_failures: int = 10
    window_minutes: int = 60


@dataclass
class SendingCfg:
    ceiling_per_hour: int = 100
    baseline_multiplier: float = 5.0
    baseline_min_hours: int = 72
    baseline_floor: float = 2.0


@dataclass
class DedupCfg:
    brute_force_hours: int = 24
    locked_out_hours: int = 24


@dataclass
class Config:
    server: ServerCfg
    provider: ProviderCfg
    recipients: RecipientsCfg
    brute_force: BruteForceCfg
    locked_out: LockedOutCfg
    sending: SendingCfg
    dedup: DedupCfg
    overrides: Dict[str, Dict[str, float]]

    def sending_for(self, account: str) -> SendingCfg:
        base = dataclasses.replace(self.sending)
        for key, value in self.overrides.get(account, {}).items():
            setattr(base, key, type(getattr(base, key))(value))
        return base

    def redacted(self) -> str:
        lines = []
        for section in ("server", "provider", "recipients", "brute_force",
                        "locked_out", "sending", "dedup"):
            lines.append("[%s]" % section)
            for f in dataclasses.fields(getattr(self, section)):
                lines.append("%s = %s" % (f.name, getattr(getattr(self, section), f.name)))
        lines.append("[overrides]")
        for account, values in sorted(self.overrides.items()):
            lines.append("%s = %s" % (account, ", ".join("%s=%s" % kv for kv in sorted(values.items()))))
        return "\n".join(lines)


PROVIDERS = ("brevo", "resend")
SEVERITIES = ("critical", "high", "medium")

# section -> (dataclass, {ini key: field name})
_SECTIONS = {
    "server": (ServerCfg, {"name": "name", "maillog": "maillog", "exim_mainlog": "exim_mainlog",
                           "state_dir": "state_dir", "log_file": "log_file"}),
    "provider": (ProviderCfg, {"kind": "kind", "api_key_file": "api_key_file", "from": "sender"}),
    "brute_force": (BruteForceCfg, {"min_failures": "min_failures", "window_minutes": "window_minutes"}),
    "locked_out": (LockedOutCfg, {"min_failures": "min_failures", "window_minutes": "window_minutes"}),
    "sending": (SendingCfg, {"ceiling_per_hour": "ceiling_per_hour",
                             "baseline_multiplier": "baseline_multiplier",
                             "baseline_min_hours": "baseline_min_hours",
                             "baseline_floor": "baseline_floor"}),
    "dedup": (DedupCfg, {"brute_force_hours": "brute_force_hours", "locked_out_hours": "locked_out_hours"}),
}
_OVERRIDABLE = {f.name for f in dataclasses.fields(SendingCfg)}


def _check_mode_0600(path: str, what: str) -> None:
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise ConfigError("%s %s must be mode 0600, is %04o" % (what, path, mode))


def _coerce(field_type, raw: str, where: str):
    try:
        if field_type is int:
            return int(raw)
        if field_type is float:
            return float(raw)
        return raw.strip()
    except ValueError:
        raise ConfigError("%s: expected %s, got %r" % (where, field_type.__name__, raw))


def _build_section(parser, section: str):
    cls, keymap = _SECTIONS[section]
    obj = cls()
    if not parser.has_section(section):
        return obj
    types = {f.name: f.type for f in dataclasses.fields(cls)}
    for key, raw in parser.items(section):
        if key not in keymap:
            raise ConfigError("[%s] unknown key %r" % (section, key))
        name = keymap[key]
        setattr(obj, name, _coerce(types[name], raw, "[%s] %s" % (section, key)))
    return obj


def _split_list(raw: str) -> List[str]:
    return [x.strip() for x in raw.split(",") if x.strip()]


def _parse_overrides(parser) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    if not parser.has_section("overrides"):
        return out
    for account, raw in parser.items("overrides"):
        values: Dict[str, float] = {}
        for pair in _split_list(raw):
            if "=" not in pair:
                raise ConfigError("[overrides] %s: expected key=value, got %r" % (account, pair))
            key, val = (p.strip() for p in pair.split("=", 1))
            if key not in _OVERRIDABLE:
                raise ConfigError("[overrides] %s: %r is not a sending threshold" % (account, key))
            values[key] = _coerce(float, val, "[overrides] %s %s" % (account, key))
        out[account] = values
    return out


def load_config(path: str, check_permissions: bool = True, require_key_file: bool = True) -> Config:
    if not os.path.isfile(path):
        raise ConfigError("config file not found: %s" % path)
    if check_permissions:
        _check_mode_0600(path, "config file")
    parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";", "#"))
    parser.optionxform = str  # keep account addresses case-sensitive in [overrides]
    try:
        parser.read(path)
    except configparser.Error as exc:
        # A duplicate section or a syntax error is a config error like any other;
        # letting configparser's own exception escape would bypass exit code 1.
        raise ConfigError("%s is not a valid INI file: %s" % (path, exc))
    for section in parser.sections():
        if section not in _SECTIONS and section not in ("recipients", "overrides"):
            raise ConfigError("unknown section [%s]" % section)

    server = _build_section(parser, "server")
    provider = _build_section(parser, "provider")
    recipients = RecipientsCfg()
    if parser.has_section("recipients"):
        for key, raw in parser.items("recipients"):
            if key not in SEVERITIES:
                raise ConfigError("[recipients] unknown severity %r" % key)
            setattr(recipients, key, _split_list(raw))
    cfg = Config(
        server=server,
        provider=provider,
        recipients=recipients,
        brute_force=_build_section(parser, "brute_force"),
        locked_out=_build_section(parser, "locked_out"),
        sending=_build_section(parser, "sending"),
        dedup=_build_section(parser, "dedup"),
        overrides=_parse_overrides(parser),
    )

    if not cfg.server.name:
        raise ConfigError("[server] name is required")
    if cfg.provider.kind not in PROVIDERS:
        raise ConfigError("[provider] kind must be one of %s" % ", ".join(PROVIDERS))
    if not cfg.provider.sender:
        raise ConfigError("[provider] from is required")
    if not any(cfg.recipients.for_severity(s) for s in SEVERITIES):
        raise ConfigError("[recipients] at least one severity needs a recipient")
    if require_key_file:
        if not os.path.isfile(cfg.provider.api_key_file):
            raise ConfigError("api key file not found: %s" % cfg.provider.api_key_file)
        if check_permissions:
            _check_mode_0600(cfg.provider.api_key_file, "api key file")
    return cfg
