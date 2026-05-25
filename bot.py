import io
import os
import re
import ast
import math
import time
import zlib
import uuid
import json
import base64
import struct
import hashlib
import random
import string
import asyncio
import datetime
import textwrap
import itertools
import functools
import discord
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, Counter, OrderedDict
from typing import Optional
from discord.ext import commands, tasks
from discord import app_commands

TOKEN = os.getenv("XEIOA_TOKEN")

# ════════════════════════════════════════════════════════════════
#  ENUMS & CONSTANTS
# ════════════════════════════════════════════════════════════════

class ThreatLevel(Enum):
    CLEAN    = ("CLEAN",    0x00ff99, "✅")
    LOW      = ("LOW",      0xffff00, "🟡")
    MEDIUM   = ("MEDIUM",   0xffaa00, "🟠")
    HIGH     = ("HIGH",     0xff4400, "🔴")
    CRITICAL = ("CRITICAL", 0xff0000, "☠️")

    def __init__(self, label, color, icon):
        self.label = label
        self.color = color
        self.icon  = icon


class Confidence(Enum):
    VERY_HIGH = (97, "VERY HIGH",  "🟢")
    HIGH      = (87, "HIGH",       "🟢")
    MEDIUM    = (70, "MEDIUM",     "🟡")
    LOW       = (50, "LOW",        "🟠")
    VERY_LOW  = (30, "VERY LOW",   "🔴")
    UNKNOWN   = (0,  "UNKNOWN",    "⚫")

    def __init__(self, score, label, icon):
        self.score = score
        self.label = label
        self.icon  = icon


class AnalysisDepth(Enum):
    QUICK    = "quick"
    STANDARD = "standard"
    DEEP     = "deep"
    VM       = "vm"


class InstructionType(Enum):
    MOVE      = "MOVE"
    LOADK     = "LOADK"
    LOADBOOL  = "LOADBOOL"
    LOADNIL   = "LOADNIL"
    GETUPVAL  = "GETUPVAL"
    SETUPVAL  = "SETUPVAL"
    GETGLOBAL = "GETGLOBAL"
    SETGLOBAL = "SETGLOBAL"
    GETTABLE  = "GETTABLE"
    SETTABLE  = "SETTABLE"
    NEWTABLE  = "NEWTABLE"
    ADD       = "ADD"
    SUB       = "SUB"
    MUL       = "MUL"
    DIV       = "DIV"
    MOD       = "MOD"
    POW       = "POW"
    UNM       = "UNM"
    NOT       = "NOT"
    CONCAT    = "CONCAT"
    LEN       = "LEN"
    JMP       = "JMP"
    EQ        = "EQ"
    LT        = "LT"
    LE        = "LE"
    CALL      = "CALL"
    TAILCALL  = "TAILCALL"
    RETURN    = "RETURN"
    FORPREP   = "FORPREP"
    FORLOOP   = "FORLOOP"
    CLOSURE   = "CLOSURE"
    VARARG    = "VARARG"
    UNKNOWN   = "UNKNOWN"


MAX_SCRIPT_SIZE   = 500 * 1024  # 500 KB
RATE_LIMIT_MAX    = 3
RATE_LIMIT_WINDOW = 300         # 5 minutes
JOB_TTL           = 86400       # 24 hours
MAX_BATCH_SIZE    = 20
MAX_VM_DEPTH      = 5
MAX_ENCODE_LAYERS = 12
HISTORY_LIMIT     = 50
INTERACTIVE_TTL   = 1800        # 30 minutes


# ════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ════════════════════════════════════════════════════════════════

@dataclass
class DecodedString:
    original:    str
    decoded:     str
    encode_chain: list[str] = field(default_factory=list)
    purpose:     str = "UNKNOWN"
    locations:   list[int] = field(default_factory=list)
    occurrences: int = 1
    confidence:  Confidence = Confidence.HIGH


@dataclass
class ThreatIndicator:
    category:    str
    description: str
    severity:    ThreatLevel
    line_number: int = -1
    evidence:    str = ""


@dataclass
class VMInstruction:
    index:       int
    opcode:      InstructionType
    operands:    list
    lua_equiv:   str = ""
    confidence:  Confidence = Confidence.HIGH
    raw:         str = ""


@dataclass
class CFGNode:
    state_id:    int
    code:        str
    successors:  list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    is_entry:    bool = False
    is_exit:     bool = False
    loop_header: bool = False


@dataclass
class AnalysisJob:
    job_id:      str
    user_id:     int
    guild_id:    int
    channel_id:  int
    status:      str    # queued | running | done | failed
    depth:       str
    created_at:  float
    completed_at: float = 0.0
    result:      dict = field(default_factory=dict)
    progress:    list[str] = field(default_factory=list)


@dataclass
class UserSettings:
    user_id:         int
    default_depth:   str = "standard"
    output_format:   str = "both"
    auto_threat:     bool = True
    annotate:        bool = True
    verbosity:       str = "normal"  # minimal | normal | verbose
    naming_style:    str = "semantic"  # semantic | generic | preserve


# ════════════════════════════════════════════════════════════════
#  GLOBAL STORAGE
# ════════════════════════════════════════════════════════════════

rate_limit:      dict[int, list[float]]     = defaultdict(list)
warn_data:       dict[int, dict[int, list]] = defaultdict(lambda: defaultdict(list))
snipe_data:      dict[int, discord.Message] = {}
job_storage:     dict[str, AnalysisJob]     = {}
user_history:    dict[int, list[dict]]      = defaultdict(list)
user_settings:   dict[int, UserSettings]    = {}
script_hash_db:  dict[str, dict]            = {}
interactive_sessions: dict[int, dict]       = {}
server_configs:  dict[int, dict]            = {}

_start_time = datetime.datetime.utcnow()
_safe_math  = {k: v for k, v in math.__dict__.items() if not k.startswith("_")}


# ════════════════════════════════════════════════════════════════
#  ROBLOX API DATABASE
# ════════════════════════════════════════════════════════════════

ROBLOX_SERVICES = {
    "Players", "Workspace", "ReplicatedStorage", "ServerStorage",
    "StarterGui", "StarterPack", "StarterPlayer", "Lighting",
    "RunService", "TweenService", "HttpService", "DataStoreService",
    "UserInputService", "ContextActionService", "GuiService",
    "SoundService", "PhysicsService", "PathfindingService",
    "MarketplaceService", "BadgeService", "GroupService",
    "InsertService", "ContentProvider", "CollectionService",
    "MemoryStoreService", "MessagingService", "TextService",
    "LocalizationService", "AssetService", "AvatarEditorService",
    "ChatService", "PolicyService", "VoiceChatService",
    "AnalyticsService", "GamepassService", "PointsService",
    "FriendService", "TeleportService", "ScriptContext",
}

ROBLOX_INSTANCES = {
    "Part", "Model", "Folder", "Script", "LocalScript", "ModuleScript",
    "RemoteEvent", "RemoteFunction", "BindableEvent", "BindableFunction",
    "Frame", "ScreenGui", "TextLabel", "TextButton", "TextBox",
    "ImageLabel", "ImageButton", "ScrollingFrame", "ViewportFrame",
    "Humanoid", "HumanoidRootPart", "Animation", "AnimationController",
    "Sound", "SoundGroup", "NumberValue", "StringValue", "BoolValue",
    "IntValue", "ObjectValue", "Color3Value", "Vector3Value",
    "Tween", "Motor6D", "Weld", "WeldConstraint", "RigidConstraint",
    "BodyVelocity", "BodyPosition", "BodyGyro", "BodyForce",
    "BillboardGui", "SurfaceGui", "SelectionBox", "Highlight",
    "Beam", "Trail", "ParticleEmitter", "Fire", "Smoke", "Sparkles",
    "SpecialMesh", "BlockMesh", "CylinderMesh", "FileMesh",
    "Sky", "Atmosphere", "Clouds", "BloomEffect", "BlurEffect",
    "DepthOfFieldEffect", "ColorCorrectionEffect", "SunRaysEffect",
}

ROBLOX_DEPRECATED = {
    "game.Players.LocalPlayer.Character.Torso": "Use HumanoidRootPart instead",
    "Instance.new('Message')":                  "Use TextLabel instead",
    "game.Workspace":                           "Use workspace directly",
    "wait()":                                   "Use task.wait() instead",
    "spawn()":                                  "Use task.spawn() instead",
    "delay()":                                  "Use task.delay() instead",
}

THREAT_PATTERNS = {
    "Discord Token Grabber": (
        r"Authorization.*Bot\s+[A-Za-z0-9._-]{59}|"
        r"discord\.com/api.*Authorization",
        ThreatLevel.CRITICAL
    ),
    "Webhook Exfiltration": (
        r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        ThreatLevel.HIGH
    ),
    "Remote Code Execution": (
        r"loadstring\s*\(\s*(?:game|workspace|script).*?HttpGet|"
        r"loadstring\s*\(\s*require\s*\(\s*\d{7,}",
        ThreatLevel.CRITICAL
    ),
    "Cookie/Token Theft": (
        r"ROBLOSECURITY|\.ROBLOSECURITY|GetCookies|win32api.*HKEY",
        ThreatLevel.CRITICAL
    ),
    "Backdoor Listener": (
        r"RemoteEvent.*:Connect.*loadstring|"
        r"OnServerEvent.*loadstring",
        ThreatLevel.CRITICAL
    ),
    "HTTP C2 Pattern": (
        r"HttpService.*GetAsync.*while|"
        r"repeat.*HttpGet.*loadstring",
        ThreatLevel.HIGH
    ),
    "Speed Exploit": (
        r"WalkSpeed\s*=\s*(?:[5-9]\d{1,3}|\d{4,})|"
        r"Humanoid\.WalkSpeed\s*=\s*\d{3,}",
        ThreatLevel.MEDIUM
    ),
    "Fly/NoClip Exploit": (
        r"CanCollide\s*=\s*false.*Humanoid|"
        r"\.CFrame\s*=\s*CFrame\.new.*Velocity",
        ThreatLevel.MEDIUM
    ),
    "Anti-Debug": (
        r"debug\.sethook|debug\.getinfo|"
        r"script\.Identity|getfenv\(\)\.print\s*=",
        ThreatLevel.LOW
    ),
    "Infinite Currency": (
        r"leaderstats.*\.Value\s*=\s*math\.huge|"
        r"Currency\s*\+?=\s*\d{6,}",
        ThreatLevel.HIGH
    ),
    "require() Backdoor": (
        r"require\s*\(\s*\d{7,}\s*\)",
        ThreatLevel.HIGH
    ),
    "Script Persistence": (
        r"BindToClose|ScriptContext\.Error|"
        r"game:GetService\(['\"]ScriptContext['\"]",
        ThreatLevel.MEDIUM
    ),
}

OBFUSCATOR_SIGNATURES = {
    "WeAreDevs v1.x": {
        "patterns": [
            r"--\[\[.*wearedevs\.net.*\]\]",
            r"local\s+D\s*=\s*\{(?:\s*\"[^\"]*\"\s*,?\s*){5,}\}",
            r"\\[0-7]{3}\\[0-7]{3}\\[0-7]{3}",
        ],
        "weight": [3, 2, 2],
        "magic_constants": [50410, 130783, 80373],
    },
    "IronBrew2": {
        "patterns": [
            r"local\s+VMInstance\s*=",
            r"bit\.bxor\s*\(",
            r"local\s+Wrap\s*=\s*function",
            r"Deserialize\s*\(",
        ],
        "weight": [3, 2, 2, 3],
        "magic_constants": [],
    },
    "Luraph v10.x": {
        "patterns": [
            r"Luraph|LURAPH",
            r"local\s+[A-Z]{1,3}\s*=\s*\{\};\s*local\s+[A-Z]{1,3}",
            r"getfenv\(\s*\)",
            r"setfenv\s*\(",
        ],
        "weight": [4, 2, 2, 2],
        "magic_constants": [],
    },
    "Moonsec v3": {
        "patterns": [
            r"Moonsec|MOONSEC",
            r"string\.byte.*string\.char",
            r"local\s+[a-z]\s*=\s*\{\s*\[true\]",
        ],
        "weight": [4, 2, 3],
        "magic_constants": [],
    },
    "PSU": {
        "patterns": [
            r"psu\.dev|PSU",
            r"[A-Za-z0-9+/=]{60,}",
            r"local\s+\w+\s*=\s*loadstring",
        ],
        "weight": [4, 1, 3],
        "magic_constants": [],
    },
    "Synapse Xen": {
        "patterns": [
            r"__index\s*=\s*function.*newproxy",
            r"setmetatable.*__newindex",
            r"syn\.|Synapse",
        ],
        "weight": [3, 2, 4],
        "magic_constants": [],
    },
    "Prometheus": {
        "patterns": [
            r"Prometheus|prometheus",
            r"local\s+[A-Z]\s*=\s*\{\};\s*[A-Z]\.__index\s*=\s*[A-Z]",
        ],
        "weight": [4, 3],
        "magic_constants": [],
    },
    "Custom VM": {
        "patterns": [
            r"while\s+\w+\s+do\s+if\s+\w+\s*[<>]=?\s*\d{4,}",
            r"local\s+\w+\s*=\s*\{\s*\[1\]",
            r"for\s+\w+\s*=\s*1\s*,\s*#\w+\s+do",
        ],
        "weight": [3, 2, 1],
        "magic_constants": [],
    },
}


# ════════════════════════════════════════════════════════════════
#  STRING REGISTRY
# ════════════════════════════════════════════════════════════════

class StringRegistry:
    """Global catalogue of every decoded string with full metadata."""

    PURPOSE_RULES = [
        (ROBLOX_SERVICES,  "SERVICE"),
        (ROBLOX_INSTANCES, "INSTANCE_TYPE"),
        ({
            "Heartbeat", "RenderStepped", "Stepped",
            "CharacterAdded", "CharacterRemoving",
            "PlayerAdded", "PlayerRemoving",
            "OnServerEvent", "OnClientEvent",
        }, "EVENT"),
        ({
            "WalkSpeed", "JumpPower", "Health", "MaxHealth",
            "CFrame", "Position", "Velocity", "CanCollide",
        }, "PROPERTY"),
        ({
            "FireServer", "FireClient", "InvokeServer",
            "InvokeClient", "FireAllClients",
            "GetService", "WaitForChild", "FindFirstChild",
            "Clone", "Destroy", "Remove",
        }, "METHOD"),
    ]

    def __init__(self):
        self._registry: dict[str, DecodedString] = {}

    def register(self, ds: DecodedString):
        key = ds.original
        if key in self._registry:
            self._registry[key].occurrences += 1
            return
        ds.purpose = self._infer_purpose(ds.decoded)
        self._registry[key] = ds

    def _infer_purpose(self, decoded: str) -> str:
        for name_set, tag in self.PURPOSE_RULES:
            if decoded in name_set:
                return tag
        if re.match(r"https?://", decoded):
            return "URL"
        if re.match(r"https://discord(?:app)?\.com/api/webhooks/", decoded):
            return "WEBHOOK"
        if re.match(r"[A-Za-z0-9._-]{24}\.[A-Za-z0-9._-]{6}\.[A-Za-z0-9._-]{27}", decoded):
            return "TOKEN"
        if re.search(r"debug|hook|anti|check|verify", decoded, re.I):
            return "ANTI_DEBUG"
        if re.match(r"^\s*$|^[A-Za-z]{1,3}$", decoded):
            return "JUNK"
        return "SCRIPT_LOGIC"

    def all_strings(self) -> list[DecodedString]:
        return list(self._registry.values())

    def by_purpose(self, purpose: str) -> list[DecodedString]:
        return [s for s in self._registry.values() if s.purpose == purpose]


# ════════════════════════════════════════════════════════════════
#  ENCODING DETECTOR  (15+ formats, 12-layer nesting)
# ════════════════════════════════════════════════════════════════

class EncodingDetector:

    @staticmethod
    def detect_and_decode(text: str, layer: int = 0) -> tuple[str, list[str]]:
        if layer >= MAX_ENCODE_LAYERS:
            return text, []
        chain: list[str] = []

        decoders = [
            ("Octal escape",      EncodingDetector._decode_octal),
            ("Hex escape",        EncodingDetector._decode_hex_escape),
            ("Unicode escape",    EncodingDetector._decode_unicode),
            ("Decimal escape",    EncodingDetector._decode_decimal),
            ("Base64",            EncodingDetector._decode_base64),
            ("Base64 URL-safe",   EncodingDetector._decode_base64_url),
            ("Base32",            EncodingDetector._decode_base32),
            ("Hex string",        EncodingDetector._decode_hex_string),
            ("Reverse",           EncodingDetector._decode_reverse),
            ("ROT13",             EncodingDetector._decode_rot13),
            ("Zlib deflate",      EncodingDetector._decode_zlib),
            ("XOR-1byte",         EncodingDetector._decode_xor_1byte),
            ("Run-length",        EncodingDetector._decode_rle),
            ("String.char seq",   EncodingDetector._decode_string_char),
            ("Concat chain",      EncodingDetector._decode_concat_chain),
        ]

        for name, decoder in decoders:
            result = decoder(text)
            if result is not None and result != text:
                chain.append(name)
                # Recurse for nested encoding
                result, sub_chain = EncodingDetector.detect_and_decode(result, layer + 1)
                chain.extend(sub_chain)
                return result, chain

        return text, chain

    # ── Individual Decoders ──────────────────────────────────

    @staticmethod
    def _decode_octal(s: str) -> Optional[str]:
        if not re.search(r"\\[0-7]{1,3}", s):
            return None
        try:
            return re.sub(
                r"\\([0-7]{1,3})",
                lambda m: chr(int(m.group(1), 8)),
                s
            )
        except Exception:
            return None

    @staticmethod
    def _decode_hex_escape(s: str) -> Optional[str]:
        if not re.search(r"\\x[0-9A-Fa-f]{2}", s):
            return None
        try:
            return re.sub(
                r"\\x([0-9A-Fa-f]{2})",
                lambda m: chr(int(m.group(1), 16)),
                s
            )
        except Exception:
            return None

    @staticmethod
    def _decode_unicode(s: str) -> Optional[str]:
        if not re.search(r"\\u[0-9A-Fa-f]{4}", s):
            return None
        try:
            return re.sub(
                r"\\u([0-9A-Fa-f]{4})",
                lambda m: chr(int(m.group(1), 16)),
                s
            )
        except Exception:
            return None

    @staticmethod
    def _decode_decimal(s: str) -> Optional[str]:
        if not re.search(r"\\([0-9]{1,3})", s):
            return None
        try:
            return re.sub(
                r"\\([0-9]{1,3})",
                lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0),
                s
            )
        except Exception:
            return None

    @staticmethod
    def _decode_base64(s: str) -> Optional[str]:
        s = s.strip().strip('"\'')
        if len(s) < 8 or len(s) % 4 != 0:
            return None
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
            return None
        try:
            decoded = base64.b64decode(s).decode("utf-8")
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded):
                return decoded
        except Exception:
            pass
        return None

    @staticmethod
    def _decode_base64_url(s: str) -> Optional[str]:
        s = s.strip().strip('"\'').replace("-", "+").replace("_", "/")
        pad = (4 - len(s) % 4) % 4
        s += "=" * pad
        try:
            decoded = base64.b64decode(s).decode("utf-8")
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded):
                return decoded
        except Exception:
            pass
        return None

    @staticmethod
    def _decode_base32(s: str) -> Optional[str]:
        s = s.strip().strip('"\'').upper()
        if not re.fullmatch(r"[A-Z2-7=]+", s):
            return None
        try:
            return base64.b32decode(s).decode("utf-8")
        except Exception:
            return None

    @staticmethod
    def _decode_hex_string(s: str) -> Optional[str]:
        s = s.strip().strip('"\'')
        if not re.fullmatch(r"[0-9A-Fa-f]+", s) or len(s) < 4 or len(s) % 2 != 0:
            return None
        try:
            return bytes.fromhex(s).decode("utf-8")
        except Exception:
            return None

    @staticmethod
    def _decode_reverse(s: str) -> Optional[str]:
        candidate = s[::-1]
        # Only treat as reverse if it looks more "normal"
        if re.search(r"\b(?:local|function|end|return|if|then)\b", candidate):
            return candidate
        return None

    @staticmethod
    def _decode_rot13(s: str) -> Optional[str]:
        result = s.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
        if result != s and re.search(r"\b(?:local|function|end)\b", result):
            return result
        return None

    @staticmethod
    def _decode_zlib(s: str) -> Optional[str]:
        s_clean = s.strip().strip('"\'')
        # Try treating as hex-encoded zlib
        try:
            raw = bytes.fromhex(s_clean)
            return zlib.decompress(raw).decode("utf-8")
        except Exception:
            pass
        # Try b64-encoded zlib
        try:
            raw = base64.b64decode(s_clean)
            return zlib.decompress(raw).decode("utf-8")
        except Exception:
            pass
        return None

    @staticmethod
    def _decode_xor_1byte(s: str) -> Optional[str]:
        """Try all 255 single-byte XOR keys; accept if result is printable Lua."""
        raw = s.encode("latin-1", errors="replace")
        for key in range(1, 256):
            try:
                candidate = bytes(b ^ key for b in raw).decode("utf-8")
                if (
                    re.search(r"\b(?:local|function|end|return)\b", candidate)
                    and all(32 <= ord(c) < 127 or c in "\n\r\t" for c in candidate)
                ):
                    return candidate
            except Exception:
                continue
        return None

    @staticmethod
    def _decode_rle(s: str) -> Optional[str]:
        """Simple run-length decode: 3a → aaa"""
        if not re.search(r"\d+[A-Za-z]", s):
            return None
        try:
            result = re.sub(r"(\d+)(.)", lambda m: m.group(2) * int(m.group(1)), s)
            if len(result) > len(s):
                return result
        except Exception:
            pass
        return None

    @staticmethod
    def _decode_string_char(s: str) -> Optional[str]:
        if "string.char" not in s:
            return None
        def repl(m):
            try:
                nums = m.group(1).split(",")
                return "".join(chr(int(n.strip())) for n in nums if n.strip().isdigit())
            except Exception:
                return m.group(0)
        result = re.sub(r"string\.char\(([0-9,\s]+)\)", repl, s)
        return result if result != s else None

    @staticmethod
    def _decode_concat_chain(s: str) -> Optional[str]:
        """Resolve 'a' .. 'b' .. 'c' → 'abc'"""
        if ".." not in s:
            return None
        parts = re.findall(r'"([^"]*)"', s)
        if len(parts) >= 2:
            result = "".join(parts)
            return result if result else None
        return None


# ════════════════════════════════════════════════════════════════
#  ARITHMETIC ENGINE
# ════════════════════════════════════════════════════════════════

class ArithmeticEngine:
    """
    Full constant folding, propagation, and
    opaque predicate elimination.
    """

    BITWISE_PATTERNS = {
        r"bit32\.bxor\s*\(([^)]+)\)": lambda a, b: a ^ b,
        r"bit32\.band\s*\(([^)]+)\)": lambda a, b: a & b,
        r"bit32\.bor\s*\(([^)]+)\)":  lambda a, b: a | b,
        r"bit32\.bnot\s*\(([^)]+)\)": lambda a: ~a & 0xFFFFFFFF,
        r"bit32\.lshift\s*\(([^)]+)\)": lambda a, n: (a << n) & 0xFFFFFFFF,
        r"bit32\.rshift\s*\(([^)]+)\)": lambda a, n: a >> n,
    }

    @classmethod
    def fold(cls, code: str) -> str:
        code = cls._fold_numeric_expressions(code)
        code = cls._fold_bitwise(code)
        code = cls._eliminate_opaque_predicates(code)
        code = cls._propagate_constants(code)
        return code

    @classmethod
    def _fold_numeric_expressions(cls, code: str) -> str:
        def try_eval(match):
            expr = match.group(0)
            clean = re.sub(r"\s+", "", expr)
            if re.fullmatch(r"[\d\s\+\-\*\/\%\^\(\)\.]+", clean):
                try:
                    result = eval(expr, {"__builtins__": {}}, _safe_math)  # nosec
                    if isinstance(result, float) and result.is_integer():
                        return str(int(result))
                    return str(round(result, 10))
                except Exception:
                    pass
            return expr

        # Match arithmetic inside assignments and conditions
        code = re.sub(
            r"(?<=[=,(\s])[\-\d][\d\s\+\-\*\/\%\^\(\)\.]{3,}(?=[\s,)\n;])",
            try_eval,
            code
        )
        return code

    @classmethod
    def _fold_bitwise(cls, code: str) -> str:
        for pat, fn in cls.BITWISE_PATTERNS.items():
            def repl(m, _fn=fn):
                args = [a.strip() for a in m.group(1).split(",")]
                try:
                    nums = [int(a, 0) for a in args]
                    result = _fn(*nums)
                    return hex(result) if result > 255 else str(result)
                except Exception:
                    return m.group(0)
            code = re.sub(pat, repl, code)
        return code

    @classmethod
    def _eliminate_opaque_predicates(cls, code: str) -> str:
        # Always-true predicates
        code = re.sub(
            r"if\s+(?:\d+\s*[<>]=?\s*\d+|true)\s+then\s*([\s\S]*?)\s*end\b",
            lambda m: m.group(1),
            code
        )
        # Always-false predicates — remove entire block
        code = re.sub(
            r"if\s+false\s+then[\s\S]*?end\b",
            "-- [DEAD BRANCH ELIMINATED]",
            code
        )
        # Bitwise always-true: bit32.band(x, 0) == 0
        code = re.sub(
            r"if\s+bit32\.band\s*\([^,]+,\s*0\)\s*==\s*0\s+then\s*([\s\S]*?)\s*end\b",
            lambda m: m.group(1),
            code
        )
        return code

    @classmethod
    def _propagate_constants(cls, code: str) -> str:
        """
        Inline single-assignment constants:
        local X = 42  → replace all X with 42
        """
        single_assigns = re.findall(
            r"local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+(?:\.\d+)?)\s*\n",
            code
        )
        for var, val in single_assigns:
            # Count assignments — only inline if assigned once
            assignment_count = len(re.findall(
                rf"\b{re.escape(var)}\s*=", code
            ))
            if assignment_count == 1:
                code = re.sub(rf"\b{re.escape(var)}\b", val, code)
                code = re.sub(
                    rf"local\s+{re.escape(var)}\s*=\s*{re.escape(val)}\s*\n",
                    f"-- [CONSTANT {var}={val} INLINED]\n",
                    code
                )
        return code


# ════════════════════════════════════════════════════════════════
#  CONTROL FLOW GRAPH
# ════════════════════════════════════════════════════════════════

class ControlFlowGraph:
    """Build and flatten a CFG from a state-machine dispatcher."""

    def __init__(self):
        self.nodes: dict[int, CFGNode] = {}
        self.entry: Optional[int]      = None
        self.exits: list[int]          = []
        self.dispatch_var: str         = ""

    def build_from_code(self, code: str) -> bool:
        dispatch_match = re.search(
            r"while\s+(\w+)\s+do\s+if\s+\1\s*[<>]=?\s*(\d+)",
            code, re.DOTALL
        )
        if not dispatch_match:
            return False

        self.dispatch_var = dispatch_match.group(1)

        # Extract all state blocks
        state_pattern = re.compile(
            rf"(?:if|elseif)\s+{re.escape(self.dispatch_var)}\s*==\s*(\d+)\s+then"
            r"\s*([\s\S]*?)(?=(?:elseif|else\s+\w|end\b))"
        )
        for m in state_pattern.finditer(code):
            sid  = int(m.group(1))
            body = m.group(2).strip()
            node = CFGNode(state_id=sid, code=body)

            # Find successor transitions
            trans = re.findall(
                rf"{re.escape(self.dispatch_var)}\s*=\s*(\d+)",
                body
            )
            node.successors = [int(t) for t in trans]
            self.nodes[sid] = node

        if self.nodes:
            self.entry = min(self.nodes.keys())
            # Exits = nodes with no successors or explicit return
            for sid, node in self.nodes.items():
                if not node.successors or "return" in node.code:
                    self.exits.append(sid)
                    node.is_exit = True
            if self.entry in self.nodes:
                self.nodes[self.entry].is_entry = True
            # Build predecessor lists
            for sid, node in self.nodes.items():
                for succ in node.successors:
                    if succ in self.nodes:
                        self.nodes[succ].predecessors.append(sid)
            return True
        return False

    def flatten_to_code(self) -> str:
        """Emit states in topological order."""
        if not self.nodes:
            return ""

        visited:  set[int]  = set()
        ordering: list[int] = []

        def dfs(sid: int):
            if sid in visited or sid not in self.nodes:
                return
            visited.add(sid)
            ordering.append(sid)
            for s in self.nodes[sid].successors:
                dfs(s)

        if self.entry is not None:
            dfs(self.entry)
        # Add any unreachable nodes at the end
        for sid in self.nodes:
            if sid not in visited:
                ordering.append(sid)

        lines = []
        for sid in ordering:
            node = self.nodes[sid]
            lines.append(f"\n-- ── State {sid} {'[ENTRY]' if node.is_entry else ''} {'[EXIT]' if node.is_exit else ''}")
            lines.append(node.code)
        return "\n".join(lines)

    def generate_ascii_flowchart(self) -> str:
        """Produce a compact ASCII flowchart."""
        if not self.nodes or len(self.nodes) > 30:
            return "(flowchart omitted — too many states)"

        lines = ["Control Flow Graph:", ""]
        visited: set[int] = set()

        def render(sid: int, depth: int = 0):
            if sid in visited or sid not in self.nodes:
                return
            visited.add(sid)
            node  = self.nodes[sid]
            prefix = "  " * depth
            label  = f"[{sid}]"
            if node.is_entry:
                label += " ENTRY"
            if node.is_exit:
                label += " EXIT"
            lines.append(f"{prefix}{'└─' if depth else '┌─'} {label}")
            for s in node.successors:
                lines.append(f"{prefix}  │")
                render(s, depth + 1)

        if self.entry is not None:
            render(self.entry)
        return "\n".join(lines)


# ════════════════════════════════════════════════════════════════
#  VM DECOMPILER
# ════════════════════════════════════════════════════════════════

class VMDecompiler:
    """
    Decompiles custom Lua VM implementations back to Lua source.
    Handles: IronBrew2, Luraph, Moonsec, and custom VMs.
    Supports stacked VMs up to MAX_VM_DEPTH deep.
    """

    VM_COMPONENT_PATTERNS = {
        "program_counter":  r"local\s+(\w+)\s*=\s*(?:0|1)\s*--\s*(?:PC|counter|state)",
        "register_file":    r"local\s+(\w+)\s*=\s*\{\}\s*--\s*(?:reg|register)",
        "constant_pool":    r"local\s+(\w+)\s*=\s*\{[\"']",
        "stack_pointer":    r"local\s+(\w+)\s*=\s*0\s*--\s*(?:sp|stack)",
        "dispatcher":       r"while\s+(\w+)\s+do",
    }

    OPCODE_HEURISTICS = [
        # (pattern, InstructionType, lua_template)
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]",
         InstructionType.MOVE,      "{reg}[{a}] = {reg}[{b}]"),
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\d+)\]",
         InstructionType.LOADK,     "{reg}[{a}] = constants[{k}]"),
        (r"(\w+)\[(\w+)\]\s*=\s*nil",
         InstructionType.LOADNIL,   "{reg}[{a}] = nil"),
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\+\s*(\w+)\[(\w+)\]",
         InstructionType.ADD,       "{reg}[{a}] = {reg}[{b}] + {reg}[{c}]"),
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\-\s*(\w+)\[(\w+)\]",
         InstructionType.SUB,       "{reg}[{a}] = {reg}[{b}] - {reg}[{c}]"),
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\*\s*(\w+)\[(\w+)\]",
         InstructionType.MUL,       "{reg}[{a}] = {reg}[{b}] * {reg}[{c}]"),
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\/\s*(\w+)\[(\w+)\]",
         InstructionType.DIV,       "{reg}[{a}] = {reg}[{b}] / {reg}[{c}]"),
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\.\.\s*(\w+)\[(\w+)\]",
         InstructionType.CONCAT,    "{reg}[{a}] = {reg}[{b}] .. {reg}[{c}]"),
        (r"game:GetService\s*\(",
         InstructionType.GETGLOBAL, 'game:GetService(...)'),
        (r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\[(\w+)\[(\w+)\]\]",
         InstructionType.GETTABLE,  "{reg}[{a}] = {reg}[{b}][{reg}[{c}]]"),
        (r"(\w+)\[(\w+)\]\[(\w+)\[(\w+)\]\]\s*=\s*(\w+)\[(\w+)\]",
         InstructionType.SETTABLE,  "{reg}[{b}][{reg}[{c}]] = {reg}[{a}]"),
        (r"return\s+(\w+)\[",
         InstructionType.RETURN,    "return {reg}[...]"),
        (r"(\w+)\s*=\s*(\w+)\s*\+\s*1\s*$",
         InstructionType.FORLOOP,   "-- for loop increment"),
        (r"for\s+\w+\s*=",
         InstructionType.FORPREP,   "-- for loop prepare"),
    ]

    def __init__(self, code: str, depth: int = 0):
        self.code  = code
        self.depth = depth
        self.instructions: list[VMInstruction] = []
        self.constants:    list[str]           = []
        self.register_var: str = "reg"
        self.vm_detected:  bool = False
        self.confidence_summary: dict[str, int] = {
            "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }

    def analyze(self) -> dict:
        self.vm_detected = self._detect_vm()
        if not self.vm_detected:
            return {"detected": False}

        self._extract_constants()
        self._identify_instructions()
        self._compute_confidence_summary()

        decompiled = self._decompile_instructions()

        # Recurse for stacked VMs
        nested = None
        if self.depth < MAX_VM_DEPTH:
            inner = VMDecompiler(decompiled, self.depth + 1)
            inner_result = inner.analyze()
            if inner_result.get("detected"):
                nested = inner_result

        return {
            "detected":           True,
            "depth":              self.depth,
            "constants":          self.constants,
            "instructions":       self.instructions,
            "decompiled":         decompiled,
            "confidence_summary": self.confidence_summary,
            "nested_vm":          nested,
        }

    def _detect_vm(self) -> bool:
        indicators = [
            bool(re.search(r"while\s+\w+\s+do\s+if\s+\w+", self.code, re.DOTALL)),
            bool(re.search(r"local\s+\w+\s*=\s*\{\}\s*\n", self.code)),
            bool(re.search(r"for\s+\w+\s*=\s*1\s*,\s*#\w+", self.code)),
        ]
        return sum(indicators) >= 2

    def _extract_constants(self):
        # Pull all string literals as potential constants
        self.constants = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', self.code)

    def _identify_instructions(self):
        lines = self.code.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("--"):
                continue
            matched = False
            for pat, itype, template in self.OPCODE_HEURISTICS:
                if re.search(pat, stripped):
                    conf = Confidence.HIGH if itype != InstructionType.UNKNOWN else Confidence.LOW
                    self.instructions.append(VMInstruction(
                        index=i,
                        opcode=itype,
                        operands=[],
                        lua_equiv=template,
                        confidence=conf,
                        raw=stripped
                    ))
                    matched = True
                    break
            if not matched and stripped:
                self.instructions.append(VMInstruction(
                    index=i,
                    opcode=InstructionType.UNKNOWN,
                    operands=[],
                    lua_equiv="-- [UNRESOLVED VM INSTRUCTION]",
                    confidence=Confidence.VERY_LOW,
                    raw=stripped
                ))

    def _compute_confidence_summary(self):
        for inst in self.instructions:
            if inst.confidence in (Confidence.HIGH, Confidence.VERY_HIGH):
                self.confidence_summary["HIGH"] += 1
            elif inst.confidence == Confidence.MEDIUM:
                self.confidence_summary["MEDIUM"] += 1
            else:
                self.confidence_summary["LOW"] += 1

    def _decompile_instructions(self) -> str:
        lines = ["-- [VM DECOMPILED OUTPUT]"]
        for inst in self.instructions:
            conf_tag = f"-- [{inst.confidence.label} CONFIDENCE]"
            if inst.opcode == InstructionType.UNKNOWN:
                lines.append(f"-- [UNRESOLVED: {inst.raw}]")
            else:
                lines.append(f"{inst.lua_equiv}  {conf_tag}")
        return "\n".join(lines)


# ════════════════════════════════════════════════════════════════
#  SEMANTIC ANALYZER
# ════════════════════════════════════════════════════════════════

class SemanticAnalyzer:
    """
    Infers variable/function names, Roblox API usage,
    and script intent from recovered code.
    """

    PARAMETER_HINTS = {
        r"Players.*:Connect\s*\(function\s*\((\w+)":   ("player",),
        r"OnServerEvent:Connect\s*\(function\s*\((\w+),\s*(\w+)": ("player", "data"),
        r"Heartbeat:Connect\s*\(function\s*\((\w+)":   ("deltaTime",),
        r"CharacterAdded:Connect\s*\(function\s*\((\w+)": ("character",),
        r"function\s+\w+\s*\((\w+),\s*(\w+)":          ("player", "value"),
    }

    def __init__(self, code: str, string_registry: StringRegistry):
        self.code     = code
        self.registry = string_registry
        self.var_map:  dict[str, str] = {}
        self.api_calls: list[dict]   = []
        self._counter: int = 0

    def analyze(self) -> str:
        self._resolve_roblox_apis()
        self._infer_variable_names()
        self._apply_parameter_hints()
        self._annotate_deprecated()
        self._add_section_headers()
        return self.code

    def _resolve_roblox_apis(self):
        # Annotate GetService calls
        def annotate_service(m):
            svc = m.group(1)
            tag = "[SERVICE]" if svc in ROBLOX_SERVICES else "[UNKNOWN SERVICE]"
            self.api_calls.append({"call": f"GetService({svc})", "purpose": tag})
            return m.group(0)

        self.code = re.sub(
            r'game:GetService\("([^"]+)"\)',
            annotate_service,
            self.code
        )

        # Annotate Instance.new
        def annotate_instance(m):
            inst = m.group(1)
            tag  = "[INSTANCE_TYPE]" if inst in ROBLOX_INSTANCES else "[UNKNOWN INSTANCE]"
            self.api_calls.append({"call": f"Instance.new({inst})", "purpose": tag})
            return m.group(0)

        self.code = re.sub(
            r'Instance\.new\("([^"]+)"\)',
            annotate_instance,
            self.code
        )

    def _infer_variable_names(self):
        """Context-aware renaming of obfuscated single-letter variables."""
        TYPE_HINTS = {
            r'game:GetService\("Players"\)':         "playersService",
            r'game:GetService\("RunService"\)':       "runService",
            r'game:GetService\("TweenService"\)':     "tweenService",
            r'game:GetService\("HttpService"\)':      "httpService",
            r'game:GetService\("DataStoreService"\)': "dataStoreService",
            r'game:GetService\("ReplicatedStorage"\)':"replicatedStorage",
            r'\.LocalPlayer\b':                       "localPlayer",
            r'\.Character\b':                         "character",
            r':WaitForChild\("Humanoid"\)':           "humanoid",
            r':WaitForChild\("HumanoidRootPart"\)':   "rootPart",
            r'Instance\.new\("RemoteEvent"\)':        "remoteEvent",
            r'Instance\.new\("RemoteFunction"\)':     "remoteFunction",
            r'Instance\.new\("ScreenGui"\)':          "screenGui",
        }

        # Find single-letter local variable assignments
        assigns = re.findall(
            r"local\s+([A-Z_]{1,2})\s*=\s*(.*?)(?:\n|$)",
            self.code
        )
        for var, rhs in assigns:
            if var in self.var_map:
                continue
            for pattern, suggested_name in TYPE_HINTS.items():
                if re.search(pattern, rhs):
                    self.var_map[var] = suggested_name
                    break
            else:
                # Infer from value type
                if re.match(r"\d+(?:\.\d+)?$", rhs.strip()):
                    self.var_map[var] = f"num_{self._next_id()}"
                elif re.match(r'"', rhs.strip()):
                    self.var_map[var] = f"str_{self._next_id()}"
                elif "function" in rhs:
                    self.var_map[var] = f"fn_{self._next_id()}"
                elif re.match(r"\{", rhs.strip()):
                    self.var_map[var] = f"tbl_{self._next_id()}"
                elif re.match(r"true|false", rhs.strip()):
                    self.var_map[var] = f"flag_{self._next_id()}"
                else:
                    self.var_map[var] = f"inst_{self._next_id()}"

        # Apply renames (longest var names first to avoid partial matches)
        for old, new in sorted(self.var_map.items(), key=lambda x: -len(x[0])):
            self.code = re.sub(rf"\b{re.escape(old)}\b", new, self.code)

    def _apply_parameter_hints(self):
        for pattern, names in self.PARAMETER_HINTS.items():
            matches = list(re.finditer(pattern, self.code))
            for m in matches:
                for i, name in enumerate(names, start=1):
                    try:
                        param = m.group(i + 1) if m.lastindex and m.lastindex >= i + 1 else None
                        if param and len(param) <= 3:
                            self.code = re.sub(
                                rf"\b{re.escape(param)}\b",
                                name,
                                self.code
                            )
                    except IndexError:
                        pass

    def _annotate_deprecated(self):
        for deprecated, suggestion in ROBLOX_DEPRECATED.items():
            if deprecated in self.code:
                self.code = self.code.replace(
                    deprecated,
                    f"{deprecated} --[[ DEPRECATED: {suggestion} ]]"
                )

    def _add_section_headers(self):
        sections = [
            (r"game:GetService\(",          "-- ── Services"),
            (r"LocalPlayer",                "-- ── Player References"),
            (r"RemoteEvent|RemoteFunction", "-- ── Networking"),
            (r"DataStore",                  "-- ── Data Management"),
            (r"Heartbeat|RenderStepped",    "-- ── Game Loop"),
            (r"ScreenGui|Frame|TextLabel",  "-- ── UI"),
        ]
        added: set[str] = set()
        lines   = self.code.splitlines()
        result  = []
        for line in lines:
            for pattern, header in sections:
                if header not in added and re.search(pattern, line):
                    result.append(f"\n{header} {'─' * (50 - len(header))}")
                    added.add(header)
                    break
            result.append(line)
        self.code = "\n".join(result)

    def _next_id(self) -> str:
        self._counter += 1
        return str(self._counter)


# ════════════════════════════════════════════════════════════════
#  THREAT SCANNER
# ════════════════════════════════════════════════════════════════

class ThreatScanner:

    def scan(self, code: str) -> tuple[ThreatLevel, list[ThreatIndicator]]:
        indicators: list[ThreatIndicator] = []
        lines = code.splitlines()

        for category, (pattern, base_level) in THREAT_PATTERNS.items():
            for i, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    indicators.append(ThreatIndicator(
                        category=category,
                        description=f"Pattern matched at line {i}",
                        severity=base_level,
                        line_number=i,
                        evidence=line.strip()[:120]
                    ))

        if not indicators:
            return ThreatLevel.CLEAN, []

        max_level = max(indicators, key=lambda x: list(ThreatLevel).index(x.severity))
        return max_level.severity, indicators

    def redact(self, code: str) -> str:
        # Discord tokens
        code = re.sub(
            r"[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
            "[DISCORD TOKEN REDACTED]", code
        )
        # Webhook URLs
        code = re.sub(
            r"https://discord(?:app)?\.com/api/webhooks/[^\s\"']+",
            "[WEBHOOK REDACTED]", code
        )
        # Roblosecurity
        code = re.sub(
            r"_\|WARNING:-DO-NOT-SHARE-THIS[^\"']+",
            "[ROBLOSECURITY REDACTED]", code
        )
        return code


# ════════════════════════════════════════════════════════════════
#  MASTER DEOBFUSCATION ENGINE  (9-pass pipeline)
# ════════════════════════════════════════════════════════════════

class MasterDeobfuscator:

    def __init__(self, code: str, depth: AnalysisDepth = AnalysisDepth.STANDARD,
                 annotate: bool = True, threat_scan: bool = True):
        self.original      = code
        self.code          = code
        self.depth         = depth
        self.annotate      = annotate
        self.do_threat     = threat_scan

        self.registry      = StringRegistry()
        self.arithmetic    = ArithmeticEngine()
        self.cfg           = ControlFlowGraph()
        self.vm            = VMDecompiler(code)
        self.threat        = ThreatScanner()

        self.obfuscator    = "Unknown"
        self.confidence    = Confidence.UNKNOWN
        self.complexity    = "Light"
        self.layers:       list[str]              = []
        self.warnings:     list[str]              = []
        self.notes:        list[str]              = []
        self.progress:     list[str]              = []
        self.threat_level: ThreatLevel            = ThreatLevel.CLEAN
        self.indicators:   list[ThreatIndicator]  = []
        self.vm_result:    dict                   = {}
        self.cfg_built:    bool                   = False
        self.flowchart:    str                    = ""
        self.api_calls:    list[dict]             = []
        self.overall_conf: float                  = 0.0
        self.deobf_time:   float                  = 0.0

    # ── Entry Point ──────────────────────────────────────────
    def run(self) -> dict:
        start = time.time()

        self._pass1_structural_analysis()
        self._pass2_string_decoding()
        self._pass3_constant_folding()
        self._pass4_dead_code_elimination()
        self._pass5_control_flow_recovery()

        if self.depth in (AnalysisDepth.VM, AnalysisDepth.DEEP):
            self._pass6_vm_decompilation()

        self._pass7_semantic_enrichment()
        self._pass8_verification()
        self._pass9_formatting()

        if self.do_threat:
            self.threat_level, self.indicators = self.threat.scan(self.code)
            self.code = self.threat.redact(self.code)

        self.deobf_time  = round(time.time() - start, 2)
        self.overall_conf = self._compute_overall_confidence()

        return self._build_result()

    # ── Pass 1 — Structural Analysis ────────────────────────
    def _pass1_structural_analysis(self):
        self._log("✅ Pass 1: Structural analysis")
        self._detect_obfuscator()
        self._assess_complexity()

    def _detect_obfuscator(self):
        best_name  = "Unknown"
        best_score = 0

        for name, sig in OBFUSCATOR_SIGNATURES.items():
            patterns = sig["patterns"]
            weights  = sig.get("weight", [1] * len(patterns))
            score    = 0
            for pat, w in zip(patterns, weights):
                if re.search(pat, self.original, re.IGNORECASE | re.DOTALL):
                    score += w
            # Check magic constants
            for const in sig.get("magic_constants", []):
                if str(const) in self.original:
                    score += 2
            if score > best_score:
                best_score = score
                best_name  = name

        self.obfuscator = best_name
        total_max = sum(
            sum(OBFUSCATOR_SIGNATURES.get(best_name, {}).get("weight", [1]))
        )
        ratio = best_score / max(total_max, 1)

        if   ratio >= 0.85: self.confidence = Confidence.VERY_HIGH
        elif ratio >= 0.65: self.confidence = Confidence.HIGH
        elif ratio >= 0.45: self.confidence = Confidence.MEDIUM
        elif ratio >= 0.25: self.confidence = Confidence.LOW
        else:               self.confidence = Confidence.VERY_LOW

    def _assess_complexity(self):
        c = self.original
        layer_map = {
            "Octal encoding":          bool(re.search(r"\\[0-7]{3}", c)),
            "Hex encoding":            bool(re.search(r"\\x[0-9A-Fa-f]{2}", c)),
            "Base64 encoding":         bool(re.search(r"[A-Za-z0-9+/]{40,}={0,2}", c)),
            "XOR encryption":          bool(re.search(r"bit\.bxor|bxor\(", c)),
            "Control flow flattening": bool(re.search(r"if\s+\w+\s*<\s*\d{5,}", c)),
            "VM-based execution":      bool(re.search(r"while\s+\w+\s+do.*if\s+\w+\s*<", c, re.DOTALL)),
            "String table":            bool(re.search(r"local\s+D\s*=\s*\{", c)),
            "Table permutation":       bool(re.search(r"D\[I\]\s*,\s*D\[l\]\s*=", c)),
            "Self-exec function":      bool(re.search(r"\(function\s*\(", c)),
            "Zlib compression":        bool(re.search(r"zlib|decompress", c, re.I)),
            "Multi-layer encoding":    bool(re.search(r"loadstring\s*\(.*loadstring", c, re.DOTALL)),
        }
        self.layers = [name for name, present in layer_map.items() if present]
        n = len(self.layers)
        if "VM-based execution" in self.layers:
            self.complexity = "VM-Based"
        elif n >= 4: self.complexity = "Heavy"
        elif n >= 2: self.complexity = "Medium"
        else:        self.complexity = "Light"

    # ── Pass 2 — String Decoding ────────────────────────────
    def _pass2_string_decoding(self):
        self._log("✅ Pass 2: String decoding")

        # Decode the primary WeAreDevs string table D
        self._decode_wad_string_table()

        # Scan all string literals in code
        string_pattern = re.compile(r'"((?:[^"\\]|\\.){4,})"')
        seen: set[str] = set()

        for m in string_pattern.finditer(self.code):
            raw = m.group(1)
            if raw in seen:
                continue
            seen.add(raw)
            decoded, chain = EncodingDetector.detect_and_decode(raw)
            if decoded != raw and chain:
                ds = DecodedString(
                    original=raw,
                    decoded=decoded,
                    encode_chain=chain
                )
                self.registry.register(ds)
                self.code = self.code.replace(f'"{raw}"', f'"{decoded}"')

        self._log(
            f"✅ Strings decoded ({len(self.registry.all_strings())} entries)"
        )

    def _decode_wad_string_table(self):
        """WeAreDevs-specific string table D with permutation loop."""
        tbl_match = re.search(
            r"local\s+D\s*=\s*\{([\s\S]*?)\}",
            self.code
        )
        if not tbl_match:
            return

        raw     = tbl_match.group(1)
        entries = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
        if not entries:
            return

        # Decode each entry
        decoded_entries = []
        for entry in entries:
            decoded, chain = EncodingDetector.detect_and_decode(entry)
            decoded_entries.append(decoded)
            if chain:
                ds = DecodedString(
                    original=entry, decoded=decoded, encode_chain=chain
                )
                self.registry.register(ds)

        # Apply permutation swaps
        pair_matches = re.findall(r"\{(\d+),\s*(\d+)\}", self.code)
        for a_str, b_str in pair_matches:
            a, b = int(a_str) - 1, int(b_str) - 1
            if 0 <= a < len(decoded_entries) and 0 <= b < len(decoded_entries):
                decoded_entries[a], decoded_entries[b] = decoded_entries[b], decoded_entries[a]

        # Replace D[n] references
        for i, val in enumerate(decoded_entries, start=1):
            self.code = re.sub(rf"\bD\[{i}\]", f'"{val}"', self.code)

        self.notes.append(
            f"WeAreDevs string table D resolved: {len(decoded_entries)} strings"
        )

    # ── Pass 3 — Constant Folding ───────────────────────────
    def _pass3_constant_folding(self):
        self._log("✅ Pass 3: Constant folding & propagation")
        self.code = ArithmeticEngine.fold(self.code)

    # ── Pass 4 — Dead Code Elimination ─────────────────────
    def _pass4_dead_code_elimination(self):
        self._log("✅ Pass 4: Dead code elimination")
        self.code = re.sub(r"if\s+true\s+then\s*([\s\S]*?)\s*end\b",  r"\1", self.code)
        self.code = re.sub(r"if\s+false\s+then[\s\S]*?end\b", "-- [DEAD BRANCH REMOVED]", self.code)
        self.code = re.sub(r";{2,}", ";", self.code)
        self.code = re.sub(r"[ \t]+\n", "\n", self.code)
        self.code = re.sub(r"\n{4,}", "\n\n\n", self.code)

        # Remove write-only variables (assigned but never read)
        assignments = re.findall(r"local\s+(\w+)\s*=", self.code)
        for var in set(assignments):
            reads = len(re.findall(rf"(?<!local\s)\b{re.escape(var)}\b", self.code))
            writes = len(re.findall(rf"\blocal\s+{re.escape(var)}\b", self.code))
            if reads <= writes:  # Never actually read
                self.code = re.sub(
                    rf"local\s+{re.escape(var)}\s*=\s*[^\n]+\n",
                    f"-- [JUNK VAR {var} REMOVED]\n",
                    self.code
                )

    # ── Pass 5 — Control Flow Recovery ─────────────────────
    def _pass5_control_flow_recovery(self):
        self._log("✅ Pass 5: Control flow reconstruction")

        if self.cfg.build_from_code(self.code):
            self.cfg_built = True
            flat = self.cfg.flatten_to_code()
            self.flowchart = self.cfg.generate_ascii_flowchart()

            # Replace the state machine with flattened code
            sm_match = re.search(
                r"while\s+\w+\s+do[\s\S]*?end\b",
                self.code
            )
            if sm_match:
                self.code = (
                    self.code[:sm_match.start()]
                    + "-- [STATE MACHINE FLATTENED]\n"
                    + flat
                    + self.code[sm_match.end():]
                )
            self.notes.append(
                f"CFG built: {len(self.cfg.nodes)} states, "
                f"entry={self.cfg.entry}, "
                f"exits={self.cfg.exits}"
            )

        # Inline self-executing wrappers
        self.code = re.sub(
            r"\(function\s*\(\.\.\.\)\s*([\s\S]*?)\s*end\)\(\.\.\.\)",
            r"-- [SELF-EXEC UNWRAPPED]\n\1",
            self.code
        )
        # Inline trivial wrappers
        self.code = re.sub(
            r"local\s+(\w+)\s*=\s*function\s*\(([^)]*)\)\s*return\s+(\w+)\(([^)]*)\)\s*end",
            lambda m: (
                f"-- [WRAPPER {m.group(1)} → {m.group(3)} INLINED]"
                if m.group(2).strip() == m.group(4).strip()
                else m.group(0)
            ),
            self.code
        )
        # Remove anti-debug patterns
        anti_debug = [
            (r"debug\.sethook\([^)]+\)",                "-- [DEBUG HOOK REMOVED]"),
            (r"debug\.getinfo\([^)]+\)",                "-- [DEBUG INFO REMOVED]"),
            (r"while\s+true\s+do\s+error\([^)]+\)\s+end", "-- [ANTI-DEBUG LOOP REMOVED]"),
            (r"if\s+type\(game\)\s*~=\s*\"[^\"]+\"\s+then[\s\S]*?end", "-- [ENV CHECK REMOVED]"),
        ]
        for pat, repl in anti_debug:
            self.code = re.sub(pat, repl, self.code, flags=re.DOTALL)

    # ── Pass 6 — VM Decompilation ───────────────────────────
    def _pass6_vm_decompilation(self):
        self._log("✅ Pass 6: VM decompilation")
        vm = VMDecompiler(self.code)
        self.vm_result = vm.analyze()
        if self.vm_result.get("detected"):
            self.code = (
                "-- [VM DECOMPILED — SEE BELOW]\n"
                + self.vm_result.get("decompiled", "")
                + "\n\n-- [ORIGINAL VM CODE FOLLOWS]\n"
                + self.code
            )
            hi  = self.vm_result["confidence_summary"]["HIGH"]
            med = self.vm_result["confidence_summary"]["MEDIUM"]
            lo  = self.vm_result["confidence_summary"]["LOW"]
            self.notes.append(
                f"VM decompiled: {hi} high / {med} medium / {lo} low confidence instructions"
            )
            if self.vm_result.get("nested_vm"):
                self.notes.append("⚠️ Nested/stacked VM detected and recursively decompiled.")

    # ── Pass 7 — Semantic Enrichment ────────────────────────
    def _pass7_semantic_enrichment(self):
        self._log("✅ Pass 7: Semantic analysis & renaming")
        analyzer    = SemanticAnalyzer(self.code, self.registry)
        self.code   = analyzer.analyze()
        self.api_calls = analyzer.api_calls

    # ── Pass 8 — Verification ───────────────────────────────
    def _pass8_verification(self):
        self._log("✅ Pass 8: Verification")
        issues = self._verify_lua_syntax()
        if issues:
            for issue in issues:
                self.notes.append(f"⚠️ Verification: {issue}")

    def _verify_lua_syntax(self) -> list[str]:
        issues = []
        # Balance check for 'function'/'end'
        opens  = len(re.findall(r"\bfunction\b", self.code))
        closes = len(re.findall(r"\bend\b", self.code))
        if abs(opens - closes) > 2:
            issues.append(
                f"Possible unbalanced function/end ({opens} function vs {closes} end)"
            )
        # Unresolved state machine references
        if re.search(r"\bD\[\d+\]", self.code):
            issues.append("Some string table references (D[N]) remain unresolved.")
        # Undefined variables check (very basic)
        used = set(re.findall(r"\b([A-Z]{1,2})\b", self.code))
        for v in used:
            if not re.search(rf"\blocal\s+{re.escape(v)}\b", self.code):
                issues.append(f"Possible undefined variable: {v}")
        return issues[:5]  # Limit to 5 issues

    # ── Pass 9 — Formatting ─────────────────────────────────
    def _pass9_formatting(self):
        self._log("✅ Pass 9: Formatting & documentation")
        self.code = self._indent_code(self.code)
        self.code = self._build_header() + "\n\n" + self.code

    def _indent_code(self, code: str) -> str:
        indent = 0
        lines  = []
        openers = {"function", "do", "repeat", "else", "elseif"}
        closers = {"end", "until", "else", "elseif"}

        for line in code.splitlines():
            s = line.strip()
            if not s:
                lines.append("")
                continue
            first = s.split()[0] if s.split() else ""
            if first in closers:
                indent = max(0, indent - 1)
            lines.append("    " * indent + s)
            if (
                first in openers
                or s.endswith(" do")
                or s.endswith(" then")
                or re.match(r"^(?:local\s+)?function\b", s)
            ):
                indent += 1

        return "\n".join(lines)

    def _build_header(self) -> str:
        all_strings  = self.registry.all_strings()
        service_list = ", ".join(
            ds.decoded for ds in self.registry.by_purpose("SERVICE")
        ) or "None detected"
        api_list = ", ".join(
            set(c["call"] for c in self.api_calls[:8])
        ) or "None detected"

        return textwrap.dedent(f"""\
            --[[
                ═══════════════════════════════════════════════════════
                DEOBFUSCATED SCRIPT — XEIOA BOT (MAX LEVEL ENGINE)
                ═══════════════════════════════════════════════════════
                Obfuscator      : {self.obfuscator}
                Confidence      : {self.confidence.icon} {self.confidence.label}
                Complexity      : {self.complexity}
                Analysis Depth  : {self.depth.value} (9-pass pipeline)
                Deobf Time      : {self.deobf_time}s
                Overall Conf    : {self.overall_conf:.1f}%
                Threat Level    : {self.threat_level.icon} {self.threat_level.label}
                Layers          : {', '.join(self.layers) or 'None'}
                Strings Decoded : {len(all_strings)}
                ═══════════════════════════════════════════════════════

                SCRIPT SUMMARY:
                {self._summarize_flow()}

                ROBLOX SERVICES USED:
                {service_list}

                API CALLS DETECTED:
                {api_list}
                ═══════════════════════════════════════════════════════
            --]]""")

    # ── Helpers ──────────────────────────────────────────────
    def _summarize_flow(self) -> str:
        c = self.code
        findings = []
        checks = [
            (r'GetService\("Players"\)',       "• Accesses Players service"),
            (r'GetService\("HttpService"\)',   "• Uses HttpService (HTTP requests)"),
            (r'LocalPlayer',                   "• Targets LocalPlayer"),
            (r'RemoteEvent|RemoteFunction',    "• Uses Remote Events/Functions"),
            (r'DataStore',                     "• Accesses DataStore"),
            (r'loadstring',                    "• Executes dynamic code ⚠️"),
            (r'WalkSpeed',                     "• Modifies movement speed"),
            (r'TweenService',                  "• Uses animations/tweens"),
            (r'BindableEvent',                 "• Uses BindableEvents"),
            (r'HttpGet|PostAsync',             "• Makes HTTP requests"),
            (r'require\s*\(\s*\d{7,}',        "• Requires external ModuleScript ⚠️"),
        ]
        for pat, desc in checks:
            if re.search(pat, c):
                findings.append(desc)
        return "\n                ".join(findings) if findings else "• Intent unclear from static analysis"

    def _compute_overall_confidence(self) -> float:
        base = self.confidence.score
        # Boost for successful string decoding
        if self.registry.all_strings():
            base = min(100, base + 5)
        # Penalty for unresolved sections
        unresolved = len(re.findall(r"\[UNRESOLVED\]|\[UNCERTAIN", self.code))
        base = max(0, base - unresolved * 2)
        # VM penalty
        if self.vm_result.get("detected"):
            lo_pct = (
                self.vm_result["confidence_summary"]["LOW"]
                / max(1, len(self.vm_result.get("instructions", [1])))
            )
            base = max(0, base - int(lo_pct * 20))
        return float(min(99.9, base))

    def _log(self, msg: str):
        self.progress.append(msg)

    def _build_result(self) -> dict:
        return {
            "obfuscator":       self.obfuscator,
            "confidence":       self.confidence,
            "complexity":       self.complexity,
            "layers":           self.layers,
            "decoded_strings":  self.registry.all_strings(),
            "clean_code":       self.code,
            "warnings":         self.warnings,
            "notes":            self.notes,
            "flow_summary":     self._summarize_flow(),
            "threat_level":     self.threat_level,
            "indicators":       self.indicators,
            "vm_result":        self.vm_result,
            "cfg_built":        self.cfg_built,
            "flowchart":        self.flowchart,
            "api_calls":        self.api_calls,
            "overall_conf":     self.overall_conf,
            "deobf_time":       self.deobf_time,
            "progress":         self.progress,
        }


# ════════════════════════════════════════════════════════════════
#  BOT CLASS
# ════════════════════════════════════════════════════════════════

class XeioaBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds           = True
        intents.members          = True
        super().__init__(command_prefix="!", intents=intents, help_command=None)

    async def setup_hook(self):
        try:
            synced = await self.tree.sync()
            print(f"✅ Synced {len(synced)} slash commands")
            self._cleanup_jobs.start()
        except Exception as e:
            print(f"❌ Sync failed: {e}")

    async def on_ready(self):
        print(f"✅ {self.user} online")
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="Lua scripts 🔍"
            )
        )

    async def on_message_delete(self, message: discord.Message):
        if not message.author.bot:
            snipe_data[message.channel.id] = message

    async def read_attachment(self, att: discord.Attachment) -> Optional[str]:
        if not any(att.filename.endswith(e) for e in (".lua", ".luau", ".txt")):
            return None
        if att.size > MAX_SCRIPT_SIZE:
            return None
        try:
            data = await att.read()
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None

    async def animated_status(self, msg, text: str):
        for _ in range(2):
            for stage in [text, f"{text}.", f"{text}. .", f"{text}. . ."]:
                try:
                    await msg.edit(
                        content=f"```ansi\n\u001b[1;32m{stage}\u001b[0m\n```"
                    )
                    await asyncio.sleep(0.3)
                except Exception:
                    pass

    @tasks.loop(hours=1)
    async def _cleanup_jobs(self):
        now = time.time()
        expired = [jid for jid, j in job_storage.items()
                   if now - j.created_at > JOB_TTL]
        for jid in expired:
            del job_storage[jid]


bot = XeioaBot()


# ════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════

def get_settings(user_id: int) -> UserSettings:
    if user_id not in user_settings:
        user_settings[user_id] = UserSettings(user_id=user_id)
    return user_settings[user_id]


def check_rate_limit(user_id: int) -> tuple[bool, int]:
    now  = time.time()
    rate_limit[user_id] = [t for t in rate_limit[user_id]
                           if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit[user_id]) >= RATE_LIMIT_MAX:
        wait = int(RATE_LIMIT_WINDOW - (now - rate_limit[user_id][0]))
        return False, wait
    rate_limit[user_id].append(now)
    return True, 0


def perm(interaction: discord.Interaction, p: str) -> bool:
    return getattr(interaction.user.guild_permissions, p, False)


def make_embed(title: str, desc: str = "", color: int = 0x00ff99) -> discord.Embed:
    e = discord.Embed(title=title, description=desc, color=color)
    e.set_footer(text="Xeioa Max-Level Deobfuscator")
    e.timestamp = datetime.datetime.utcnow()
    return e


def build_detection_embed(result: dict) -> discord.Embed:
    conf:  Confidence  = result["confidence"]
    threat: ThreatLevel = result["threat_level"]
    color = threat.color

    e = discord.Embed(
        title="🔍 Deobfuscation Analysis",
        color=color
    )
    e.add_field(name="Obfuscator",       value=f"`{result['obfuscator']}`",    inline=True)
    e.add_field(name="Confidence",       value=f"{conf.icon} {conf.label}",    inline=True)
    e.add_field(name="Complexity",       value=f"`{result['complexity']}`",    inline=True)
    e.add_field(name="Overall Conf.",    value=f"`{result['overall_conf']:.1f}%`", inline=True)
    e.add_field(name="Analysis Time",    value=f"`{result['deobf_time']}s`",   inline=True)
    e.add_field(
        name=f"Threat {threat.icon}",
        value=f"`{threat.label}`",
        inline=True
    )
    layers = "\n".join(f"• {l}" for l in result["layers"]) or "None detected"
    e.add_field(name="Layers Detected", value=layers, inline=False)
    e.set_footer(text="Xeioa Max-Level Deobfuscator")
    e.timestamp = datetime.datetime.utcnow()
    return e


def build_strings_embed(strings: list[DecodedString]) -> discord.Embed:
    e = make_embed(
        f"📋 Decoded String Table ({len(strings)} entries)",
        color=0x5865F2
    )
    if strings:
        groups: dict[str, list] = defaultdict(list)
        for s in strings:
            groups[s.purpose].append(s.decoded[:60])

        for purpose, items in list(groups.items())[:6]:
            e.add_field(
                name=f"[{purpose}] ({len(items)})",
                value="\n".join(f"`{i}`" for i in items[:5])
                      + (f"\n*...+{len(items)-5} more*" if len(items) > 5 else ""),
                inline=True
            )
    else:
        e.description = "*No decodable strings found.*"
    return e


def build_threat_embed(
    level: ThreatLevel,
    indicators: list[ThreatIndicator]
) -> discord.Embed:
    e = discord.Embed(
        title=f"{level.icon} Threat Report — {level.label}",
        color=level.color
    )
    if not indicators:
        e.description = "✅ No threats detected."
        return e

    cats: dict[str, list] = defaultdict(list)
    for ind in indicators:
        cats[ind.category].append(ind)

    for cat, inds in cats.items():
        val = "\n".join(
            f"Line {i.line_number}: `{i.evidence[:80]}`"
            for i in inds[:3]
        )
        e.add_field(name=f"🚨 {cat}", value=val or "No evidence", inline=False)

    e.set_footer(text="Xeioa Threat Scanner")
    e.timestamp = datetime.datetime.utcnow()
    return e


def build_progress_embed(progress: list[str]) -> discord.Embed:
    e = make_embed("⚙️ Analysis Progress", "\n".join(progress), 0x5865F2)
    return e


def build_api_embed(api_calls: list[dict]) -> discord.Embed:
    e = make_embed("🔌 Roblox API Usage", color=0x00ccff)
    seen: set[str] = set()
    rows = []
    for c in api_calls:
        key = c["call"]
        if key not in seen:
            seen.add(key)
            rows.append(f"`{c['call']}` — {c['purpose']}")
    e.description = "\n".join(rows[:20]) or "*No API calls detected.*"
    return e


async def send_code_result(
    interaction: discord.Interaction,
    msg,
    code: str,
    filename: str,
    output_format: str
):
    file_obj = discord.File(io.BytesIO(code.encode()), filename=filename)
    preview  = code[:1800] + "\n-- [TRUNCATED — SEE FILE]" if len(code) > 1800 else code

    if output_format == "file":
        await msg.delete()
        await interaction.channel.send(
            content="📎 Deobfuscated output:",
            file=file_obj
        )
    elif output_format == "both":
        await msg.edit(content=f"```lua\n{preview}\n```")
        file_obj2 = discord.File(io.BytesIO(code.encode()), filename=filename)
        await interaction.channel.send(content="📎 Full file:", file=file_obj2)
    else:
        if len(code) > 1900:
            await msg.delete()
            await interaction.channel.send(
                content="📎 Output too large — attached as file:",
                file=file_obj
            )
        else:
            await msg.edit(content=f"```lua\n{preview}\n```")


def add_to_history(user_id: int, result: dict, filename: str):
    entry = {
        "timestamp":  datetime.datetime.utcnow().isoformat(),
        "filename":   filename,
        "obfuscator": result["obfuscator"],
        "threat":     result["threat_level"].label,
        "confidence": result["overall_conf"],
    }
    user_history[user_id].insert(0, entry)
    user_history[user_id] = user_history[user_id][:HISTORY_LIMIT]


def fingerprint_code(code: str) -> str:
    stripped = re.sub(r"\s+|--[^\n]*", "", code)
    return hashlib.sha256(stripped.encode()).hexdigest()


# ════════════════════════════════════════════════════════════════
#  PRIMARY COMMAND — /deobfuscate
# ════════════════════════════════════════════════════════════════

@bot.tree.command(
    name="deobfuscate",
    description="🔓 Full 9-pass deobfuscation of any Roblox Lua script"
)
@app_commands.describe(
    file="Upload a .lua / .luau / .txt file",
    script="Paste a short script directly",
    depth="Analysis depth",
    output_format="How to return results",
    annotate="Include inline annotations",
    threat_scan="Run threat/malware scan"
)
@app_commands.choices(
    depth=[
        app_commands.Choice(name="⚡ Quick  (strings + cleanup)",  value="quick"),
        app_commands.Choice(name="⚙️ Standard (full pipeline)",    value="standard"),
        app_commands.Choice(name="🔬 Deep  (all passes + VM)",     value="deep"),
        app_commands.Choice(name="🤖 VM   (VM analysis focus)",    value="vm"),
    ],
    output_format=[
        app_commands.Choice(name="Code block",       value="codeblock"),
        app_commands.Choice(name="File attachment",  value="file"),
        app_commands.Choice(name="Both",             value="both"),
    ]
)
async def cmd_deobfuscate(
    interaction: discord.Interaction,
    file:          Optional[discord.Attachment] = None,
    script:        Optional[str]                = None,
    depth:         str  = "standard",
    output_format: str  = "both",
    annotate:      bool = True,
    threat_scan:   bool = True
):
    ok, wait = check_rate_limit(interaction.user.id)
    if not ok:
        await interaction.response.send_message(
            f"⏳ Rate limited. Try again in **{wait}s**.", ephemeral=True
        ); return

    if not file and not script:
        await interaction.response.send_message(
            "❌ Provide a `file` or `script`.", ephemeral=True
        ); return

    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mInitializing 9-pass deobfuscation engine...\u001b[0m\n```"
    )
    msg = await interaction.original_response()

    # Load code
    if file:
        if file.size > MAX_SCRIPT_SIZE:
            await msg.edit(content="❌ File exceeds 500 KB limit."); return
        code = await bot.read_attachment(file)
        if not code:
            await msg.edit(content="❌ Invalid file type. Use .lua/.luau/.txt"); return
        fname = file.filename
    else:
        code  = script
        fname = "pasted_script.lua"

    # Check known hash
    fp = fingerprint_code(code)
    if fp in script_hash_db:
        known = script_hash_db[fp]
        await msg.edit(
            content=(
                f"⚡ Script recognized from database!\n"
                f"Previously identified as: `{known['obfuscator']}`\n"
                f"Threat: `{known['threat']}`\n"
                f"Running fresh analysis anyway..."
            )
        )
        await asyncio.sleep(1.5)

    # Send progress updates
    await bot.animated_status(msg, f"Running [{depth}] analysis")

    # Run engine
    depth_enum = AnalysisDepth(depth)
    loop       = asyncio.get_event_loop()
    engine     = MasterDeobfuscator(code, depth_enum, annotate, threat_scan)
    result     = await loop.run_in_executor(None, engine.run)

    # Store in hash db
    script_hash_db[fp] = {
        "obfuscator": result["obfuscator"],
        "threat":     result["threat_level"].label,
        "timestamp":  time.time(),
    }

    # Store in history
    add_to_history(interaction.user.id, result, fname)

    # Build embeds
    det_embed  = build_detection_embed(result)
    str_embed  = build_strings_embed(result["decoded_strings"])
    api_embed  = build_api_embed(result["api_calls"])
    prog_embed = build_progress_embed(result["progress"])

    flow_embed = make_embed(
        "🔄 Execution Flow Summary",
        result["flow_summary"],
        color=0x5865F2
    )

    threat_embed = build_threat_embed(
        result["threat_level"],
        result["indicators"]
    )

    embeds = [det_embed, str_embed, flow_embed, api_embed, threat_embed, prog_embed]

    await msg.edit(content="✅ **Analysis complete:**", embeds=embeds)

    # Send flowchart if built
    if result["cfg_built"] and result["flowchart"]:
        fc = result["flowchart"]
        if len(fc) < 1900:
            await interaction.channel.send(f"```\n{fc}\n```")

    # VM summary
    if result["vm_result"].get("detected"):
        vm_r   = result["vm_result"]
        cs     = vm_r["confidence_summary"]
        total  = sum(cs.values()) or 1
        hi_pct = round(cs["HIGH"]   / total * 100)
        me_pct = round(cs["MEDIUM"] / total * 100)
        lo_pct = round(cs["LOW"]    / total * 100)
        vm_embed = make_embed(
            "🤖 VM Decompiler Results",
            f"**Instructions recovered:** {total}\n"
            f"🟢 High confidence: {hi_pct}%\n"
            f"🟡 Medium: {me_pct}%\n"
            f"🔴 Low: {lo_pct}%\n"
            + (f"⚠️ Nested VM detected (depth {vm_r['depth']+1})"
               if vm_r.get("nested_vm") else ""),
            color=0x9b59b6
        )
        await interaction.channel.send(embed=vm_embed)

    # Send deobfuscated code
    code_msg = await interaction.channel.send(
        "```ansi\n\u001b[1;32mPreparing clean output...\u001b[0m\n```"
    )
    await send_code_result(
        interaction, code_msg,
        result["clean_code"],
        f"deobfuscated_{fname}",
        output_format
    )


# ════════════════════════════════════════════════════════════════
#  /deob-strings
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-strings", description="Extract & decode the full string table")
@app_commands.describe(
    file="Upload .lua/.luau/.txt",
    script="Or paste script"
)
async def cmd_deob_strings(
    interaction: discord.Interaction,
    file:   Optional[discord.Attachment] = None,
    script: Optional[str] = None
):
    ok, wait = check_rate_limit(interaction.user.id)
    if not ok:
        await interaction.response.send_message(f"⏳ Wait {wait}s.", ephemeral=True); return
    if not file and not script:
        await interaction.response.send_message("❌ Provide file or script.", ephemeral=True); return

    await interaction.response.defer()
    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input."); return

    engine = MasterDeobfuscator(code, AnalysisDepth.QUICK)
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, engine.run)

    strings = result["decoded_strings"]
    embed   = build_strings_embed(strings)

    if strings:
        lines  = []
        for i, s in enumerate(strings, 1):
            chain = " → ".join(s.encode_chain) if s.encode_chain else "direct"
            lines.append(
                f"{i:3}. [{s.purpose:12}] "
                f"({s.occurrences}x) "
                f"\"{s.decoded[:50]}\" "
                f"[via {chain}]"
            )
        txt     = "\n".join(lines)
        file_out = discord.File(io.BytesIO(txt.encode()), filename="decoded_strings.txt")
        await interaction.followup.send(embed=embed, file=file_out)
    else:
        await interaction.followup.send(embed=embed)


# ════════════════════════════════════════════════════════════════
#  /deob-identify
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-identify", description="Identify the obfuscator used")
@app_commands.describe(file="Upload file", script="Or paste script")
async def cmd_deob_identify(
    interaction: discord.Interaction,
    file:   Optional[discord.Attachment] = None,
    script: Optional[str] = None
):
    if not file and not script:
        await interaction.response.send_message("❌ Provide file or script.", ephemeral=True); return
    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input."); return

    engine = MasterDeobfuscator(code, AnalysisDepth.QUICK)
    engine._pass1_structural_analysis()

    result = {
        "obfuscator":    engine.obfuscator,
        "confidence":    engine.confidence,
        "complexity":    engine.complexity,
        "layers":        engine.layers,
        "overall_conf":  float(engine.confidence.score),
        "threat_level":  ThreatLevel.CLEAN,
        "deobf_time":    0.0,
        "api_calls":     [],
        "indicators":    [],
    }

    embed = build_detection_embed(result)
    embed.title = "🔍 Obfuscator Identification"

    # Version hints
    hints = []
    code_str = code
    for name, sig in OBFUSCATOR_SIGNATURES.items():
        for const in sig.get("magic_constants", []):
            if str(const) in code_str:
                hints.append(f"Magic constant `{const}` → suggests **{name}**")

    if hints:
        embed.add_field(name="🔢 Version Hints", value="\n".join(hints), inline=False)

    await interaction.followup.send(embed=embed)


# ════════════════════════════════════════════════════════════════
#  /deob-explain
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-explain", description="High-level explanation of a script")
@app_commands.describe(file="Upload file", script="Or paste script")
async def cmd_deob_explain(
    interaction: discord.Interaction,
    file:   Optional[discord.Attachment] = None,
    script: Optional[str] = None
):
    if not file and not script:
        await interaction.response.send_message("❌ Provide file or script.", ephemeral=True); return
    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input."); return

    engine = MasterDeobfuscator(code, AnalysisDepth.STANDARD)
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, engine.run)

    det_embed    = build_detection_embed(result)
    threat_embed = build_threat_embed(result["threat_level"], result["indicators"])
    api_embed    = build_api_embed(result["api_calls"])

    flow_embed = make_embed(
        "📖 Script Explanation",
        result["flow_summary"] + "\n\n"
        + f"**Services:** "
        + ", ".join(s.decoded for s in result["decoded_strings"]
                    if s.purpose == "SERVICE")[:200] or "None"
        + "\n**Threat Level:** "
        + f"{result['threat_level'].icon} {result['threat_level'].label}",
        color=0x5865F2
    )

    await interaction.followup.send(embeds=[det_embed, flow_embed, api_embed, threat_embed])


# ════════════════════════════════════════════════════════════════
#  /deob-threat
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-threat", description="Dedicated threat/malware analysis")
@app_commands.describe(file="Upload file", script="Or paste script")
async def cmd_deob_threat(
    interaction: discord.Interaction,
    file:   Optional[discord.Attachment] = None,
    script: Optional[str] = None
):
    if not file and not script:
        await interaction.response.send_message("❌ Provide file or script.", ephemeral=True); return
    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input."); return

    scanner  = ThreatScanner()
    level, indicators = scanner.scan(code)
    embed    = build_threat_embed(level, indicators)

    # IoC summary
    ioc_lines = []
    for ind in indicators:
        ioc_lines.append(
            f"• **{ind.category}** (line {ind.line_number}): "
            f"`{ind.evidence[:80]}`"
        )
    if ioc_lines:
        ioc_embed = make_embed(
            "🔎 Indicators of Compromise (IoCs)",
            "\n".join(ioc_lines[:20]),
            color=level.color
        )
        await interaction.followup.send(embeds=[embed, ioc_embed])
    else:
        await interaction.followup.send(embed=embed)


# ════════════════════════════════════════════════════════════════
#  /deob-compare
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-compare", description="Compare two scripts for similarity")
@app_commands.describe(script1="First file", script2="Second file")
async def cmd_deob_compare(
    interaction: discord.Interaction,
    script1: discord.Attachment,
    script2: discord.Attachment
):
    await interaction.response.defer()
    c1 = await bot.read_attachment(script1)
    c2 = await bot.read_attachment(script2)

    if not c1 or not c2:
        await interaction.followup.send("❌ Could not read one or both files."); return

    loop = asyncio.get_event_loop()
    e1   = MasterDeobfuscator(c1, AnalysisDepth.STANDARD)
    e2   = MasterDeobfuscator(c2, AnalysisDepth.STANDARD)
    r1   = await loop.run_in_executor(None, e1.run)
    r2   = await loop.run_in_executor(None, e2.run)

    # Hash comparison
    h1 = fingerprint_code(r1["clean_code"])
    h2 = fingerprint_code(r2["clean_code"])

    if h1 == h2:
        verdict = "✅ **Identical** — same script under different obfuscation."
        color   = 0x00ff99
        sim     = 100.0
    else:
        # String-level similarity
        s1 = set(s.decoded for s in r1["decoded_strings"])
        s2 = set(s.decoded for s in r2["decoded_strings"])
        union     = len(s1 | s2) or 1
        intersect = len(s1 & s2)
        sim       = round(intersect / union * 100, 1)

        if   sim >= 90: verdict = f"🟢 **Very likely same script** ({sim}% similarity)"; color = 0x00ff99
        elif sim >= 70: verdict = f"🟡 **Probably same script** ({sim}% similarity)";   color = 0xffaa00
        elif sim >= 40: verdict = f"🟠 **Possibly related** ({sim}% similarity)";        color = 0xff6600
        else:           verdict = f"🔴 **Different scripts** ({sim}% similarity)";       color = 0xff0000

    embed = make_embed("🔄 Script Comparison", color=color)
    embed.add_field(name="Script 1", value=f"`{r1['obfuscator']}`\n`{script1.filename}`", inline=True)
    embed.add_field(name="Script 2", value=f"`{r2['obfuscator']}`\n`{script2.filename}`", inline=True)
    embed.add_field(name="Similarity", value=f"`{sim}%`", inline=True)
    embed.add_field(name="Verdict", value=verdict, inline=False)

    # Layer comparison
    l1 = set(r1["layers"])
    l2 = set(r2["layers"])
    shared = l1 & l2
    if shared:
        embed.add_field(
            name="Shared Obfuscation Layers",
            value="\n".join(f"• {l}" for l in shared),
            inline=False
        )
    await interaction.followup.send(embed=embed)


# ════════════════════════════════════════════════════════════════
#  /deob-vm-analysis
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-vm-analysis", description="Dedicated VM architecture analysis")
@app_commands.describe(file="Upload file", script="Or paste script")
async def cmd_deob_vm(
    interaction: discord.Interaction,
    file:   Optional[discord.Attachment] = None,
    script: Optional[str] = None
):
    if not file and not script:
        await interaction.response.send_message("❌ Provide file or script.", ephemeral=True); return
    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input."); return

    loop = asyncio.get_event_loop()
    vm   = VMDecompiler(code)
    r    = await loop.run_in_executor(None, vm.analyze)

    if not r.get("detected"):
        await interaction.followup.send(
            embed=make_embed("🤖 VM Analysis", "❌ No VM detected in this script.", 0xff0000)
        ); return

    cs     = r["confidence_summary"]
    total  = sum(cs.values()) or 1
    insts  = r.get("instructions", [])

    embed = make_embed("🤖 VM Architecture Analysis", color=0x9b59b6)
    embed.add_field(name="VM Detected",   value="✅ Yes",                      inline=True)
    embed.add_field(name="Nesting Depth", value=f"`{r['depth']}`",              inline=True)
    embed.add_field(name="Nested VM",     value="⚠️ Yes" if r.get("nested_vm") else "No", inline=True)
    embed.add_field(
        name="Instructions",
        value=(
            f"Total: **{total}**\n"
            f"🟢 High: `{cs['HIGH']}`\n"
            f"🟡 Medium: `{cs['MEDIUM']}`\n"
            f"🔴 Low: `{cs['LOW']}`"
        ),
        inline=True
    )
    embed.add_field(
        name="Constants Extracted",
        value=f"`{len(r.get('constants', []))}`",
        inline=True
    )

    # Instruction breakdown
    opcode_counts: dict[str, int] = Counter(
        i.opcode.value for i in insts
    )
    breakdown = "\n".join(
        f"`{k}`: {v}" for k, v in
        sorted(opcode_counts.items(), key=lambda x: -x[1])[:10]
    )
    embed.add_field(name="Opcode Breakdown", value=breakdown or "N/A", inline=False)

    await interaction.followup.send(embed=embed)

    # Send decompiled output as file
    decompiled = r.get("decompiled", "-- No decompiled output")
    f_out = discord.File(io.BytesIO(decompiled.encode()), filename="vm_decompiled.lua")
    await interaction.channel.send(content="📎 VM Decompiled Output:", file=f_out)


# ════════════════════════════════════════════════════════════════
#  /deob-api
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-api", description="Show all Roblox API calls in the script")
@app_commands.describe(file="Upload file", script="Or paste script")
async def cmd_deob_api(
    interaction: discord.Interaction,
    file:   Optional[discord.Attachment] = None,
    script: Optional[str] = None
):
    if not file and not script:
        await interaction.response.send_message("❌ Provide file or script.", ephemeral=True); return
    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input."); return

    engine = MasterDeobfuscator(code, AnalysisDepth.QUICK)
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, engine.run)

    embed  = build_api_embed(result["api_calls"])
    await interaction.followup.send(embed=embed)


# ════════════════════════════════════════════════════════════════
#  /deob-history
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-history", description="View your last 50 deobfuscation jobs")
async def cmd_deob_history(interaction: discord.Interaction):
    history = user_history.get(interaction.user.id, [])
    if not history:
        await interaction.response.send_message(
            "📭 You have no deobfuscation history yet.", ephemeral=True
        ); return

    embed = make_embed(
        f"📜 Your Deobfuscation History ({len(history)} jobs)",
        color=0x5865F2
    )
    lines = []
    for i, entry in enumerate(history[:20], 1):
        ts = entry["timestamp"][:10]
        lines.append(
            f"`{i:2}.` `{ts}` — `{entry['filename'][:20]}` — "
            f"**{entry['obfuscator']}** — "
            f"Threat: `{entry['threat']}` — "
            f"Conf: `{entry['confidence']:.1f}%`"
        )
    embed.description = "\n".join(lines)
    if len(history) > 20:
        embed.set_footer(text=f"Showing 20/{len(history)} jobs | Xeioa Bot")
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ════════════════════════════════════════════════════════════════
#  /deob-settings
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-settings", description="Configure your personal deobfuscation settings")
@app_commands.describe(
    depth="Default analysis depth",
    output="Default output format",
    threat="Auto-run threat scan",
    annotate="Include inline annotations",
    verbosity="Comment verbosity level",
    naming="Variable naming style"
)
@app_commands.choices(
    depth=[
        app_commands.Choice(name="quick",    value="quick"),
        app_commands.Choice(name="standard", value="standard"),
        app_commands.Choice(name="deep",     value="deep"),
        app_commands.Choice(name="vm",       value="vm"),
    ],
    output=[
        app_commands.Choice(name="codeblock", value="codeblock"),
        app_commands.Choice(name="file",      value="file"),
        app_commands.Choice(name="both",      value="both"),
    ],
    verbosity=[
        app_commands.Choice(name="minimal", value="minimal"),
        app_commands.Choice(name="normal",  value="normal"),
        app_commands.Choice(name="verbose", value="verbose"),
    ],
    naming=[
        app_commands.Choice(name="semantic (smart)", value="semantic"),
        app_commands.Choice(name="generic (var_N)",  value="generic"),
        app_commands.Choice(name="preserve original",value="preserve"),
    ]
)
async def cmd_deob_settings(
    interaction: discord.Interaction,
    depth:    Optional[str]  = None,
    output:   Optional[str]  = None,
    threat:   Optional[bool] = None,
    annotate: Optional[bool] = None,
    verbosity: Optional[str] = None,
    naming:   Optional[str]  = None
):
    s = get_settings(interaction.user.id)

    if depth:    s.default_depth  = depth
    if output:   s.output_format  = output
    if threat is not None:   s.auto_threat  = threat
    if annotate is not None: s.annotate     = annotate
    if verbosity: s.verbosity     = verbosity
    if naming:   s.naming_style  = naming

    embed = make_embed("⚙️ Your Settings Updated", color=0x00ff99)
    embed.add_field(name="Default Depth",   value=f"`{s.default_depth}`",  inline=True)
    embed.add_field(name="Output Format",   value=f"`{s.output_format}`",  inline=True)
    embed.add_field(name="Auto Threat",     value=f"`{s.auto_threat}`",    inline=True)
    embed.add_field(name="Annotations",     value=f"`{s.annotate}`",       inline=True)
    embed.add_field(name="Verbosity",       value=f"`{s.verbosity}`",      inline=True)
    embed.add_field(name="Naming Style",    value=f"`{s.naming_style}`",   inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ════════════════════════════════════════════════════════════════
#  /deob-help
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="deob-help", description="Full help for the deobfuscator")
async def cmd_deob_help(interaction: discord.Interaction):
    embed = discord.Embed(
        title="📖 Xeioa Max-Level Deobfuscator — Help",
        description=(
            "The most advanced Roblox Lua deobfuscation engine available.\n"
            "9-pass iterative pipeline, VM decompilation, CFG recovery, "
            "semantic analysis, and full threat scanning."
        ),
        color=0x00ff99
    )

    embed.add_field(
        name="🔓 Core Commands",
        value=(
            "`/deobfuscate` — Full 9-pass deobfuscation\n"
            "`/deob-strings` — Decode string table only\n"
            "`/deob-identify` — Identify obfuscator\n"
            "`/deob-explain` — High-level explanation\n"
            "`/deob-threat` — Dedicated threat report\n"
            "`/deob-compare` — Compare two scripts\n"
            "`/deob-vm-analysis` — VM architecture analysis\n"
            "`/deob-api` — Roblox API usage map"
        ),
        inline=False
    )

    embed.add_field(
        name="👤 User Commands",
        value=(
            "`/deob-history` — View last 50 jobs\n"
            "`/deob-settings` — Configure preferences\n"
            "`/deob-help` — This message"
        ),
        inline=False
    )

    embed.add_field(
        name="🧠 Engine Capabilities",
        value=(
            "• **15+ encoding formats** decoded automatically\n"
            "• **12-layer** nested encoding support\n"
            "• **9-pass** iterative deobfuscation pipeline\n"
            "• **Full VM decompilation** (IronBrew2, Luraph, Moonsec)\n"
            "• **Stacked VM** support (up to 5 levels deep)\n"
            "• **Control Flow Graph** reconstruction\n"
            "• **Semantic variable renaming** (context-aware)\n"
            "• **200+ Roblox API** recognition\n"
            "• **10 threat categories** with IoC analysis\n"
            "• **Confidence scoring** per section\n"
            "• **Script fingerprinting** database"
        ),
        inline=False
    )

    tbl = (
        "Obfuscator      | Support    | Version Detection\n"
        "----------------|------------|------------------\n"
        "WeAreDevs       | ✅ Full    | ✅ Yes\n"
        "IronBrew2       | ✅ Full    | ✅ Yes\n"
        "Luraph          | ✅ Full    | ✅ Yes\n"
        "Moonsec v3      | ✅ Full    | ✅ Yes\n"
        "PSU             | ✅ Full    | ⚠️ Partial\n"
        "Synapse Xen     | ⚠️ Partial | ⚠️ Partial\n"
        "Prometheus      | ⚠️ Partial | ⚠️ Partial\n"
        "Custom VM       | ⚠️ Heuristic| ❌ No"
    )
    embed.add_field(name="📋 Supported Obfuscators", value=f"```\n{tbl}\n```", inline=False)

    embed.add_field(
        name="⚙️ Limits",
        value=(
            f"• Max file size: **500 KB**\n"
            f"• Rate limit: **{RATE_LIMIT_MAX} requests / 5 minutes**\n"
            f"• Batch: **{MAX_BATCH_SIZE} scripts** per job\n"
            f"• History: **{HISTORY_LIMIT} jobs** stored\n"
            f"• Discord tokens + webhooks **auto-redacted**\n"
            f"• Malware flagged but **always deobfuscated**"
        ),
        inline=False
    )

    embed.set_footer(text="Xeioa Max-Level Deobfuscator — Built for precision")
    await interaction.response.send_message(embed=embed)


# ════════════════════════════════════════════════════════════════
#  UTILITY COMMANDS (kept from previous version)
# ════════════════════════════════════════════════════════════════

@bot.tree.command(name="ping", description="Bot latency")
async def ping(interaction: discord.Interaction):
    ms    = round(bot.latency * 1000)
    color = 0x00ff99 if ms < 100 else 0xffaa00 if ms < 200 else 0xff0000
    await interaction.response.send_message(
        embed=make_embed("🏓 Pong!", f"**{ms}ms**", color)
    )


@bot.tree.command(name="uptime", description="Bot uptime")
async def uptime(interaction: discord.Interaction):
    delta = datetime.datetime.utcnow() - _start_time
    h, r  = divmod(int(delta.total_seconds()), 3600)
    m, s  = divmod(r, 60)
    await interaction.response.send_message(
        embed=make_embed("⏱️ Uptime", f"**{h}h {m}m {s}s**")
    )


@bot.tree.command(name="snipe", description="Last deleted message")
async def snipe(interaction: discord.Interaction):
    msg = snipe_data.get(interaction.channel_id)
    if not msg:
        await interaction.response.send_message("❌ Nothing to snipe!", ephemeral=True); return
    e = make_embed(f"💨 Sniped — #{interaction.channel.name}", msg.content or "*[no text]*", 0xff6b6b)
    e.set_author(name=str(msg.author), icon_url=msg.author.display_avatar.url)
    e.timestamp = msg.created_at
    await interaction.response.send_message(embed=e)


@bot.tree.command(name="cmds", description="All commands")
async def cmds(interaction: discord.Interaction):
    e = discord.Embed(title="⚡ Xeioa Bot Commands", color=0x00ff99)
    e.add_field(
        name="🔓 Deobfuscation",
        value=(
            "`/deobfuscate` `/deob-strings` `/deob-identify`\n"
            "`/deob-explain` `/deob-threat` `/deob-compare`\n"
            "`/deob-vm-analysis` `/deob-api`\n"
            "`/deob-history` `/deob-settings` `/deob-help`"
        ),
        inline=False
    )
    e.add_field(
        name="📊 Utility",
        value="`/ping` `/uptime` `/snipe` `/cmds`",
        inline=False
    )
    e.set_footer(text="Xeioa Max-Level Deobfuscator")
    await interaction.response.send_message(embed=e)


# ════════════════════════════════════════════════════════════════
#  RUN
# ════════════════════════════════════════════════════════════════

if not TOKEN:
    print("❌ Missing XEIOA_TOKEN environment variable")
else:
    bot.run(TOKEN)
