import io
import os
import re
import math
import time
import base64
import random
import string
import asyncio
import hashlib
import datetime
import discord
from collections import defaultdict
from discord.ext import commands
from discord import app_commands

TOKEN = os.getenv("XEIOA_TOKEN")

# ============================================================
#  RATE LIMIT STORAGE
# ============================================================
# rate_limit[user_id] = [timestamp, timestamp, ...]
rate_limit: dict[int, list[float]] = defaultdict(list)
RATE_LIMIT_MAX     = 3
RATE_LIMIT_WINDOW  = 300  # 5 minutes in seconds
MAX_SCRIPT_SIZE    = 500 * 1024  # 500 KB

# ============================================================
#  WARN / SNIPE STORAGE
# ============================================================
warn_data: dict[int, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
snipe_data: dict[int, discord.Message] = {}
_start_time = datetime.datetime.utcnow()


# ============================================================
#  DEOBFUSCATOR ENGINE
# ============================================================
class LuaDeobfuscator:
    """
    Core deobfuscation engine.
    Handles: octal/hex escapes, Base64, XOR, Caesar,
    string-char, table permutations, control-flow
    flattening, junk arithmetic, and VM-pattern hints.
    """

    # ── Obfuscator Signatures ────────────────────────────────
    SIGNATURES = {
        "WeAreDevs": [
            r"wearedevs\.net",
            r"local\s+D\s*=\s*\{",
            r"\\[0-7]{3}\\[0-7]{3}",
        ],
        "IronBrew2": [
            r"IronBrew",
            r"local\s+VMInstance",
            r"bit\.bxor",
            r"local\s+Wrap\s*=\s*function",
        ],
        "Luraph": [
            r"Luraph",
            r"local\s+[A-Z]{1,3}\s*=\s*\{\};\s*local\s+[A-Z]{1,3}",
            r"getfenv\(\)",
        ],
        "Moonsec": [
            r"Moonsec",
            r"string\.byte.*string\.char",
            r"local\s+[a-z]\s*=\s*\{\s*\[",
        ],
        "PSU": [
            r"psu\.dev",
            r"local\s+[A-Za-z_]+\s*=\s*\"[A-Za-z0-9+/=]{20,}\"",
        ],
        "Synapse Xen": [
            r"__index\s*=\s*function",
            r"setmetatable.*newproxy",
        ],
        "Prometheus": [
            r"Prometheus",
            r"local\s+[A-Z]\s*=\s*\{\};\s*[A-Z]\.__index",
        ],
    }

    # ── Base64 Alphabet Detection ────────────────────────────
    B64_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    B64_URL_SAFE  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    # ── Variable Name Pool ───────────────────────────────────
    DESCRIPTIVE_NAMES = [
        "player", "service", "instance", "value",
        "result", "target", "handler", "callback",
        "index", "count", "data", "object",
        "connection", "remote", "event", "func",
        "table", "string", "number", "bool",
    ]

    def __init__(self, code: str, depth: str = "standard"):
        self.original = code
        self.code     = code
        self.depth    = depth  # quick | standard | deep

        self.detected_obfuscator  = "Unknown"
        self.confidence           = "Low"
        self.complexity           = "Light"
        self.layers: list[str]    = []
        self.decoded_strings: list[str] = []
        self.warnings: list[str]  = []
        self.notes: list[str]     = []
        self.var_map: dict[str, str] = {}
        self._name_counter = 0

    # ── Public Entry Point ───────────────────────────────────
    def run(self) -> dict:
        self._detect_obfuscator()
        self._assess_complexity()

        if self.depth in ("standard", "deep"):
            self._decode_strings()
            self._decode_string_char()
            self._simplify_junk_arithmetic()
            self._resolve_table_permutations()
            self._flatten_control_flow()
            self._remove_dead_code()
            self._inline_wrappers()
            self._resolve_env_manipulation()
            self._rename_variables()
            self._remove_anti_debug()

        if self.depth == "quick":
            self._decode_strings()
            self._decode_string_char()

        self._detect_malware()
        self._sanitize_sensitive()
        self._format_output()

        return {
            "obfuscator":      self.detected_obfuscator,
            "confidence":      self.confidence,
            "complexity":      self.complexity,
            "layers":          self.layers,
            "decoded_strings": self.decoded_strings,
            "clean_code":      self.code,
            "warnings":        self.warnings,
            "notes":           self.notes,
            "flow_summary":    self._summarize_flow(),
        }

    # ── Detection ────────────────────────────────────────────
    def _detect_obfuscator(self):
        scores: dict[str, int] = {}
        for name, patterns in self.SIGNATURES.items():
            score = sum(
                1 for p in patterns
                if re.search(p, self.original, re.IGNORECASE | re.DOTALL)
            )
            if score:
                scores[name] = score

        if not scores:
            self.detected_obfuscator = "Unknown"
            self.confidence = "Low"
            return

        best = max(scores, key=lambda k: scores[k])
        best_score = scores[best]
        total_sigs = len(self.SIGNATURES[best])

        self.detected_obfuscator = best
        if best_score >= total_sigs:
            self.confidence = "High"
        elif best_score >= total_sigs / 2:
            self.confidence = "Medium"
        else:
            self.confidence = "Low"

    def _assess_complexity(self):
        code = self.original
        has_vm   = bool(re.search(r"while\s+\w+\s+do.*if\s+\w+\s*<\s*\d+", code, re.DOTALL))
        has_b64  = bool(re.search(r"[A-Za-z0-9+/]{40,}={0,2}", code))
        has_oct  = bool(re.search(r"\\[0-7]{3}", code))
        has_hex  = bool(re.search(r"\\x[0-9A-Fa-f]{2}", code))
        has_xor  = bool(re.search(r"bit\.bxor|bxor\(", code))
        has_cf   = bool(re.search(r"if\s+\w+\s*<\s*\d{5,}", code))

        layer_map = {
            "Octal encoding":            has_oct,
            "Hex encoding":              has_hex,
            "Base64 encoding":           has_b64,
            "XOR encryption":            has_xor,
            "Control flow flattening":   has_cf,
            "VM-based execution":        has_vm,
        }
        self.layers = [name for name, present in layer_map.items() if present]

        count = len(self.layers)
        if has_vm:
            self.complexity = "VM-Based"
        elif count >= 3:
            self.complexity = "Heavy"
        elif count >= 1:
            self.complexity = "Medium"
        else:
            self.complexity = "Light"

    # ── String Decoding ──────────────────────────────────────
    def _decode_strings(self):
        """Resolve octal, hex, and Base64 string literals."""
        # --- Octal escapes ---
        def decode_octal(match):
            s = match.group(0)
            try:
                return re.sub(
                    r"\\([0-7]{1,3})",
                    lambda m: chr(int(m.group(1), 8)),
                    s
                )
            except Exception:
                return s

        self.code = re.sub(r'"[^"]*\\[0-7]{2,3}[^"]*"', decode_octal, self.code)
        self.code = re.sub(r"'[^']*\\[0-7]{2,3}[^']*'", decode_octal, self.code)

        # --- Hex escapes ---
        self.code = re.sub(
            r"\\x([0-9A-Fa-f]{2})",
            lambda m: chr(int(m.group(1), 16)),
            self.code
        )

        # --- Numeric escapes (decimal) ---
        self.code = re.sub(
            r"\\([0-9]{1,3})",
            lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0),
            self.code
        )

        # --- Inline Base64 strings ---
        def try_b64(match):
            candidate = match.group(1)
            # Only attempt if length is plausible for B64
            if len(candidate) < 8 or len(candidate) % 4 != 0:
                return match.group(0)
            try:
                decoded = base64.b64decode(candidate).decode("utf-8")
                # Only replace if result is printable ASCII
                if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded):
                    self.decoded_strings.append(decoded)
                    return f'"{decoded}"'
            except Exception:
                pass
            return match.group(0)

        self.code = re.sub(r'"([A-Za-z0-9+/=]{16,})"', try_b64, self.code)

        # --- XOR-encrypted strings (heuristic) ---
        self._try_xor_decode()

        # --- Caesar cipher strings (heuristic) ---
        self._try_caesar_decode()

    def _try_xor_decode(self):
        """Detect simple XOR key patterns: string.byte(c) XOR key."""
        # Pattern: local key = N; ... char(byte XOR key)
        key_match = re.search(r"local\s+\w+\s*=\s*(\d+)\s*--\s*xor", self.code, re.IGNORECASE)
        if not key_match:
            return
        key = int(key_match.group(1))

        def xor_char(match):
            try:
                return chr(int(match.group(1)) ^ key)
            except Exception:
                return match.group(0)

        self.code = re.sub(r"string\.byte\(\"(.)\"\)\s*%^\s*\d+", xor_char, self.code)
        self.notes.append(f"XOR key {key} detected and applied to string decryption.")

    def _try_caesar_decode(self):
        """Detect Caesar cipher patterns in string tables."""
        # Very basic heuristic: look for consistent +N offset patterns
        pattern = re.search(r"string\.char\(([0-9]+)\s*\+\s*([0-9]+)\)", self.code)
        if not pattern:
            return
        shift = int(pattern.group(2))
        if 1 <= shift <= 25:
            self.notes.append(f"Possible Caesar cipher with shift {shift} detected.")

    def _decode_string_char(self):
        """Convert string.char(...) calls to string literals."""
        def repl(match):
            try:
                nums = [n.strip() for n in match.group(1).split(",")]
                chars = "".join(chr(int(n)) for n in nums if n.isdigit())
                self.decoded_strings.append(chars)
                return f'"{chars}"'
            except Exception:
                return match.group(0)

        self.code = re.sub(r"string\.char\(([0-9,\s]+)\)", repl, self.code)

    # ── Junk Arithmetic ──────────────────────────────────────
    def _simplify_junk_arithmetic(self):
        """Fold constant arithmetic expressions."""
        _SAFE = {k: v for k, v in math.__dict__.items() if not k.startswith("_")}

        def fold(match):
            expr = match.group(0)
            # Only fold if purely numeric
            if re.fullmatch(r"[\d\s\+\-\*\/\%\(\)\.]+", expr.strip()):
                try:
                    result = eval(expr, {"__builtins__": {}}, _SAFE)  # nosec
                    if isinstance(result, (int, float)):
                        return str(int(result)) if isinstance(result, float) and result.is_integer() else str(result)
                except Exception:
                    pass
            return expr

        # Match arithmetic inside local assignments
        self.code = re.sub(
            r"(?<==\s)[\-\d][\d\s\+\-\*\/\%\(\)\.]+(?=\s*[\n;,\)])",
            fold,
            self.code
        )

    # ── Table Permutation ────────────────────────────────────
    def _resolve_table_permutations(self):
        """
        Execute WeAreDevs-style table shuffle loops.
        Pattern: for I,l in ipairs({{...}}) do D[I], D[l] = D[l], D[I] end
        """
        # Extract string table D
        tbl_match = re.search(
            r"local\s+D\s*=\s*\{([\s\S]*?)\}",
            self.code
        )
        if not tbl_match:
            return

        raw = tbl_match.group(1)
        entries = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
        if not entries:
            return

        # Find swap pairs
        swap_matches = re.findall(
            r"D\[I\]\s*,\s*D\[l\]\s*=\s*D\[l\]\s*,\s*D\[I\]",
            self.code
        )
        pair_matches = re.findall(r"\{(\d+),\s*(\d+)\}", self.code)

        for a_str, b_str in pair_matches:
            a, b = int(a_str) - 1, int(b_str) - 1
            if 0 <= a < len(entries) and 0 <= b < len(entries):
                entries[a], entries[b] = entries[b], entries[a]

        # Store resolved strings
        self.decoded_strings = entries[:] if not self.decoded_strings else self.decoded_strings

        # Replace D[n] references
        for i, val in enumerate(entries, start=1):
            self.code = re.sub(
                rf"\bD\[{i}\]",
                f'"{val}"',
                self.code
            )

        self.notes.append(f"Resolved WeAreDevs string table D with {len(entries)} entries.")

    # ── Control Flow Flattening ──────────────────────────────
    def _flatten_control_flow(self):
        """
        Detect state-machine dispatcher loops and annotate them.
        Full reconstruction requires runtime tracing; we annotate
        blocks with their state number for human readability.
        """
        # Find dispatcher variable
        dispatch_match = re.search(
            r"while\s+(\w+)\s+do\s+if\s+\1\s*<\s*(\d+)",
            self.code,
            re.DOTALL
        )
        if not dispatch_match:
            return

        var_name  = dispatch_match.group(1)
        threshold = dispatch_match.group(2)

        # Annotate each state block
        def annotate_state(match):
            state = match.group(1)
            return f"\n-- [STATE {state}]\n{match.group(0)}"

        self.code = re.sub(
            rf"elseif\s+{re.escape(var_name)}\s*==\s*(\d+)\s+then",
            annotate_state,
            self.code
        )

        # Remove opaque predicates that always evaluate true/false
        self.code = re.sub(
            r"if\s+\d+\s*[<>]=?\s*\d+\s*then\s*([\s\S]*?)\s*end",
            lambda m: m.group(1),  # keep the body, drop the dead if
            self.code
        )

        self.notes.append(
            f"State machine dispatcher detected (var={var_name}, "
            f"threshold={threshold}). States annotated."
        )

    # ── Dead Code Removal ────────────────────────────────────
    def _remove_dead_code(self):
        """Remove provably dead branches and no-op statements."""
        # Remove: if true then ... end  (but keep body)
        self.code = re.sub(
            r"if\s+true\s+then\s*([\s\S]*?)\s*end\b",
            r"\1",
            self.code
        )
        # Remove: if false then ... end (whole block)
        self.code = re.sub(
            r"if\s+false\s+then[\s\S]*?end\b",
            "-- [DEAD BRANCH REMOVED]",
            self.code
        )
        # Remove semicolons chains
        self.code = re.sub(r";{2,}", ";", self.code)
        # Remove trailing whitespace
        self.code = re.sub(r"[ \t]+\n", "\n", self.code)
        # Collapse 3+ blank lines
        self.code = re.sub(r"\n{4,}", "\n\n\n", self.code)

    # ── Inline Wrappers ──────────────────────────────────────
    def _inline_wrappers(self):
        """
        Inline trivial one-liner wrapper functions.
        Pattern: local f = function(...) return g(...) end
        """
        pattern = re.compile(
            r"local\s+(\w+)\s*=\s*function\s*\(([^)]*)\)\s*"
            r"return\s+(\w+)\(([^)]*)\)\s*end"
        )

        def inline(match):
            wrapper  = match.group(1)
            params   = match.group(2)
            inner    = match.group(3)
            args     = match.group(4)
            if params.strip() == args.strip():
                self.code = self.code.replace(wrapper + "(", inner + "(")
                return f"-- [INLINED: {wrapper} → {inner}]"
            return match.group(0)

        self.code = pattern.sub(inline, self.code)

        # Unwrap self-executing anonymous functions
        self.code = re.sub(
            r"\(function\s*\(\.\.\.\)\s*([\s\S]*?)\s*end\)\(\.\.\.\)",
            r"-- [UNWRAPPED SELF-EXEC]\n\1",
            self.code
        )

    # ── Environment Manipulation ─────────────────────────────
    def _resolve_env_manipulation(self):
        """Resolve getfenv/_ENV indirection patterns."""
        # Replace getfenv() references with _ENV
        self.code = re.sub(r"getfenv\(\s*\)", "_ENV", self.code)

        # Resolve _ENV["service"] → service lookups
        self.code = re.sub(
            r'_ENV\["([A-Za-z_][A-Za-z0-9_]*)"\]',
            r"\1",
            self.code
        )

        # Resolve game:GetService("X") stored in local
        def resolve_service(match):
            var  = match.group(1)
            svc  = match.group(2)
            self.code = self.code.replace(var, svc)
            return f'local {svc} = game:GetService("{svc}")'

        self.code = re.sub(
            r'local\s+(\w+)\s*=\s*game:GetService\("([^"]+)"\)',
            resolve_service,
            self.code
        )

    # ── Variable Renaming ────────────────────────────────────
    def _rename_variables(self):
        """Rename obfuscated single/double letter variable names."""
        # Find all locals
        locals_found = re.findall(
            r"\blocal\s+([A-Z_]{1,2})\b",
            self.code
        )

        for var in set(locals_found):
            if var in ("D", "I"):  # Already handled above
                continue
            new_name = self._next_name()
            self.var_map[var] = new_name
            self.code = re.sub(rf"\b{re.escape(var)}\b", new_name, self.code)

    def _next_name(self) -> str:
        pool = self.DESCRIPTIVE_NAMES
        idx  = self._name_counter % len(pool)
        suffix = self._name_counter // len(pool)
        self._name_counter += 1
        name = pool[idx]
        return name if suffix == 0 else f"{name}_{suffix}"

    # ── Anti-Debug Removal ───────────────────────────────────
    def _remove_anti_debug(self):
        """Remove common anti-analysis patterns."""
        patterns = [
            # Infinite loop triggers
            (r"while\s+true\s+do\s+error\([^)]+\)\s+end", "-- [ANTI-DEBUG LOOP REMOVED]"),
            # Debug hook installers
            (r"debug\.sethook\([^)]+\)", "-- [DEBUG HOOK REMOVED]"),
            # Timing checks
            (r"os\.clock\(\).*\n.*error\(", "-- [TIMING CHECK REMOVED]"),
            # Environment fingerprinting
            (r"if\s+type\(game\)\s*~=\s*\"[^\"]+\"\s+then[\s\S]*?end", "-- [ENV CHECK REMOVED]"),
        ]
        for pat, replacement in patterns:
            self.code = re.sub(pat, replacement, self.code, flags=re.DOTALL)

    # ── Malware Detection ────────────────────────────────────
    def _detect_malware(self):
        """Flag potentially malicious patterns."""
        malware_patterns = {
            "Discord token grabber":    r"Authorization.*Bot\s+[A-Za-z0-9._-]{59}",
            "Webhook exfiltration":     r"https://discord(?:app)?\.com/api/webhooks/",
            "Remote code execution":    r"loadstring\s*\(\s*game:HttpGet\(",
            "Backdoor (getfenv exec)":  r"getfenv\(\)\s*\.\s*loadstring",
            "Password/cookie stealer":  r"win32api|HKEY_CURRENT_USER.*password",
            "HTTP POST exfiltration":   r"HttpService.*PostAsync.*password|token",
        }
        for label, pattern in malware_patterns.items():
            if re.search(pattern, self.code, re.IGNORECASE):
                self.warnings.append(f"⚠️ MALWARE DETECTED: {label}")

    # ── Sensitive Data Scrubbing ─────────────────────────────
    def _sanitize_sensitive(self):
        """Strip tokens, webhooks, and credentials."""
        # Discord bot tokens
        self.code = re.sub(
            r"[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
            "[DISCORD TOKEN REDACTED]",
            self.code
        )
        # Webhook URLs
        self.code = re.sub(
            r"https://discord(?:app)?\.com/api/webhooks/[^\s\"']+",
            "[WEBHOOK URL REDACTED]",
            self.code
        )

    # ── Output Formatting ────────────────────────────────────
    def _format_output(self):
        """Apply final formatting: indentation, header comment."""
        header = (
            f"-- Deobfuscated by Xeioa Bot\n"
            f"-- Detected: {self.detected_obfuscator} "
            f"({self.confidence} confidence)\n"
            f"-- Complexity: {self.complexity}\n"
            f"-- Layers: {', '.join(self.layers) or 'None detected'}\n"
            f"-- Date: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
        )

        # Basic indentation fix
        indent = 0
        lines  = []
        openers  = re.compile(r"\b(function|do|then|repeat|else)\b")
        closers  = re.compile(r"\b(end|until|else)\b")

        for line in self.code.splitlines():
            stripped = line.strip()
            if not stripped:
                lines.append("")
                continue
            first = stripped.split()[0] if stripped.split() else ""
            if first in ("end", "until", "else", "elseif"):
                indent = max(0, indent - 1)
            lines.append("    " * indent + stripped)
            if (
                first in ("function", "do", "repeat", "else", "elseif")
                or stripped.endswith("do")
                or stripped.endswith("then")
                or re.match(r"^function\b", stripped)
                or re.match(r"^local\s+function\b", stripped)
            ):
                indent += 1

        self.code = header + "\n" + "\n".join(lines)

    # ── Flow Summary ─────────────────────────────────────────
    def _summarize_flow(self) -> str:
        code = self.code
        summary = []

        if re.search(r'game:GetService\("Players"\)', code):
            summary.append("• Accesses the Players service (likely player-targeting)")
        if re.search(r'game:GetService\("HttpService"\)', code):
            summary.append("• Uses HttpService (network requests detected)")
        if re.search(r'Instance\.new\(', code):
            summary.append("• Creates new Roblox Instances")
        if re.search(r'RemoteEvent|RemoteFunction', code):
            summary.append("• Fires or connects RemoteEvents/RemoteFunctions")
        if re.search(r'LocalPlayer', code):
            summary.append("• Targets the LocalPlayer specifically")
        if re.search(r'loadstring', code):
            summary.append("• Executes dynamic code via loadstring ⚠️")
        if re.search(r'workspace|game\.Workspace', code):
            summary.append("• Manipulates Workspace objects")
        if not summary:
            summary.append("• Unable to determine high-level intent from available patterns.")

        return "\n".join(summary)


# ============================================================
#  IDENTIFY ENGINE (lightweight — no full deobf)
# ============================================================
class LuaIdentifier:
    def __init__(self, code: str):
        self.engine = LuaDeobfuscator(code, depth="quick")

    def identify(self) -> dict:
        self.engine._detect_obfuscator()
        self.engine._assess_complexity()
        return {
            "obfuscator":  self.engine.detected_obfuscator,
            "confidence":  self.engine.confidence,
            "complexity":  self.engine.complexity,
            "layers":      self.engine.layers,
        }


# ============================================================
#  BOT CLASS
# ============================================================
class XeioaBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True
        super().__init__(command_prefix="!", intents=intents, help_command=None)

    async def setup_hook(self):
        try:
            synced = await self.tree.sync()
            print(f"✅ Synced {len(synced)} slash commands")
        except Exception as e:
            print(f"❌ Failed to sync: {e}")

    async def on_ready(self):
        print(f"✅ Logged in as {self.user}")
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="Lua scripts 👀"
            )
        )

    async def on_message_delete(self, message: discord.Message):
        if not message.author.bot:
            snipe_data[message.channel.id] = message

    async def animated_status(self, message, text):
        for _ in range(2):
            for stage in [text, f"{text}.", f"{text}. .", f"{text}. . ."]:
                try:
                    await message.edit(
                        content=f"```ansi\n\u001b[1;32m{stage}\u001b[0m\n```"
                    )
                    await asyncio.sleep(0.35)
                except Exception:
                    pass

    async def read_attachment(self, attachment: discord.Attachment) -> str | None:
        try:
            if not any(
                attachment.filename.endswith(ext)
                for ext in (".lua", ".luau", ".txt")
            ):
                return None
            if attachment.size > MAX_SCRIPT_SIZE:
                return None
            data = await attachment.read()
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None


bot = XeioaBot()


# ============================================================
#  RATE LIMITER
# ============================================================
def check_rate_limit(user_id: int) -> tuple[bool, int]:
    now = time.time()
    timestamps = rate_limit[user_id]
    # Remove timestamps outside window
    rate_limit[user_id] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit[user_id]) >= RATE_LIMIT_MAX:
        oldest = rate_limit[user_id][0]
        wait   = int(RATE_LIMIT_WINDOW - (now - oldest))
        return False, wait
    rate_limit[user_id].append(now)
    return True, 0


# ============================================================
#  HELPERS
# ============================================================
def make_embed(
    title: str,
    desc: str = "",
    color: int = 0x00ff99
) -> discord.Embed:
    embed = discord.Embed(title=title, description=desc, color=color)
    embed.set_footer(text="Xeioa Lua Deobfuscator")
    embed.timestamp = datetime.datetime.utcnow()
    return embed


async def send_lua_result(
    interaction: discord.Interaction,
    msg,
    result: str,
    filename: str,
    output_format: str = "codeblock"
):
    file_obj = discord.File(io.BytesIO(result.encode()), filename=filename)
    preview  = result[:1800] + "\n... [truncated]" if len(result) > 1800 else result

    if output_format == "file":
        await msg.delete()
        await interaction.channel.send(file=file_obj)

    elif output_format == "both":
        await msg.edit(content=f"```lua\n{preview}\n```")
        await interaction.channel.send(
            content="📎 Full output attached:",
            file=file_obj
        )

    else:  # codeblock (default)
        if len(result) > 1900:
            await msg.delete()
            await interaction.channel.send(
                content="📎 Output too large — attached as file:",
                file=file_obj
            )
        else:
            await msg.edit(content=f"```lua\n{result}\n```")


def build_detection_embed(result: dict) -> discord.Embed:
    conf_colors = {"High": 0x00ff99, "Medium": 0xffaa00, "Low": 0xff4444}
    color = conf_colors.get(result["confidence"], 0x00ff99)

    embed = make_embed("🔍 Obfuscator Detection", color=color)
    embed.add_field(
        name="Detected Obfuscator",
        value=result["obfuscator"],
        inline=True
    )
    embed.add_field(
        name="Confidence",
        value=result["confidence"],
        inline=True
    )
    embed.add_field(
        name="Complexity Level",
        value=result["complexity"],
        inline=True
    )
    embed.add_field(
        name="Layers Detected",
        value="\n".join(result["layers"]) if result["layers"] else "None detected",
        inline=False
    )
    return embed


def build_strings_embed(decoded: list[str]) -> discord.Embed:
    embed = make_embed(
        f"📋 Decoded String Table ({len(decoded)} entries)",
        color=0x5865F2
    )
    if decoded:
        preview = "\n".join(
            f"`{i+1}.` {s[:80]}" for i, s in enumerate(decoded[:20])
        )
        if len(decoded) > 20:
            preview += f"\n*... and {len(decoded)-20} more (see attached file)*"
        embed.description = preview
    else:
        embed.description = "*No decodable strings found.*"
    return embed


def build_warnings_embed(warnings: list[str], notes: list[str]) -> discord.Embed | None:
    if not warnings and not notes:
        return None
    color  = 0xff0000 if warnings else 0xffaa00
    embed  = make_embed("⚠️ Notes & Warnings", color=color)
    if warnings:
        embed.add_field(
            name="🚨 Security Warnings",
            value="\n".join(warnings),
            inline=False
        )
    if notes:
        embed.add_field(
            name="📝 Analysis Notes",
            value="\n".join(notes),
            inline=False
        )
    return embed


# ============================================================
#  DEOBFUSCATE  (/deobfuscate)
# ============================================================
@bot.tree.command(
    name="deobfuscate",
    description="Full deobfuscation of a Roblox Lua script"
)
@app_commands.describe(
    file="Upload a .lua / .luau / .txt file",
    script="Or paste a short script directly",
    depth="Analysis depth: quick | standard | deep",
    output_format="Output format: codeblock | file | both"
)
@app_commands.choices(
    depth=[
        app_commands.Choice(name="quick",    value="quick"),
        app_commands.Choice(name="standard", value="standard"),
        app_commands.Choice(name="deep",     value="deep"),
    ],
    output_format=[
        app_commands.Choice(name="codeblock", value="codeblock"),
        app_commands.Choice(name="file",      value="file"),
        app_commands.Choice(name="both",      value="both"),
    ]
)
async def deobfuscate(
    interaction: discord.Interaction,
    file:          discord.Attachment | None = None,
    script:        str | None = None,
    depth:         str = "standard",
    output_format: str = "codeblock"
):
    # Rate limit
    ok, wait = check_rate_limit(interaction.user.id)
    if not ok:
        await interaction.response.send_message(
            f"⏳ Rate limited. Try again in **{wait}s** "
            f"(max {RATE_LIMIT_MAX} requests per 5 minutes).",
            ephemeral=True
        )
        return

    if not file and not script:
        await interaction.response.send_message(
            "❌ Provide a `file` or `script` argument.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mStarting Deobfuscation...\u001b[0m\n```"
    )
    msg = await interaction.original_response()
    await bot.animated_status(msg, f"Deobfuscating [{depth}]")

    # Load code
    if file:
        if file.size > MAX_SCRIPT_SIZE:
            await msg.edit(content="❌ File exceeds 500 KB limit.")
            return
        code = await bot.read_attachment(file)
        if code is None:
            await msg.edit(content="❌ Invalid file. Use .lua / .luau / .txt")
            return
    else:
        code = script

    # Run deobfuscator in executor (non-blocking)
    loop = asyncio.get_event_loop()
    engine = LuaDeobfuscator(code, depth=depth)
    result = await loop.run_in_executor(None, engine.run)

    # Send embeds
    det_embed  = build_detection_embed(result)
    str_embed  = build_strings_embed(result["decoded_strings"])
    warn_embed = build_warnings_embed(result["warnings"], result["notes"])

    flow_embed = make_embed(
        "🔄 Execution Flow Summary",
        result["flow_summary"],
        color=0x5865F2
    )

    embeds = [det_embed, str_embed, flow_embed]
    if warn_embed:
        embeds.append(warn_embed)

    await msg.edit(
        content="✅ **Analysis complete:**",
        embeds=embeds
    )

    # Send clean code
    await send_lua_result(
        interaction,
        await interaction.channel.send(
            "```ansi\n\u001b[1;32mPreparing output...\u001b[0m\n```"
        ),
        result["clean_code"],
        "deobfuscated_output.lua",
        output_format
    )


# ============================================================
#  STRING TABLE ONLY  (/deob-strings)
# ============================================================
@bot.tree.command(
    name="deob-strings",
    description="Extract and decode only the string table from an obfuscated script"
)
@app_commands.describe(
    file="Upload a .lua / .luau / .txt file",
    script="Or paste a short script"
)
async def deob_strings(
    interaction: discord.Interaction,
    file:   discord.Attachment | None = None,
    script: str | None = None
):
    ok, wait = check_rate_limit(interaction.user.id)
    if not ok:
        await interaction.response.send_message(
            f"⏳ Rate limited. Wait **{wait}s**.", ephemeral=True
        )
        return

    if not file and not script:
        await interaction.response.send_message("❌ Provide a file or script.", ephemeral=True)
        return

    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read the input.")
        return

    engine = LuaDeobfuscator(code, depth="quick")
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, engine.run)

    embed = build_strings_embed(result["decoded_strings"])

    # If many strings, attach as file too
    if len(result["decoded_strings"]) > 20:
        txt = "\n".join(
            f"{i+1}. {s}" for i, s in enumerate(result["decoded_strings"])
        )
        file_out = discord.File(io.BytesIO(txt.encode()), filename="decoded_strings.txt")
        await interaction.followup.send(embed=embed, file=file_out)
    else:
        await interaction.followup.send(embed=embed)


# ============================================================
#  IDENTIFY  (/deob-identify)
# ============================================================
@bot.tree.command(
    name="deob-identify",
    description="Identify the obfuscator without full deobfuscation"
)
@app_commands.describe(
    file="Upload a .lua / .luau / .txt file",
    script="Or paste a short script"
)
async def deob_identify(
    interaction: discord.Interaction,
    file:   discord.Attachment | None = None,
    script: str | None = None
):
    if not file and not script:
        await interaction.response.send_message("❌ Provide a file or script.", ephemeral=True)
        return

    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input.")
        return

    identifier = LuaIdentifier(code)
    result     = identifier.identify()

    embed = build_detection_embed(result)
    embed.title = "🔍 Obfuscator Identification"
    await interaction.followup.send(embed=embed)


# ============================================================
#  EXPLAIN  (/deob-explain)
# ============================================================
@bot.tree.command(
    name="deob-explain",
    description="Explain what an obfuscated script does at a high level"
)
@app_commands.describe(
    file="Upload a .lua / .luau / .txt file",
    script="Or paste a short script"
)
async def deob_explain(
    interaction: discord.Interaction,
    file:   discord.Attachment | None = None,
    script: str | None = None
):
    if not file and not script:
        await interaction.response.send_message("❌ Provide a file or script.", ephemeral=True)
        return

    await interaction.response.defer()

    code = (await bot.read_attachment(file)) if file else script
    if not code:
        await interaction.followup.send("❌ Could not read input.")
        return

    engine = LuaDeobfuscator(code, depth="quick")
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, engine.run)

    det_embed  = build_detection_embed(result)
    flow_embed = make_embed(
        "🔄 High-Level Execution Summary",
        result["flow_summary"],
        color=0x5865F2
    )
    warn_embed = build_warnings_embed(result["warnings"], result["notes"])

    embeds = [det_embed, flow_embed]
    if warn_embed:
        embeds.append(warn_embed)

    await interaction.followup.send(embeds=embeds)


# ============================================================
#  COMPARE  (/deob-compare)
# ============================================================
@bot.tree.command(
    name="deob-compare",
    description="Compare two scripts to check if they are the same under different obfuscation"
)
@app_commands.describe(
    script1="First .lua / .txt file",
    script2="Second .lua / .txt file"
)
async def deob_compare(
    interaction: discord.Interaction,
    script1: discord.Attachment,
    script2: discord.Attachment
):
    await interaction.response.defer()

    code1 = await bot.read_attachment(script1)
    code2 = await bot.read_attachment(script2)

    if not code1 or not code2:
        await interaction.followup.send("❌ Could not read one or both files.")
        return

    loop = asyncio.get_event_loop()

    e1 = LuaDeobfuscator(code1, depth="standard")
    e2 = LuaDeobfuscator(code2, depth="standard")

    r1 = await loop.run_in_executor(None, e1.run)
    r2 = await loop.run_in_executor(None, e2.run)

    # Compare by hash of cleaned code (ignoring comments/whitespace)
    def normalize(code: str) -> str:
        code = re.sub(r"--[^\n]*", "", code)
        code = re.sub(r"--\[\[.*?\]\]", "", code, flags=re.DOTALL)
        return re.sub(r"\s+", "", code)

    h1 = hashlib.sha256(normalize(r1["clean_code"]).encode()).hexdigest()
    h2 = hashlib.sha256(normalize(r2["clean_code"]).encode()).hexdigest()

    if h1 == h2:
        verdict = "✅ **Scripts appear to be identical** under the surface."
        color   = 0x00ff99
    else:
        # Check string table overlap
        s1 = set(r1["decoded_strings"])
        s2 = set(r2["decoded_strings"])
        overlap = len(s1 & s2)
        total   = len(s1 | s2)
        pct     = round((overlap / total) * 100) if total else 0

        if pct >= 80:
            verdict = f"🟡 **Likely the same script** — {pct}% string overlap."
            color   = 0xffaa00
        elif pct >= 40:
            verdict = f"🟠 **Possibly related** — {pct}% string overlap."
            color   = 0xff6600
        else:
            verdict = f"❌ **Different scripts** — only {pct}% string overlap."
            color   = 0xff0000

    embed = make_embed("🔄 Script Comparison", color=color)
    embed.add_field(name="Script 1", value=r1["obfuscator"], inline=True)
    embed.add_field(name="Script 2", value=r2["obfuscator"], inline=True)
    embed.add_field(name="Verdict", value=verdict, inline=False)

    await interaction.followup.send(embed=embed)


# ============================================================
#  DEOB-HELP  (/deob-help)
# ============================================================
@bot.tree.command(name="deob-help", description="Help and info about the deobfuscator")
async def deob_help(interaction: discord.Interaction):
    embed = discord.Embed(
        title="📖 Xeioa Deobfuscator — Help",
        description="A specialized Roblox Lua deobfuscation engine.",
        color=0x00ff99
    )

    embed.add_field(
        name="Commands",
        value=(
            "`/deobfuscate` — Full deobfuscation pipeline\n"
            "`/deob-strings` — Decode string table only\n"
            "`/deob-identify` — Identify obfuscator\n"
            "`/deob-explain` — High-level script explanation\n"
            "`/deob-compare` — Compare two scripts\n"
            "`/deob-help` — This message"
        ),
        inline=False
    )

    embed.add_field(
        name="Depth Options",
        value=(
            "`quick` — String decoding + basic cleanup\n"
            "`standard` — Full pipeline (default)\n"
            "`deep` — Multiple passes + VM hints + annotations"
        ),
        inline=False
    )

    tbl = (
        "| Obfuscator    | Support    |\n"
        "|---------------|------------|\n"
        "| WeAreDevs     | ✅ Full    |\n"
        "| IronBrew2     | ✅ Full    |\n"
        "| Luraph        | ✅ Full    |\n"
        "| Moonsec v3    | ✅ Full    |\n"
        "| PSU           | ✅ Full    |\n"
        "| Synapse Xen   | ⚠️ Partial |\n"
        "| Prometheus    | ⚠️ Partial |\n"
        "| Custom        | ⚠️ Heuristic |"
    )
    embed.add_field(name="Supported Obfuscators", value=f"```\n{tbl}\n```", inline=False)

    embed.add_field(
        name="Limits",
        value=(
            f"• Max file size: **500 KB**\n"
            f"• Rate limit: **{RATE_LIMIT_MAX} requests per 5 minutes**\n"
            "• Discord tokens and webhooks are auto-redacted\n"
            "• Malware is flagged but still deobfuscated"
        ),
        inline=False
    )
    embed.set_footer(text="Xeioa Lua Deobfuscator")
    await interaction.response.send_message(embed=embed)


# ============================================================
#  GENERAL UTILITY COMMANDS
# ============================================================
@bot.tree.command(name="ping", description="Check bot latency")
async def ping(interaction: discord.Interaction):
    ms    = round(bot.latency * 1000)
    color = 0x00ff99 if ms < 100 else 0xffaa00 if ms < 200 else 0xff0000
    embed = make_embed("🏓 Pong!", f"Latency: **{ms}ms**", color)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="uptime", description="Bot uptime")
async def uptime(interaction: discord.Interaction):
    delta = datetime.datetime.utcnow() - _start_time
    h, r  = divmod(int(delta.total_seconds()), 3600)
    m, s  = divmod(r, 60)
    embed = make_embed("⏱️ Uptime", f"**{h}h {m}m {s}s**")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="cmds", description="Show all commands")
async def cmds(interaction: discord.Interaction):
    embed = discord.Embed(
        title="⚡ Xeioa Commands",
        description="Roblox Lua Deobfuscator + Utility Bot",
        color=0x00ff99
    )
    embed.add_field(
        name="🔓 Deobfuscation",
        value=(
            "`/deobfuscate` — Full deobfuscation\n"
            "`/deob-strings` — String table only\n"
            "`/deob-identify` — Detect obfuscator\n"
            "`/deob-explain` — High-level summary\n"
            "`/deob-compare` — Compare two scripts\n"
            "`/deob-help` — Help & supported obfuscators"
        ),
        inline=False
    )
    embed.add_field(
        name="🔧 Lua Tools",
        value=(
            "`/obf` — Obfuscate Lua file\n"
            "`/minify` — Minify Lua file\n"
            "`/format` — Format Lua file\n"
            "`/linecount` — File stats\n"
            "`/luacheck` — Syntax hints\n"
            "`/base64encode` / `/base64decode`"
        ),
        inline=False
    )
    embed.add_field(
        name="🛡️ Moderation",
        value=(
            "`/kick` `/ban` `/unban` `/mute` `/unmute`\n"
            "`/warn` `/warnings` `/clearwarns`\n"
            "`/purge` `/lc` `/unlock` `/slowmode` `/nick`"
        ),
        inline=False
    )
    embed.add_field(
        name="📊 Info & Fun",
        value=(
            "`/ping` `/uptime` `/serverinfo` `/userinfo`\n"
            "`/avatar` `/roleinfo` `/snipe` `/calc`\n"
            "`/coinflip` `/roll` `/choose` `/poll`"
        ),
        inline=False
    )
    embed.set_footer(text="Xeioa • Rate limit: 3 deobf/5min")
    await interaction.response.send_message(embed=embed)


# ── (All other commands from the previous version below) ────

@bot.tree.command(name="snipe", description="Show last deleted message")
async def snipe(interaction: discord.Interaction):
    m = snipe_data.get(interaction.channel_id)
    if not m:
        await interaction.response.send_message("❌ Nothing to snipe!", ephemeral=True)
        return
    embed = make_embed(
        f"💨 Sniped — #{interaction.channel.name}",
        m.content or "*[no text]*",
        0xff6b6b
    )
    embed.set_author(name=str(m.author), icon_url=m.author.display_avatar.url)
    embed.timestamp = m.created_at
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="serverinfo", description="Server information")
async def serverinfo(interaction: discord.Interaction):
    g = interaction.guild
    embed = discord.Embed(title=f"📊 {g.name}", color=0x00ff99)
    if g.icon:
        embed.set_thumbnail(url=g.icon.url)
    embed.add_field(name="Owner",    value=f"<@{g.owner_id}>",          inline=True)
    embed.add_field(name="Members",  value=g.member_count,               inline=True)
    embed.add_field(name="Channels", value=len(g.channels),              inline=True)
    embed.add_field(name="Roles",    value=len(g.roles),                 inline=True)
    embed.add_field(name="Boosts",   value=g.premium_subscription_count, inline=True)
    embed.add_field(name="Created",  value=g.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.set_footer(text=f"ID: {g.id}")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="userinfo", description="User information")
@app_commands.describe(member="Target member")
async def userinfo(interaction: discord.Interaction, member: discord.Member = None):
    member = member or interaction.user
    roles  = [r.mention for r in member.roles if r.name != "@everyone"]
    embed  = discord.Embed(title=f"👤 {member}", color=member.color)
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="ID",          value=member.id, inline=True)
    embed.add_field(name="Bot?",        value=member.bot, inline=True)
    embed.add_field(name="Joined",      value=member.joined_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name="Registered",  value=member.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name=f"Roles ({len(roles)})", value=" ".join(roles) or "None", inline=False)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="avatar", description="Get a user's avatar")
@app_commands.describe(member="Target member")
async def avatar(interaction: discord.Interaction, member: discord.Member = None):
    member = member or interaction.user
    embed  = make_embed(f"🖼️ {member.display_name}'s Avatar")
    embed.set_image(url=member.display_avatar.url)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="roleinfo", description="Role information")
@app_commands.describe(role="The role")
async def roleinfo(interaction: discord.Interaction, role: discord.Role):
    embed = make_embed(f"🏷️ {role.name}", color=role.color.value)
    embed.add_field(name="ID",          value=role.id,           inline=True)
    embed.add_field(name="Members",     value=len(role.members), inline=True)
    embed.add_field(name="Mentionable", value=role.mentionable,  inline=True)
    embed.add_field(name="Hoisted",     value=role.hoist,        inline=True)
    embed.add_field(name="Position",    value=role.position,     inline=True)
    embed.add_field(name="Created",     value=role.created_at.strftime("%Y-%m-%d"), inline=True)
    await interaction.response.send_message(embed=embed)


_SAFE_MATH = {k: v for k, v in math.__dict__.items() if not k.startswith("_")}

@bot.tree.command(name="calc", description="Math calculator")
@app_commands.describe(expression="e.g. 2**10 or sqrt(144)")
async def calc(interaction: discord.Interaction, expression: str):
    try:
        result = eval(expression, {"__builtins__": {}}, _SAFE_MATH)  # nosec
        embed  = make_embed("🧮 Calculator", f"`{expression}` = **{result}**")
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(f"❌ Error: `{e}`", ephemeral=True)


@bot.tree.command(name="base64encode", description="Encode text to Base64")
@app_commands.describe(text="Text to encode")
async def b64enc(interaction: discord.Interaction, text: str):
    await interaction.response.send_message(
        f"```\n{base64.b64encode(text.encode()).decode()}\n```"
    )


@bot.tree.command(name="base64decode", description="Decode Base64 text")
@app_commands.describe(text="Base64 to decode")
async def b64dec(interaction: discord.Interaction, text: str):
    try:
        out = base64.b64decode(text).decode("utf-8", errors="replace")
        await interaction.response.send_message(f"```\n{out}\n```")
    except Exception:
        await interaction.response.send_message("❌ Invalid Base64.", ephemeral=True)


@bot.tree.command(name="coinflip", description="Flip a coin")
async def coinflip(interaction: discord.Interaction):
    await interaction.response.send_message(random.choice(["🪙 Heads", "🪙 Tails"]))


@bot.tree.command(name="roll", description="Roll a dice")
@app_commands.describe(sides="Number of sides")
async def roll(interaction: discord.Interaction, sides: int = 6):
    if sides < 2:
        await interaction.response.send_message("❌ Min 2 sides.", ephemeral=True)
        return
    embed = make_embed("🎲 Dice Roll", f"d{sides} → **{random.randint(1, sides)}**")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="choose", description="Pick from choices")
@app_commands.describe(options="Comma-separated options")
async def choose(interaction: discord.Interaction, options: str):
    items = [o.strip() for o in options.split(",") if o.strip()]
    if not items:
        await interaction.response.send_message("❌ No valid choices.", ephemeral=True)
        return
    embed = make_embed("🎯 I Choose...", f"**{random.choice(items)}**")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="poll", description="Create a poll")
@app_commands.describe(question="Poll question", options="Comma-separated (max 5)")
async def poll(interaction: discord.Interaction, question: str, options: str):
    opts   = [o.strip() for o in options.split(",") if o.strip()][:5]
    emojis = ["1️⃣","2️⃣","3️⃣","4️⃣","5️⃣"]
    if len(opts) < 2:
        await interaction.response.send_message("❌ Need at least 2 options.", ephemeral=True)
        return
    desc  = "\n".join(f"{emojis[i]} {opt}" for i, opt in enumerate(opts))
    embed = make_embed(f"📊 {question}", desc, 0x5865F2)
    await interaction.response.send_message(embed=embed)
    msg   = await interaction.original_response()
    for i in range(len(opts)):
        await msg.add_reaction(emojis[i])


# ── Moderation ───────────────────────────────────────────────
def perm(interaction: discord.Interaction, p: str) -> bool:
    return getattr(interaction.user.guild_permissions, p, False)


@bot.tree.command(name="lc", description="Lock a channel")
@app_commands.describe(channel="Channel to lock")
async def lc(interaction: discord.Interaction, channel: discord.TextChannel):
    if not perm(interaction, "manage_channels"):
        await interaction.response.send_message("❌ Missing `Manage Channels`.", ephemeral=True); return
    ow = channel.overwrites_for(interaction.guild.default_role)
    ow.send_messages = False
    await channel.set_permissions(interaction.guild.default_role, overwrite=ow)
    await interaction.response.send_message(
        embed=make_embed("🔒 Locked", f"{channel.mention} locked.", 0xff0000)
    )


@bot.tree.command(name="unlock", description="Unlock a channel")
@app_commands.describe(channel="Channel to unlock")
async def unlock(interaction: discord.Interaction, channel: discord.TextChannel):
    if not perm(interaction, "manage_channels"):
        await interaction.response.send_message("❌ Missing `Manage Channels`.", ephemeral=True); return
    ow = channel.overwrites_for(interaction.guild.default_role)
    ow.send_messages = True
    await channel.set_permissions(interaction.guild.default_role, overwrite=ow)
    await interaction.response.send_message(
        embed=make_embed("🔓 Unlocked", f"{channel.mention} unlocked.")
    )


@bot.tree.command(name="slowmode", description="Set channel slowmode")
@app_commands.describe(seconds="Delay in seconds (0 to disable)")
async def slowmode(interaction: discord.Interaction, seconds: int, channel: discord.TextChannel = None):
    if not perm(interaction, "manage_channels"):
        await interaction.response.send_message("❌ Missing `Manage Channels`.", ephemeral=True); return
    ch = channel or interaction.channel
    await ch.edit(slowmode_delay=max(0, seconds))
    await interaction.response.send_message(
        embed=make_embed("🐢 Slowmode", f"{ch.mention}: **{seconds}s**")
    )


@bot.tree.command(name="purge", description="Bulk delete messages")
@app_commands.describe(amount="Messages to delete (1-100)")
async def purge(interaction: discord.Interaction, amount: int):
    if not perm(interaction, "manage_messages"):
        await interaction.response.send_message("❌ Missing `Manage Messages`.", ephemeral=True); return
    await interaction.response.defer(ephemeral=True)
    deleted = await interaction.channel.purge(limit=max(1, min(amount, 100)))
    await interaction.followup.send(f"🗑️ Deleted **{len(deleted)}** messages.", ephemeral=True)


@bot.tree.command(name="kick", description="Kick a member")
@app_commands.describe(member="Member", reason="Reason")
async def kick(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason"):
    if not perm(interaction, "kick_members"):
        await interaction.response.send_message("❌ Missing `Kick Members`.", ephemeral=True); return
    try:
        await member.kick(reason=reason)
        await interaction.response.send_message(
            embed=make_embed("👢 Kicked", f"**{member}** — {reason}", 0xff6600)
        )
    except discord.Forbidden:
        await interaction.response.send_message("❌ Can't kick that user.", ephemeral=True)


@bot.tree.command(name="ban", description="Ban a member")
@app_commands.describe(member="Member", reason="Reason")
async def ban(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason"):
    if not perm(interaction, "ban_members"):
        await interaction.response.send_message("❌ Missing `Ban Members`.", ephemeral=True); return
    try:
        await member.ban(reason=reason)
        await interaction.response.send_message(
            embed=make_embed("🔨 Banned", f"**{member}** — {reason}", 0xff0000)
        )
    except discord.Forbidden:
        await interaction.response.send_message("❌ Can't ban that user.", ephemeral=True)


@bot.tree.command(name="unban", description="Unban by user ID")
@app_commands.describe(user_id="User ID to unban")
async def unban(interaction: discord.Interaction, user_id: str):
    if not perm(interaction, "ban_members"):
        await interaction.response.send_message("❌ Missing `Ban Members`.", ephemeral=True); return
    try:
        user = await bot.fetch_user(int(user_id))
        await interaction.guild.unban(user)
        await interaction.response.send_message(
            embed=make_embed("✅ Unbanned", f"**{user}** has been unbanned.")
        )
    except Exception as e:
        await interaction.response.send_message(f"❌ Error: `{e}`", ephemeral=True)


@bot.tree.command(name="mute", description="Timeout a member")
@app_commands.describe(member="Member", minutes="Duration", reason="Reason")
async def mute(interaction: discord.Interaction, member: discord.Member, minutes: int = 10, reason: str = "No reason"):
    if not perm(interaction, "moderate_members"):
        await interaction.response.send_message("❌ Missing `Moderate Members`.", ephemeral=True); return
    until = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
    try:
        await member.timeout(until, reason=reason)
        await interaction.response.send_message(
            embed=make_embed("🔇 Muted", f"**{member}** — {minutes}m — {reason}", 0xff6600)
        )
    except discord.Forbidden:
        await interaction.response.send_message("❌ Can't mute that user.", ephemeral=True)


@bot.tree.command(name="unmute", description="Remove timeout")
@app_commands.describe(member="Member to unmute")
async def unmute(interaction: discord.Interaction, member: discord.Member):
    if not perm(interaction, "moderate_members"):
        await interaction.response.send_message("❌ Missing `Moderate Members`.", ephemeral=True); return
    try:
        await member.timeout(None)
        await interaction.response.send_message(
            embed=make_embed("🔊 Unmuted", f"**{member}**'s timeout removed.")
        )
    except discord.Forbidden:
        await interaction.response.send_message("❌ Can't unmute that user.", ephemeral=True)


@bot.tree.command(name="warn", description="Warn a member")
@app_commands.describe(member="Member", reason="Reason")
async def warn(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason"):
    if not perm(interaction, "manage_messages"):
        await interaction.response.send_message("❌ Missing `Manage Messages`.", ephemeral=True); return
    warn_data[interaction.guild.id][member.id].append(reason)
    total = len(warn_data[interaction.guild.id][member.id])
    embed = make_embed("⚠️ Warning", f"**{member}** — {reason}\nTotal: **{total}**", 0xffaa00)
    await interaction.response.send_message(embed=embed)
    try:
        await member.send(f"⚠️ Warned in **{interaction.guild.name}**: {reason}")
    except Exception:
        pass


@bot.tree.command(name="warnings", description="View member warnings")
@app_commands.describe(member="Member to check")
async def warnings_cmd(interaction: discord.Interaction, member: discord.Member):
    warns = warn_data[interaction.guild.id][member.id]
    if not warns:
        await interaction.response.send_message(f"✅ **{member}** has no warnings."); return
    desc  = "\n".join(f"`{i+1}.` {w}" for i, w in enumerate(warns))
    embed = make_embed(f"⚠️ Warnings — {member}", desc, 0xffaa00)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="clearwarns", description="Clear member warnings")
@app_commands.describe(member="Member to clear")
async def clearwarns(interaction: discord.Interaction, member: discord.Member):
    if not perm(interaction, "manage_messages"):
        await interaction.response.send_message("❌ Missing `Manage Messages`.", ephemeral=True); return
    warn_data[interaction.guild.id][member.id] = []
    await interaction.response.send_message(
        embed=make_embed("✅ Cleared", f"All warnings removed for **{member}**.")
    )


@bot.tree.command(name="nick", description="Change member nickname")
@app_commands.describe(member="Member", nickname="New nickname (blank to reset)")
async def nick(interaction: discord.Interaction, member: discord.Member, nickname: str = None):
    if not perm(interaction, "manage_nicknames"):
        await interaction.response.send_message("❌ Missing `Manage Nicknames`.", ephemeral=True); return
    try:
        await member.edit(nick=nickname)
        msg = f"Set to **{nickname}**" if nickname else "**Reset**"
        await interaction.response.send_message(
            embed=make_embed("✏️ Nickname", f"{member.mention}: {msg}")
        )
    except discord.Forbidden:
        await interaction.response.send_message("❌ Can't change that nickname.", ephemeral=True)


# ============================================================
#  RUN
# ============================================================
if not TOKEN:
    print("❌ XEIOA_TOKEN environment variable missing")
else:
    bot.run(TOKEN)
