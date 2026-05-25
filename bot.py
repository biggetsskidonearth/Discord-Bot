import io
import os
import re
import time
import math
import base64
import random
import string
import asyncio
import datetime
import discord
from discord.ext import commands
from discord import app_commands
from collections import defaultdict

TOKEN = os.getenv("XEIOA_TOKEN")

# ============================================================
#  COOLDOWN / WARN STORAGE (in-memory)
# ============================================================
warn_data: dict[int, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
# warn_data[guild_id][user_id] = ["reason1", "reason2", ...]

snipe_data: dict[int, discord.Message] = {}
# snipe_data[channel_id] = last deleted message


# ============================================================
#  BOT CLASS
# ============================================================
class XeioaBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True

        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None
        )

    async def setup_hook(self):
        try:
            synced = await self.tree.sync()
            print(f"✅ Synced {len(synced)} slash commands")
        except Exception as e:
            print(f"❌ Failed to sync commands: {e}")

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
        stages = [text, f"{text}.", f"{text}. .", f"{text}. . ."]
        for _ in range(2):
            for stage in stages:
                try:
                    await message.edit(
                        content=f"```ansi\n\u001b[1;32m{stage}\u001b[0m\n```"
                    )
                    await asyncio.sleep(0.4)
                except Exception:
                    pass

    def random_var(self):
        chars = string.ascii_letters + "Il"
        return ''.join(
            random.choice(chars)
            for _ in range(random.randint(15, 30))
        )

    async def read_attachment(self, attachment):
        try:
            allowed = (
                attachment.filename.endswith(".lua")
                or attachment.filename.endswith(".luau")
                or attachment.filename.endswith(".txt")
            )
            if not allowed:
                return None
            data = await attachment.read()
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None

    # ── Obfuscation ──────────────────────────────────────────
    def advanced_obfuscate(self, code: str) -> str:
        variables = set(re.findall(r"\blocal\s+([a-zA-Z_][a-zA-Z0-9_]*)", code))
        replacements = {var: self.random_var() for var in variables}

        for old, new in replacements.items():
            code = re.sub(rf"\b{re.escape(old)}\b", new, code)

        def string_to_char(match):
            s = match.group(1)
            encoded = ",".join(str(ord(c)) for c in s)
            return f"string.char({encoded})"

        code = re.sub(r'"([^"\n]+)"', string_to_char, code)

        encoded = base64.b64encode(code.encode()).decode()
        wrapper = f'''local data = "{encoded}"
local decoded = game:GetService("HttpService"):Base64Decode(data)
loadstring(decoded)()'''
        return wrapper.strip()

    # ── Deobfuscation ────────────────────────────────────────
    def advanced_deobfuscate(self, code: str) -> str:
        code = re.sub(r";+", ";", code)

        def repl(match):
            try:
                nums = match.group(1).split(",")
                return '"' + ''.join(chr(int(n.strip())) for n in nums) + '"'
            except Exception:
                return match.group(0)

        code = re.sub(r"string\.char\((.*?)\)", repl, code)
        code = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), code)
        code = re.sub(
            r"\\([0-9]{1,3})",
            lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0),
            code
        )
        return code.strip()

    # ── Lua minifier ─────────────────────────────────────────
    def minify_lua(self, code: str) -> str:
        # Remove single-line comments
        code = re.sub(r"--[^\n]*", "", code)
        # Remove multi-line comments
        code = re.sub(r"--\[\[.*?\]\]", "", code, flags=re.DOTALL)
        # Collapse whitespace / blank lines
        lines = [line.strip() for line in code.splitlines() if line.strip()]
        return " ".join(lines)

    # ── Lua formatter (basic) ─────────────────────────────────
    def format_lua(self, code: str) -> str:
        indent = 0
        result = []
        keywords_open  = {"do", "then", "function", "repeat", "else", "elseif"}
        keywords_close = {"end", "until", "else", "elseif"}

        for line in code.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            first_word = stripped.split()[0] if stripped.split() else ""

            if first_word in keywords_close:
                indent = max(0, indent - 1)

            result.append("    " * indent + stripped)

            if (
                first_word in keywords_open
                or stripped.endswith("do")
                or stripped.endswith("then")
                or re.match(r"function\s", stripped)
            ):
                indent += 1

        return "\n".join(result)


bot = XeioaBot()


# ============================================================
#  HELPER
# ============================================================
def perm_check(interaction: discord.Interaction, perm: str) -> bool:
    return getattr(interaction.user.guild_permissions, perm, False)


def make_embed(title: str, desc: str, color: int = 0x00ff99) -> discord.Embed:
    embed = discord.Embed(title=title, description=desc, color=color)
    embed.set_footer(text="Xeioa Bot")
    embed.timestamp = datetime.datetime.utcnow()
    return embed


# ============================================================
#  /cmds
# ============================================================
@bot.tree.command(name="cmds", description="Show all commands")
async def cmds(interaction: discord.Interaction):
    embed = discord.Embed(
        title="⚡ Xeioa Commands ⚡",
        description="Advanced Roblox Lua Utility + Moderation Bot",
        color=0x00ff99
    )

    categories = {
        "🔧 Lua Tools": [
            ("/obf `<file>`",        "Obfuscate a Lua file"),
            ("/deobf `<file>`",      "Deobfuscate a Lua file"),
            ("/minify `<file>`",     "Minify a Lua file"),
            ("/format `<file>`",     "Auto-format a Lua file"),
            ("/linecount `<file>`",  "Count lines in a Lua file"),
            ("/luacheck `<code>`",   "Quick syntax check snippet"),
        ],
        "🛡️ Moderation": [
            ("/lc `<channel>`",      "Lock a channel"),
            ("/unlock `<channel>`",  "Unlock a channel"),
            ("/kick `<user>`",       "Kick a member"),
            ("/ban `<user>`",        "Ban a member"),
            ("/unban `<id>`",        "Unban by user ID"),
            ("/mute `<user>`",       "Timeout a member"),
            ("/unmute `<user>`",     "Remove timeout"),
            ("/purge `<amount>`",    "Bulk delete messages"),
            ("/warn `<user>`",       "Warn a member"),
            ("/warnings `<user>`",   "View a member's warnings"),
            ("/clearwarns `<user>`", "Clear a member's warnings"),
            ("/slowmode `<secs>`",   "Set channel slowmode"),
            ("/nick `<user>`",       "Change a member's nickname"),
        ],
        "📊 Info / Utility": [
            ("/ping",                "Bot latency"),
            ("/serverinfo",          "Server information"),
            ("/userinfo `<user>`",   "User information"),
            ("/avatar `<user>`",     "Get a user's avatar"),
            ("/roleinfo `<role>`",   "Role information"),
            ("/snipe",               "Show last deleted message"),
            ("/calc `<expr>`",       "Math calculator"),
            ("/base64encode `<t>`",  "Encode text to Base64"),
            ("/base64decode `<t>`",  "Decode Base64 text"),
            ("/coinflip",            "Flip a coin"),
            ("/roll `<sides>`",      "Roll a dice"),
            ("/choose `<opts>`",     "Pick from choices"),
            ("/uptime",              "Bot uptime"),
            ("/poll `<q>` `<opts>`", "Create a quick poll"),
        ],
    }

    for cat, fields in categories.items():
        value = "\n".join(f"`{name}` — {desc}" for name, desc in fields)
        embed.add_field(name=cat, value=value, inline=False)

    embed.set_footer(text="Xeioa Utility + Lua Bot")
    await interaction.response.send_message(embed=embed)


# ============================================================
#  PING
# ============================================================
@bot.tree.command(name="ping", description="Check bot latency")
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    color = 0x00ff99 if latency < 100 else 0xffaa00 if latency < 200 else 0xff0000
    embed = make_embed("🏓 Pong!", f"Latency: **{latency}ms**", color)
    await interaction.response.send_message(embed=embed)


# ============================================================
#  UPTIME
# ============================================================
_start_time = datetime.datetime.utcnow()

@bot.tree.command(name="uptime", description="Show bot uptime")
async def uptime(interaction: discord.Interaction):
    delta = datetime.datetime.utcnow() - _start_time
    hours, remainder = divmod(int(delta.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    embed = make_embed("⏱️ Uptime", f"**{hours}h {minutes}m {seconds}s**")
    await interaction.response.send_message(embed=embed)


# ============================================================
#  LUA TOOLS
# ============================================================
async def _send_lua_result(interaction, msg, result, filename):
    if len(result) < 1900:
        await msg.edit(content=f"```lua\n{result}\n```")
    else:
        output = discord.File(io.BytesIO(result.encode()), filename=filename)
        await msg.delete()
        await interaction.channel.send(file=output)


@bot.tree.command(name="deobf", description="Deobfuscate Lua code")
@app_commands.describe(file="Upload .lua .luau or .txt file")
async def deobf(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mStarting Deobfuscation...\u001b[0m\n```"
    )
    msg = await interaction.original_response()
    await bot.animated_status(msg, "Deobfuscating")
    code = await bot.read_attachment(file)
    if not code:
        await msg.edit(content="❌ Invalid file. Use .lua / .luau / .txt")
        return
    result = bot.advanced_deobfuscate(code)
    await _send_lua_result(interaction, msg, result, "deobfuscated.lua")


@bot.tree.command(name="obf", description="Obfuscate Lua code")
@app_commands.describe(file="Upload .lua .luau or .txt file")
async def obf(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mStarting Obfuscation...\u001b[0m\n```"
    )
    msg = await interaction.original_response()
    await bot.animated_status(msg, "Obfuscating")
    code = await bot.read_attachment(file)
    if not code:
        await msg.edit(content="❌ Invalid file. Use .lua / .luau / .txt")
        return
    result = bot.advanced_obfuscate(code)
    await _send_lua_result(interaction, msg, result, "obfuscated.lua")


@bot.tree.command(name="minify", description="Minify a Lua file")
@app_commands.describe(file="Upload .lua .luau or .txt file")
async def minify(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mMinifying...\u001b[0m\n```"
    )
    msg = await interaction.original_response()
    await bot.animated_status(msg, "Minifying")
    code = await bot.read_attachment(file)
    if not code:
        await msg.edit(content="❌ Invalid file.")
        return
    result = bot.minify_lua(code)
    await _send_lua_result(interaction, msg, result, "minified.lua")


@bot.tree.command(name="format", description="Auto-format a Lua file")
@app_commands.describe(file="Upload .lua .luau or .txt file")
async def format_cmd(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mFormatting...\u001b[0m\n```"
    )
    msg = await interaction.original_response()
    await bot.animated_status(msg, "Formatting")
    code = await bot.read_attachment(file)
    if not code:
        await msg.edit(content="❌ Invalid file.")
        return
    result = bot.format_lua(code)
    await _send_lua_result(interaction, msg, result, "formatted.lua")


@bot.tree.command(name="linecount", description="Count lines / chars in a Lua file")
@app_commands.describe(file="Upload .lua .luau or .txt file")
async def linecount(interaction: discord.Interaction, file: discord.Attachment):
    code = await bot.read_attachment(file)
    if not code:
        await interaction.response.send_message("❌ Invalid file.", ephemeral=True)
        return
    lines = code.splitlines()
    embed = make_embed(
        "📄 File Stats",
        f"**Lines:** {len(lines)}\n"
        f"**Characters:** {len(code)}\n"
        f"**Words:** {len(code.split())}\n"
        f"**File:** `{file.filename}`"
    )
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="luacheck", description="Quick Lua snippet syntax hint")
@app_commands.describe(code="Paste a short Lua snippet")
async def luacheck(interaction: discord.Interaction, code: str):
    issues = []
    opens  = len(re.findall(r"\bfunction\b|\bdo\b|\bthen\b", code))
    closes = len(re.findall(r"\bend\b", code))
    if opens > closes:
        issues.append(f"⚠️ Possibly missing `end` ({opens} open vs {closes} close)")
    if re.search(r'print\s+[^(]', code):
        issues.append("⚠️ `print` used without parentheses")
    if not issues:
        issues.append("✅ No obvious issues found")
    embed = make_embed("🔍 Lua Syntax Check", "\n".join(issues))
    await interaction.response.send_message(embed=embed)


# ============================================================
#  BASE64
# ============================================================
@bot.tree.command(name="base64encode", description="Encode text to Base64")
@app_commands.describe(text="Text to encode")
async def b64encode(interaction: discord.Interaction, text: str):
    result = base64.b64encode(text.encode()).decode()
    await interaction.response.send_message(f"```\n{result}\n```")


@bot.tree.command(name="base64decode", description="Decode Base64 text")
@app_commands.describe(text="Base64 string to decode")
async def b64decode(interaction: discord.Interaction, text: str):
    try:
        result = base64.b64decode(text.encode()).decode("utf-8", errors="replace")
        await interaction.response.send_message(f"```\n{result}\n```")
    except Exception:
        await interaction.response.send_message("❌ Invalid Base64 string.", ephemeral=True)


# ============================================================
#  CALCULATOR
# ============================================================
_SAFE_NAMES = {k: v for k, v in math.__dict__.items() if not k.startswith("_")}

@bot.tree.command(name="calc", description="Math calculator")
@app_commands.describe(expression="Math expression e.g. 2**10 or sqrt(144)")
async def calc(interaction: discord.Interaction, expression: str):
    try:
        result = eval(expression, {"__builtins__": {}}, _SAFE_NAMES)  # nosec
        embed = make_embed("🧮 Calculator", f"`{expression}` = **{result}**")
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(f"❌ Error: `{e}`", ephemeral=True)


# ============================================================
#  FUN / UTILITY
# ============================================================
@bot.tree.command(name="coinflip", description="Flip a coin")
async def coinflip(interaction: discord.Interaction):
    result = random.choice(["🪙 Heads", "🪙 Tails"])
    await interaction.response.send_message(result)


@bot.tree.command(name="roll", description="Roll a dice")
@app_commands.describe(sides="Number of sides (default 6)")
async def roll(interaction: discord.Interaction, sides: int = 6):
    if sides < 2:
        await interaction.response.send_message("❌ Minimum 2 sides.", ephemeral=True)
        return
    result = random.randint(1, sides)
    embed = make_embed("🎲 Dice Roll", f"Rolling a **d{sides}**... you got **{result}**!")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="choose", description="Pick from a list of choices")
@app_commands.describe(options="Choices separated by commas")
async def choose(interaction: discord.Interaction, options: str):
    choices = [c.strip() for c in options.split(",") if c.strip()]
    if not choices:
        await interaction.response.send_message("❌ No valid choices.", ephemeral=True)
        return
    picked = random.choice(choices)
    embed = make_embed("🎯 I Choose...", f"**{picked}**")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="poll", description="Create a quick poll")
@app_commands.describe(
    question="The poll question",
    options="Comma-separated options (max 5)"
)
async def poll(interaction: discord.Interaction, question: str, options: str):
    opts = [o.strip() for o in options.split(",") if o.strip()][:5]
    if len(opts) < 2:
        await interaction.response.send_message("❌ Provide at least 2 options.", ephemeral=True)
        return

    emojis = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣"]
    desc = "\n".join(f"{emojis[i]} {opt}" for i, opt in enumerate(opts))
    embed = make_embed(f"📊 {question}", desc, 0x5865F2)
    embed.set_footer(text=f"Poll by {interaction.user.display_name}")

    await interaction.response.send_message(embed=embed)
    msg = await interaction.original_response()
    for i in range(len(opts)):
        await msg.add_reaction(emojis[i])


# ============================================================
#  SNIPE
# ============================================================
@bot.tree.command(name="snipe", description="Show the last deleted message")
async def snipe(interaction: discord.Interaction):
    msg = snipe_data.get(interaction.channel_id)
    if not msg:
        await interaction.response.send_message("❌ Nothing to snipe!", ephemeral=True)
        return
    embed = make_embed(
        f"💨 Sniped from #{interaction.channel.name}",
        msg.content or "*[no text content]*",
        0xff6b6b
    )
    embed.set_author(name=str(msg.author), icon_url=msg.author.display_avatar.url)
    embed.timestamp = msg.created_at
    await interaction.response.send_message(embed=embed)


# ============================================================
#  SERVER INFO
# ============================================================
@bot.tree.command(name="serverinfo", description="Server information")
async def serverinfo(interaction: discord.Interaction):
    g = interaction.guild
    embed = discord.Embed(title=f"📊 {g.name}", color=0x00ff99)
    embed.set_thumbnail(url=g.icon.url if g.icon else discord.Embed.Empty)
    embed.add_field(name="Owner",       value=f"<@{g.owner_id}>",     inline=True)
    embed.add_field(name="Members",     value=g.member_count,          inline=True)
    embed.add_field(name="Channels",    value=len(g.channels),         inline=True)
    embed.add_field(name="Roles",       value=len(g.roles),            inline=True)
    embed.add_field(name="Boosts",      value=g.premium_subscription_count, inline=True)
    embed.add_field(name="Created",     value=g.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.set_footer(text=f"ID: {g.id}")
    await interaction.response.send_message(embed=embed)


# ============================================================
#  USER INFO
# ============================================================
@bot.tree.command(name="userinfo", description="User information")
@app_commands.describe(member="Target member (default: yourself)")
async def userinfo(interaction: discord.Interaction, member: discord.Member = None):
    member = member or interaction.user
    roles = [r.mention for r in member.roles if r.name != "@everyone"]
    embed = discord.Embed(title=f"👤 {member}", color=member.color)
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="ID",         value=member.id,                        inline=True)
    embed.add_field(name="Bot?",       value=member.bot,                       inline=True)
    embed.add_field(name="Joined",     value=member.joined_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name="Registered", value=member.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name=f"Roles ({len(roles)})", value=" ".join(roles) or "None", inline=False)
    await interaction.response.send_message(embed=embed)


# ============================================================
#  AVATAR
# ============================================================
@bot.tree.command(name="avatar", description="Get a user's avatar")
@app_commands.describe(member="Target member")
async def avatar(interaction: discord.Interaction, member: discord.Member = None):
    member = member or interaction.user
    embed = discord.Embed(title=f"🖼️ {member.display_name}'s Avatar", color=0x00ff99)
    embed.set_image(url=member.display_avatar.url)
    await interaction.response.send_message(embed=embed)


# ============================================================
#  ROLE INFO
# ============================================================
@bot.tree.command(name="roleinfo", description="Role information")
@app_commands.describe(role="The role to inspect")
async def roleinfo(interaction: discord.Interaction, role: discord.Role):
    embed = discord.Embed(title=f"🏷️ {role.name}", color=role.color)
    embed.add_field(name="ID",          value=role.id,             inline=True)
    embed.add_field(name="Members",     value=len(role.members),   inline=True)
    embed.add_field(name="Mentionable", value=role.mentionable,    inline=True)
    embed.add_field(name="Hoisted",     value=role.hoist,          inline=True)
    embed.add_field(name="Position",    value=role.position,       inline=True)
    embed.add_field(name="Created",     value=role.created_at.strftime("%Y-%m-%d"), inline=True)
    await interaction.response.send_message(embed=embed)


# ============================================================
#  MODERATION
# ============================================================
@bot.tree.command(name="lc", description="Lock a channel")
@app_commands.describe(channel="Channel to lock")
async def lc(interaction: discord.Interaction, channel: discord.TextChannel):
    if not perm_check(interaction, "manage_channels"):
        await interaction.response.send_message("❌ Missing `Manage Channels`.", ephemeral=True)
        return
    ow = channel.overwrites_for(interaction.guild.default_role)
    ow.send_messages = False
    await channel.set_permissions(interaction.guild.default_role, overwrite=ow)
    embed = make_embed("🔒 Channel Locked", f"{channel.mention} has been **locked**.", 0xff0000)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="unlock", description="Unlock a channel")
@app_commands.describe(channel="Channel to unlock")
async def unlock(interaction: discord.Interaction, channel: discord.TextChannel):
    if not perm_check(interaction, "manage_channels"):
        await interaction.response.send_message("❌ Missing `Manage Channels`.", ephemeral=True)
        return
    ow = channel.overwrites_for(interaction.guild.default_role)
    ow.send_messages = True
    await channel.set_permissions(interaction.guild.default_role, overwrite=ow)
    embed = make_embed("🔓 Channel Unlocked", f"{channel.mention} has been **unlocked**.")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="slowmode", description="Set channel slowmode")
@app_commands.describe(seconds="Seconds (0 to disable)", channel="Target channel")
async def slowmode(interaction: discord.Interaction, seconds: int, channel: discord.TextChannel = None):
    if not perm_check(interaction, "manage_channels"):
        await interaction.response.send_message("❌ Missing `Manage Channels`.", ephemeral=True)
        return
    channel = channel or interaction.channel
    await channel.edit(slowmode_delay=max(0, seconds))
    msg = f"Slowmode set to **{seconds}s**" if seconds else "Slowmode **disabled**"
    embed = make_embed("🐢 Slowmode", f"{channel.mention}: {msg}")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="purge", description="Bulk delete messages")
@app_commands.describe(amount="Number of messages to delete (1-100)")
async def purge(interaction: discord.Interaction, amount: int):
    if not perm_check(interaction, "manage_messages"):
        await interaction.response.send_message("❌ Missing `Manage Messages`.", ephemeral=True)
        return
    amount = max(1, min(amount, 100))
    await interaction.response.defer(ephemeral=True)
    deleted = await interaction.channel.purge(limit=amount)
    await interaction.followup.send(f"🗑️ Deleted **{len(deleted)}** messages.", ephemeral=True)


@bot.tree.command(name="kick", description="Kick a member")
@app_commands.describe(member="Member to kick", reason="Reason")
async def kick(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not perm_check(interaction, "kick_members"):
        await interaction.response.send_message("❌ Missing `Kick Members`.", ephemeral=True)
        return
    try:
        await member.kick(reason=reason)
        embed = make_embed("👢 Kicked", f"**{member}** was kicked.\n**Reason:** {reason}", 0xff6600)
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I can't kick that user.", ephemeral=True)


@bot.tree.command(name="ban", description="Ban a member")
@app_commands.describe(member="Member to ban", reason="Reason")
async def ban(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not perm_check(interaction, "ban_members"):
        await interaction.response.send_message("❌ Missing `Ban Members`.", ephemeral=True)
        return
    try:
        await member.ban(reason=reason)
        embed = make_embed("🔨 Banned", f"**{member}** was banned.\n**Reason:** {reason}", 0xff0000)
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I can't ban that user.", ephemeral=True)


@bot.tree.command(name="unban", description="Unban a user by ID")
@app_commands.describe(user_id="The user's ID")
async def unban(interaction: discord.Interaction, user_id: str):
    if not perm_check(interaction, "ban_members"):
        await interaction.response.send_message("❌ Missing `Ban Members`.", ephemeral=True)
        return
    try:
        uid = int(user_id)
        user = await bot.fetch_user(uid)
        await interaction.guild.unban(user)
        embed = make_embed("✅ Unbanned", f"**{user}** has been unbanned.")
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(f"❌ Error: `{e}`", ephemeral=True)


@bot.tree.command(name="mute", description="Timeout (mute) a member")
@app_commands.describe(member="Member to mute", minutes="Duration in minutes", reason="Reason")
async def mute(interaction: discord.Interaction, member: discord.Member, minutes: int = 10, reason: str = "No reason"):
    if not perm_check(interaction, "moderate_members"):
        await interaction.response.send_message("❌ Missing `Moderate Members`.", ephemeral=True)
        return
    until = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
    try:
        await member.timeout(until, reason=reason)
        embed = make_embed(
            "🔇 Muted",
            f"**{member}** timed out for **{minutes}m**.\n**Reason:** {reason}",
            0xff6600
        )
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I can't mute that user.", ephemeral=True)


@bot.tree.command(name="unmute", description="Remove timeout from a member")
@app_commands.describe(member="Member to unmute")
async def unmute(interaction: discord.Interaction, member: discord.Member):
    if not perm_check(interaction, "moderate_members"):
        await interaction.response.send_message("❌ Missing `Moderate Members`.", ephemeral=True)
        return
    try:
        await member.timeout(None)
        embed = make_embed("🔊 Unmuted", f"**{member}**'s timeout has been removed.")
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I can't unmute that user.", ephemeral=True)


@bot.tree.command(name="warn", description="Warn a member")
@app_commands.describe(member="Member to warn", reason="Reason for warning")
async def warn(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason"):
    if not perm_check(interaction, "manage_messages"):
        await interaction.response.send_message("❌ Missing `Manage Messages`.", ephemeral=True)
        return
    warn_data[interaction.guild.id][member.id].append(reason)
    total = len(warn_data[interaction.guild.id][member.id])
    embed = make_embed(
        "⚠️ Warning Issued",
        f"**{member}** warned.\n**Reason:** {reason}\n**Total Warnings:** {total}",
        0xffaa00
    )
    await interaction.response.send_message(embed=embed)
    try:
        await member.send(
            f"⚠️ You were warned in **{interaction.guild.name}**\n**Reason:** {reason}"
        )
    except Exception:
        pass


@bot.tree.command(name="warnings", description="View a member's warnings")
@app_commands.describe(member="Member to check")
async def warnings(interaction: discord.Interaction, member: discord.Member):
    warns = warn_data[interaction.guild.id][member.id]
    if not warns:
        await interaction.response.send_message(f"✅ **{member}** has no warnings.")
        return
    listed = "\n".join(f"`{i+1}.` {w}" for i, w in enumerate(warns))
    embed = make_embed(f"⚠️ Warnings for {member}", listed, 0xffaa00)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="clearwarns", description="Clear all warnings for a member")
@app_commands.describe(member="Member to clear")
async def clearwarns(interaction: discord.Interaction, member: discord.Member):
    if not perm_check(interaction, "manage_messages"):
        await interaction.response.send_message("❌ Missing `Manage Messages`.", ephemeral=True)
        return
    warn_data[interaction.guild.id][member.id] = []
    embed = make_embed("✅ Warnings Cleared", f"All warnings for **{member}** have been removed.")
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="nick", description="Change a member's nickname")
@app_commands.describe(member="Target member", nickname="New nickname (leave blank to reset)")
async def nick(interaction: discord.Interaction, member: discord.Member, nickname: str = None):
    if not perm_check(interaction, "manage_nicknames"):
        await interaction.response.send_message("❌ Missing `Manage Nicknames`.", ephemeral=True)
        return
    try:
        await member.edit(nick=nickname)
        msg = f"Nickname set to **{nickname}**" if nickname else "Nickname **reset**"
        embed = make_embed("✏️ Nickname Changed", f"{member.mention}: {msg}")
        await interaction.response.send_message(embed=embed)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I can't change that user's nickname.", ephemeral=True)


# ============================================================
#  RUN
# ============================================================
if not TOKEN:
    print("❌ XEIOA_TOKEN environment variable missing")
else:
    bot.run(TOKEN)
