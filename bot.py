import io
import os
import re
import base64
import random
import string
import asyncio
import discord
from discord.ext import commands
from discord import app_commands

class XeioaBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True

        super().__init__(
            command_prefix="/",
            intents=intents,
            help_command=None
        )

    async def setup_hook(self):
        await self.tree.sync()
        print("Slash commands synced")

    async def on_ready(self):
        print(f"Logged in as {self.user}")

    async def animated_status(self, msg, text):
        stages = [
            f"{text}",
            f"{text}.",
            f"{text}. .",
            f"{text}. . ."
        ]

        for _ in range(3):
            for stage in stages:
                await msg.edit(content=f"```ansi\n\u001b[1;32m{stage}\u001b[0m\n```")
                await asyncio.sleep(0.4)

    async def get_code_input(self, interaction, code):
        if code:
            return code

        if interaction.attachments:
            attachment = interaction.attachments[0]

            allowed = (
                attachment.filename.endswith(".lua")
                or attachment.filename.endswith(".luau")
                or attachment.filename.endswith(".txt")
            )

            if not allowed:
                await interaction.response.send_message(
                    "Only `.lua`, `.luau`, and `.txt` files are supported.",
                    ephemeral=True
                )
                return None

            data = await attachment.read()

            return data.decode("utf-8", errors="ignore")

        await interaction.response.send_message(
            "Provide code or upload a file.",
            ephemeral=True
        )

        return None

    def random_var(self):
        chars = string.ascii_letters + "Il"

        return ''.join(
            random.choice(chars)
            for _ in range(random.randint(15, 30))
        )

    def advanced_obfuscate(self, code: str) -> str:
        variables = set(
            re.findall(
                r"\blocal\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                code
            )
        )

        replacements = {}

        for var in variables:
            replacements[var] = self.random_var()

        for old, new in replacements.items():
            code = re.sub(
                rf"\b{re.escape(old)}\b",
                new,
                code
            )

        string_pattern = r'"([^"\n]+)"'

        def string_to_char(match):
            s = match.group(1)

            encoded = ",".join(
                str(ord(c))
                for c in s
            )

            return f"string.char({encoded})"

        code = re.sub(
            string_pattern,
            string_to_char,
            code
        )

        encoded = base64.b64encode(
            code.encode()
        ).decode()

        wrapper = f'''
local data = "{encoded}"

local decoded = game:GetService("HttpService"):Base64Decode(data)

loadstring(decoded)()
'''

        return wrapper.strip()

    def advanced_deobfuscate(self, code: str) -> str:
        code = re.sub(r";+", ";", code)

        pattern = r"string\.char\((.*?)\)"

        def repl(match):
            try:
                nums = match.group(1).split(",")

                chars = ''.join(
                    chr(int(n.strip()))
                    for n in nums
                )

                return f'"{chars}"'

            except:
                return match.group(0)

        code = re.sub(pattern, repl, code)

        code = re.sub(
            r"\\x([0-9A-Fa-f]{2})",
            lambda m: chr(int(m.group(1), 16)),
            code
        )

        code = re.sub(
            r"\\([0-9]{1,3})",
            lambda m: chr(int(m.group(1)))
            if int(m.group(1)) < 256
            else m.group(0),
            code
        )

        return code.strip()


bot = XeioaBot()


@bot.tree.command(name="cmds", description="Show all commands")
async def cmds(interaction: discord.Interaction):
    embed = discord.Embed(
        title="⚡ Xeioa Commands ⚡",
        description="Advanced Roblox Lua Utility Bot",
        color=0x00ff99
    )

    embed.add_field(
        name="/deobf",
        value="Deobfuscate Lua/Luau code or uploaded files",
        inline=False
    )

    embed.add_field(
        name="/obf",
        value="Obfuscate Lua/Luau code",
        inline=False
    )

    embed.add_field(
        name="/lc",
        value="Lock a channel so normal users cannot type",
        inline=False
    )

    embed.add_field(
        name="/ping",
        value="Check bot latency",
        inline=False
    )

    embed.set_footer(text="Xeioa Deobfr")

    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="ping", description="Ping the bot")
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)

    await interaction.response.send_message(
        f"🏓 Pong! `{latency}ms`"
    )


@bot.tree.command(name="deobf", description="Deobfuscate Lua code")
@app_commands.describe(
    code="Lua code",
    file="Upload a .lua/.luau/.txt file"
)
async def deobf(
    interaction: discord.Interaction,
    code: str = None,
    file: discord.Attachment = None
):
    if file:
        allowed = (
            file.filename.endswith(".lua")
            or file.filename.endswith(".luau")
            or file.filename.endswith(".txt")
        )

        if not allowed:
            await interaction.response.send_message(
                "Invalid file type.",
                ephemeral=True
            )
            return

        data = await file.read()

        code = data.decode("utf-8", errors="ignore")

    if not code:
        await interaction.response.send_message(
            "Provide code or upload a file.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mDeobfuscating...\u001b[0m\n```"
    )

    msg = await interaction.original_response()

    await bot.animated_status(msg, "Deobfuscating")

    result = bot.advanced_deobfuscate(code)

    if len(result) < 1900:
        await msg.edit(
            content=f"```lua\n{result}\n```"
        )

    else:
        out = discord.File(
            io.BytesIO(result.encode()),
            filename="deobfuscated.lua"
        )

        await msg.delete()

        await interaction.channel.send(file=out)


@bot.tree.command(name="obf", description="Obfuscate Lua code")
@app_commands.describe(
    code="Lua code",
    file="Upload a .lua/.luau/.txt file"
)
async def obf(
    interaction: discord.Interaction,
    code: str = None,
    file: discord.Attachment = None
):
    if file:
        allowed = (
            file.filename.endswith(".lua")
            or file.filename.endswith(".luau")
            or file.filename.endswith(".txt")
        )

        if not allowed:
            await interaction.response.send_message(
                "Invalid file type.",
                ephemeral=True
            )
            return

        data = await file.read()

        code = data.decode("utf-8", errors="ignore")

    if not code:
        await interaction.response.send_message(
            "Provide code or upload a file.",
            ephemeral=True
        )
        return

    await interaction.response.send_message(
        "```ansi\n\u001b[1;32mObfuscating...\u001b[0m\n```"
    )

    msg = await interaction.original_response()

    await bot.animated_status(msg, "Obfuscating")

    result = bot.advanced_obfuscate(code)

    if len(result) < 1900:
        await msg.edit(
            content=f"```lua\n{result}\n```"
        )

    else:
        out = discord.File(
            io.BytesIO(result.encode()),
            filename="obfuscated.lua"
        )

        await msg.delete()

        await interaction.channel.send(file=out)


@bot.tree.command(name="lc", description="Lock a channel")
@app_commands.describe(
    channel="Select channel to lock"
)
async def lockchannel(
    interaction: discord.Interaction,
    channel: discord.TextChannel
):
    if not interaction.user.guild_permissions.manage_channels:
        await interaction.response.send_message(
            "You do not have permission.",
            ephemeral=True
        )
        return

    overwrite = channel.overwrites_for(
        interaction.guild.default_role
    )

    overwrite.send_messages = False

    await channel.set_permissions(
        interaction.guild.default_role,
        overwrite=overwrite
    )

    embed = discord.Embed(
        title="🔒 Channel Locked",
        description=f"{channel.mention} has been locked.",
        color=0xff0000
    )

    await interaction.response.send_message(embed=embed)


def main():
    print("Starting Xeioa Deobfr...")

    token = os.getenv("XEIOA_TOKEN")

    if not token:
        print("ERROR: XEIOA_TOKEN not set")
        return

    bot.run(token)


if __name__ == "__main__":
    main()
