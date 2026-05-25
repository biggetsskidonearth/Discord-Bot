import io
import os
import re
import base64
import random
import string
import asyncio
import discord
from discord.ext import commands

class XeioaBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True

        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None
        )

    async def setup_hook(self):
        print("Bot setup complete")

    async def on_ready(self):
        print(f"Logged in as {self.user}")

    async def on_message(self, message):
        if message.author.bot:
            return

        await self.process_commands(message)

    @commands.command()
    async def ping(self, ctx):
        await ctx.send("Pong!")

    @commands.command()
    async def helpme(self, ctx):
        embed = discord.Embed(
            title="⚡ Xeioa Deobfr ⚡",
            description="Advanced Roblox Lua Obfuscator & Deobfuscator",
            color=0x00ff99
        )

        embed.add_field(
            name="Commands",
            value=(
                "`!deobf <lua code>`\n"
                "`!obf <lua code>`\n"
                "You can also upload `.lua`, `.luau`, or `.txt` files."
            ),
            inline=False
        )

        await ctx.send(embed=embed)

    async def animated_status(self, msg, text):
        stages = [
            f"{text}",
            f"{text}.",
            f"{text}. .",
            f"{text}. . ."
        ]

        for _ in range(3):
            for stage in stages:
                await msg.edit(
                    content=f"```ansi\n\u001b[1;32m{stage}\u001b[0m\n```"
                )
                await asyncio.sleep(0.4)

    async def get_code_input(self, ctx, code):
        # Text argument provided
        if code:
            return code

        # File upload provided
        if ctx.message.attachments:
            attachment = ctx.message.attachments[0]

            allowed = (
                attachment.filename.endswith(".lua")
                or attachment.filename.endswith(".luau")
                or attachment.filename.endswith(".txt")
            )

            if not allowed:
                await ctx.send(
                    "Only `.lua`, `.luau`, and `.txt` files are supported."
                )
                return None

            try:
                data = await attachment.read()
                return data.decode("utf-8", errors="ignore")

            except Exception as e:
                await ctx.send(f"Failed to read file: {e}")
                return None

        await ctx.send(
            "Provide code or upload a `.lua`, `.luau`, or `.txt` file."
        )

        return None

    @commands.command()
    async def deobf(self, ctx, *, code=None):
        code = await self.get_code_input(ctx, code)

        if not code:
            return

        status = await ctx.send("Starting deobfuscation...")

        await self.animated_status(status, "Deobfuscating")

        result = self.advanced_deobfuscate(code)

        if len(result) < 1900:
            await status.edit(
                content=f"```lua\n{result}\n```"
            )
        else:
            file = discord.File(
                io.BytesIO(result.encode()),
                filename="deobfuscated.lua"
            )

            await status.delete()
            await ctx.send(file=file)

    @commands.command()
    async def obf(self, ctx, *, code=None):
        code = await self.get_code_input(ctx, code)

        if not code:
            return

        status = await ctx.send("Starting obfuscation...")

        await self.animated_status(status, "Obfuscating")

        result = self.advanced_obfuscate(code)

        if len(result) < 1900:
            await status.edit(
                content=f"```lua\n{result}\n```"
            )
        else:
            file = discord.File(
                io.BytesIO(result.encode()),
                filename="obfuscated.lua"
            )

            await status.delete()
            await ctx.send(file=file)

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

        junk = [
            "--[[ protected ]]",
            "--[[ xeioa ]]",
            "--[[ encrypted ]]",
            "--[[ anti skid ]]"
        ]

        for _ in range(5):
            pos = random.randint(0, len(code))
            code = (
                code[:pos]
                + random.choice(junk)
                + "\n"
                + code[pos:]
            )

        fake_blocks = """
if false then
    print("Xeioa")
end
"""

        code = fake_blocks + "\n" + code

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
        code = self.normalize_whitespace(code)
        code = self.remove_semicolon_spam(code)
        code = self.decode_string_char(code)
        code = self.decode_hex(code)
        code = self.decode_decimal_escapes(code)
        code = self.decode_base64_strings(code)
        code = self.clean_variable_names(code)
        code = self.remove_junk_comments(code)
        code = self.unpack_concat_strings(code)
        code = self.cleanup_control_flow(code)
        return code.strip()

    def normalize_whitespace(self, code: str) -> str:
        code = code.replace("\r\n", "\n")
        code = re.sub(r"\n{3,}", "\n\n", code)
        return code

    def remove_semicolon_spam(self, code: str) -> str:
        return re.sub(r";+", ";", code)

    def decode_string_char(self, code: str) -> str:
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

        return re.sub(pattern, repl, code)

    def decode_hex(self, code: str) -> str:
        return re.sub(
            r"\\x([0-9A-Fa-f]{2})",
            lambda m: chr(int(m.group(1), 16)),
            code
        )

    def decode_decimal_escapes(self, code: str) -> str:
        return re.sub(
            r"\\([0-9]{1,3})",
            lambda m: chr(int(m.group(1)))
            if int(m.group(1)) < 256
            else m.group(0),
            code
        )

    def decode_base64_strings(self, code: str) -> str:
        pattern = r'"([A-Za-z0-9+/=]{16,})"'

        def repl(match):
            s = match.group(1)

            try:
                decoded = base64.b64decode(
                    s
                ).decode("utf-8")

                if all(
                    32 <= ord(c) < 127
                    or c in "\n\t"
                    for c in decoded
                ):
                    return f'"{decoded}"'

            except:
                pass

            return match.group(0)

        return re.sub(pattern, repl, code)

    def clean_variable_names(self, code: str) -> str:
        replacements = {}
        counter = 1

        pattern = r"\b([Il]{5,}|[a-zA-Z_]{18,})\b"

        matches = re.findall(pattern, code)

        for var in matches:
            if var not in replacements:
                replacements[var] = f"var_{counter}"
                counter += 1

        for old, new in replacements.items():
            code = re.sub(
                rf"\b{re.escape(old)}\b",
                new,
                code
            )

        return code

    def remove_junk_comments(self, code: str) -> str:
        return re.sub(
            r"--\[\[[\s\S]*?\]\]",
            "",
            code
        )

    def unpack_concat_strings(self, code: str) -> str:
        pattern = r'"([^"]*)"\s*\.\.\s*"([^"]*)"'

        while re.search(pattern, code):
            code = re.sub(
                pattern,
                lambda m: f'"{m.group(1) + m.group(2)}"',
                code
            )

        return code

    def cleanup_control_flow(self, code: str) -> str:
        code = re.sub(
            r"if false then.*?end",
            "",
            code,
            flags=re.S
        )

        code = re.sub(
            r"if true then",
            "",
            code
        )

        code = re.sub(
            r"while true do",
            "while true do -- infinite loop",
            code
        )

        return code


def main():
    print("Starting Xeioa Deobfr...")

    token = os.getenv("XEIOA_TOKEN")

    if not token:
        print("ERROR: XEIOA_TOKEN environment variable not set")
        return

    bot = XeioaBot()
    bot.run(token)


if __name__ == "__main__":
    main()
