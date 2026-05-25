# bot.py

```python
import io
import re
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

    @commands.command(name="ping")
    async def ping(self, ctx):
        await ctx.send("Pong!")

    @commands.command(name="deobf")
    async def deobf(self, ctx, *, code=None):
        """
        Basic Lua deobfuscator for educational/research use.
        Usage:
        !deobf <lua code>
        """

        if not code:
            await ctx.send("Please provide Lua code to deobfuscate.")
            return

        result = self.basic_lua_deobfuscate(code)

        if len(result) < 1900:
            await ctx.send(f"```lua\n{result}\n```")
        else:
            file = discord.File(
                io.BytesIO(result.encode()),
                filename="deobfuscated.lua"
            )
            await ctx.send("Deobfuscated output:", file=file)

    def basic_lua_deobfuscate(self, code: str) -> str:
        """
        VERY basic cleanup/deobfuscation.
        This is not a full reverse engineering engine.
        """

        # Remove repeated semicolons
        code = re.sub(r";+", ";", code)

        # Decode simple escaped decimal chars: string.char(72,101,108)
        code = self.decode_string_char(code)

        # Replace escaped hex strings
        code = self.decode_hex_escapes(code)

        # Remove excessive whitespace
        code = re.sub(r"\n{3,}", "\n\n", code)

        # Clean variable spam like local lllll =
        code = re.sub(
            r"local\s+([Il]{5,}|[a-zA-Z]{15,})",
            "local cleaned_var",
            code
        )

        return code.strip()

    def decode_string_char(self, code: str) -> str:
        pattern = r"string\.char\((.*?)\)"

        def repl(match):
            try:
                nums = match.group(1).split(",")
                chars = ''.join(chr(int(n.strip())) for n in nums)
                return f'"{chars}"'
            except:
                return match.group(0)

        return re.sub(pattern, repl, code)

    def decode_hex_escapes(self, code: str) -> str:
        def replace_hex(match):
            try:
                return bytes.fromhex(match.group(1)).decode("utf-8")
            except:
                return match.group(0)

        return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), code)
