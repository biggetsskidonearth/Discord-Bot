#!/usr/bin/env python3
"""
Xeioa Deobfr - Discord Bot Launcher
Run with: python main.py
"""

import asyncio
import sys
import os

def main():
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║                                                      ║")
    print("  ║          ⚡  Xeioa Deobfr  ⚡                        ║")
    print("  ║          Lua Reverse Engineering Bot                 ║")
    print("  ║                                                      ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()

    if len(sys.argv) < 2:
        print("  Usage: python main.py <bot_token>")
        print()
        print("  Get your token from: https://discord.com/developers/applications")
        print()
        print("  Or set environment variable:")
        print("    export XEIOA_TOKEN=your_token_here")
        print("    python main.py")
        print()
        token = os.environ.get("XEIOA_TOKEN", "")
        if not token:
            sys.exit(1)
    else:
        token = sys.argv[1]

    from bot import XeioaBot
    bot = XeioaBot()
    bot.run(token)

if __name__ == "__main__":
    main()
