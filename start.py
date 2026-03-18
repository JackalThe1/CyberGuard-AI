#!/usr/bin/env python3
"""
CyberGuard AI - Universal Launcher
Works on Windows, macOS, and Linux — run from anywhere.
"""
import os
import sys
import subprocess
import webbrowser
from pathlib import Path

# Always run from the directory this script lives in,
# regardless of where the user calls it from.
os.chdir(Path(__file__).resolve().parent)


def check_python_version():
    if sys.version_info < (3, 9):
        print("❌ Python 3.9 or higher required")
        print(f"   Current version: {sys.version}")
        print("   Download from: https://www.python.org/downloads/")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")


def check_dependencies():
    try:
        import flask
        import requests
        print("✅ Core dependencies installed")
        try:
            import groq
            print("✅ Groq AI library available")
        except ImportError:
            print("⚠️  groq not installed — AI features will use heuristics")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e.name}")
        print("\n📦 Installing dependencies...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("✅ Dependencies installed successfully")
            return True
        else:
            print("❌ Failed to install dependencies")
            print(result.stderr)
            return False


def check_env_file():
    env_path = Path(".env")
    env_example = Path(".env.example")

    if not env_path.exists():
        print("⚠️  .env file not found")
        if env_example.exists():
            print("📝 Creating .env from .env.example")
            env_path.write_text(env_example.read_text())
            print()
            print("╔══════════════════════════════════════════════════╗")
            print("║  ACTION REQUIRED: Configure your API keys         ║")
            print("║                                                    ║")
            print("║  Edit .env and set:                               ║")
            print("║  • GROQ_API_KEY (https://console.groq.com)        ║")
            print("║  • SLACK_WEBHOOK_URL (optional)                   ║")
            print("║  • DISCORD_WEBHOOK_URL (optional)                 ║")
            print("╚══════════════════════════════════════════════════╝")
            print()
            print("  → No API key? App runs with heuristic analysis!")
            print("    Just set GROQ_API_KEY= (leave blank) in .env")
            print()
            return False

    env_content = env_path.read_text()
    if "your_groq_api_key_here" in env_content:
        print("⚠️  .env exists but Groq key not configured")
        print("   Running with heuristic analysis (no AI key needed)")
        print("   To enable AI: edit .env and add your GROQ_API_KEY")
    else:
        print("✅ Configuration file found")
    return True


def start_server():
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  🚀 CyberGuard AI is starting up...              ║")
    print("╚══════════════════════════════════════════════════╝")

    try:
        from app import app

        def open_browser():
            import time
            time.sleep(1.5)
            webbrowser.open('http://localhost:5000')

        import threading
        threading.Thread(target=open_browser, daemon=True).start()

        print()
        print("  🌐 Dashboard → http://localhost:5000")
        print("  📋 Demo logs → sample_logs/apache_access.log")
        print("  🛑 Stop      → Press CTRL+C")
        print()
        print("─" * 52)

        app.run(host='0.0.0.0', port=5000, debug=False)

    except KeyboardInterrupt:
        print("\n\n  👋 CyberGuard AI stopped. Goodbye!\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)


def main():
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  🔒 CyberGuard AI                                ║")
    print("║     Autonomous Security Operations Platform      ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    check_python_version()

    if not check_dependencies():
        print()
        print("❌ Dependency setup failed. Try manually:")
        print(f"   {sys.executable} -m pip install -r requirements.txt")
        sys.exit(1)

    check_env_file()

    print()
    start_server()


if __name__ == "__main__":
    main()
