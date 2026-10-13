import os
from pathlib import Path

from dotenv_loader import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

from coreworks.hub import create_app

app = create_app()

if __name__ == "__main__":
    # Local-only development server. Do not expose to a public interface.
    app.run(host="127.0.0.1", port=5055, debug=False)
