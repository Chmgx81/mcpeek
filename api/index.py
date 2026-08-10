import sys
import os

# Ensure backend package is importable (Vercel runs from project root)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.main import app  # noqa: E402

from mangum import Mangum  # noqa: E402

handler = Mangum(app, lifespan="off")
