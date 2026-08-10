import sys
import os

# Add the backend directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mangum import Mangum
from app.main import app

handler = Mangum(app)
