"""Allow `python -m app` to start the server."""

import uvicorn

from .config import settings

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
