"""
Cyber Hub Backend - Launcher
Developed by Syed Muhammad Tayyab

    python run.py            -> starts the engine on http://127.0.0.1:8765
    python run.py --port 9000
API docs: http://127.0.0.1:8765/docs
"""
import argparse
import os

import uvicorn

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Cyber Hub security engine")
    ap.add_argument("--port", type=int, default=int(os.environ.get("CYBERHUB_PORT", 8765)))
    ap.add_argument("--reload", action="store_true", help="auto-reload while developing")
    a = ap.parse_args()
    os.environ["CYBERHUB_PORT"] = str(a.port)
    # Host is fixed to loopback: the engine must never be reachable from the network.
    uvicorn.run("cyberhub.main:create_app", factory=True, host="127.0.0.1", port=a.port,
                reload=a.reload, log_level="info")
