from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional
from pymongo import MongoClient

from intelligence.attack_analyzer import analyze_attack
from intelligence.response_engine import generate_response


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(title="ARIA Intelligence API")


# ============================================================
# MONGODB
# ============================================================

MONGO_URI = "mongodb://127.0.0.1:27017"

mongo_client = MongoClient(MONGO_URI)

db = mongo_client["aria"]

commands_collection = db["commands"]


# Test MongoDB connection when API starts
try:
    mongo_client.admin.command("ping")
    print("[MongoDB] Connected successfully")
except Exception as e:
    print(f"[MongoDB] Connection failed: {e}")


# ============================================================
# REQUEST MODEL
# ============================================================

class CommandRequest(BaseModel):
    command: str
    session: str = "unknown"
    src_ip: str = "unknown"
    src_port: Optional[int] = None
    dst_ip: str = "unknown"
    dst_port: Optional[int] = None


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "ARIA Intelligence API",
        "mongodb": "enabled"
    }


# ============================================================
# ANALYZE COMMAND
# ============================================================

@app.post("/analyze")
def analyze_command(request: CommandRequest):

    command = request.command.strip()

    if not command:
        return {
            "command": "",
            "intent": "",
            "behavior": "",
            "mitre": None,
            "response": ""
        }

    # --------------------------------------------------------
    # 1. Analyze command
    # --------------------------------------------------------

    analysis = analyze_attack(command)

    intent = analysis.get("intent", "")
    behavior = analysis.get("behavior", "")
    mitre = analysis.get("mitre")

    # --------------------------------------------------------
    # 2. Generate realistic response
    # --------------------------------------------------------

    response = generate_response(
        command=command,
        intent=intent,
        behavior=behavior,
        mitre=mitre
    )

    # --------------------------------------------------------
    # 3. Create database document
    # --------------------------------------------------------

    document = {
        "timestamp": datetime.now(timezone.utc),

        "session": request.session,

        "src_ip": request.src_ip,
        "src_port": request.src_port,

        "dst_ip": request.dst_ip,
        "dst_port": request.dst_port,

        "command": command,

        "intent": intent,

        "behavior": behavior,

        "mitre": mitre,

        "response": response
    }

    # --------------------------------------------------------
    # 4. Save to MongoDB
    # --------------------------------------------------------

    try:

        result = commands_collection.insert_one(document)

        print(
            f"[MongoDB] Saved command "
            f"{command!r} "
            f"ID={result.inserted_id}"
        )

    except Exception as e:

        print(f"[MongoDB] Insert failed: {e}")

    # --------------------------------------------------------
    # 5. Return result to Cowrie
    # --------------------------------------------------------

    return {
        "command": command,
        "intent": intent,
        "behavior": behavior,
        "mitre": mitre,
        "response": response
    }


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "aria_api:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
