# app/app.py
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import shutil
import tempfile
from .parser.pcap_parse import summarize_pcap


app = FastAPI(title="FireShark API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (for serving the upload.html page)
app.mount("/static", StaticFiles(directory="."), name="static")


@app.get("/")
def root():
    return {"message": "🔥 FireShark API is live!"}


@app.get("/ping")
def ping():
    return {"ok": True}


ALLOWED_EXT = {".pcap", ".cap", ".pcapng"}  # now supports .pcapng


from typing import List, Dict, Any

from fastapi import Body
from fastapi.responses import JSONResponse
from fastapi import status
from fastapi import APIRouter

from pydantic import BaseModel, Field


class ScanEvent(BaseModel):
    type: str = Field(
        ...,
        description="Classification of the scan event (e.g., full_handshake, half_open_rst, etc.)",
    )
    src: str = Field(..., description="Source (client) IP address")
    sport: int = Field(..., description="Source (client) port")
    dst: str = Field(..., description="Destination (server) IP address")
    dport: int = Field(..., description="Destination (server) port")
    start_time: float = Field(..., description="Timestamp of first event in handshake")
    end_time: float = Field(..., description="Timestamp of last event in handshake")
    evidence: List[str] = Field(
        ..., description="Observed handshake sequence, e.g. ['SYN','SYN+ACK','ACK']"
    )


class PcapSummary(BaseModel):
    file: str
    total_packets: int
    protocols: List[Dict[str, Any]]
    top_talkers: List[Dict[str, Any]]
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    top_tcp_ports: List[Dict[str, Any]]
    top_udp_ports: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    truncated: bool
    scans: List[ScanEvent]


@app.post(
    "/upload",
    response_model=PcapSummary,
    response_model_exclude_unset=True,
    summary="Upload a PCAP and analyze for handshake-based scans",
    response_description="PCAP summary and scan events",
)
async def upload_pcap(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload .pcap, .cap, or .pcapng",
        )

    # Save to a temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp_path = Path(tmp.name)
        try:
            shutil.copyfileobj(file.file, tmp)
        finally:
            file.file.close()

    try:
        summary = summarize_pcap(str(tmp_path))
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCAP parse error: {e}")
    finally:
        # Clean up
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
