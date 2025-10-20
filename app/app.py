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


@app.post("/upload")
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
        return JSONResponse(summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCAP parse error: {e}")
    finally:
        # Clean up
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
