# 🔥 FireShark

**FireShark** is a simple network forensics tool that analyzes packet captures (PCAPs) to reveal SYN port scans. It provides a clean, interactive web UI for uploading PCAP files and visualizing detected SYN scan events over time.

---

## 🎯 Goal

FireShark helps answer:

> “Are there SYN port scans in this network capture?”

It focuses on time-based SYN scan detection and makes it easy to spot scanning hosts and their targets.

---

## 🚦 Features (Current)

- **PCAP upload** via drag-and-drop or file select
- **SYN scan detection** (shows source, targets, ports, and time window)
- **Scan summary** (total scans, sources, destinations, busiest port)
- **Timeline bar** for each scan event
- **Modern, cyber-themed UI**

---

## 🚧 Planned Features

- Detection of additional scan types (e.g., UDP, XMAS, FIN, NULL, ICMP sweeps)
- Timeline visualization of multiple scan types and events
- Grouping and filtering of scan events by type, source, or time
- Enhanced visualizations (heatmaps, port activity charts)
- Export of scan results (JSON, CSV, PDF)
- Top talkers and protocol statistics
- Alert overlays for suspicious/malicious activity

---

## 🧩 Architecture Overview

| Layer           | Technology                | Purpose                                      |
|-----------------|--------------------------|----------------------------------------------|
| **Frontend**    | HTML + JS (`main.js`)    | Scan upload and results visualization        |
| **Styling**     | CSS (`style.css`)        | Modern cyber-themed UI                       |
| **Backend**     | FastAPI (Python)         | Handles file uploads, parsing, and analysis  |
| **Packet Parsing** | Scapy                  | Extracts metadata from PCAPs                 |

---

## ⚙️ Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/FireShark.git
cd FireShark
```

### 2. Set Up Python Environment
```bash
python -m venv fires_env
# On Windows:
fires_env\Scripts\activate
# On Mac/Linux:
source fires_env/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Start the FastAPI Backend
```bash
uvicorn app.app:app --reload --host 0.0.0.0 --port 8000
```

### 5. Open the Frontend
Open `upload.html` in your browser (or deploy with a static file server).

---

## 📁 Project Structure

```
fire-shark/
├── app/                # FastAPI backend & PCAP parsing modules
├── images/             # Logo and static images
├── pcaps/              # Example/test PCAP files (not tracked by git)
├── fires_env/          # Python virtual environment (gitignored)
├── main.js             # Frontend JavaScript
├── style.css           # Frontend CSS
├── upload.html         # Main frontend page
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules
├── notes/              # Local notes (gitignored)
└── ReadMe.md           # This file
```

---

## 📝 .gitignore
- Ignores `fires_env/`, `__pycache__/`, `.vscode/`, `notes/`, and other generated files.
- Keeps your repo clean and focused on code and config.

---

## 🗒️ Notes Folder
If you keep personal notes or scratch files, place them in the `notes/` folder. This folder is ignored by git by default.

---

## 🤝 Contributing
Pull requests and issues are welcome!

---

## 📄 License
MIT
