# CybeRay - Malware Analysis Sandbox

A GUI-based malware analysis platform with CAPEv2 integration, featuring static/dynamic analysis, behavior graphs, and automatic YARA rule generation.

## 🚀 Features

- **📊 Static Analysis** - Hash calculation, PE parsing, string extraction, suspicious pattern detection
- **🔬 Dynamic Analysis** - CAPEv2 sandbox integration, API tracing, process monitoring
- **🌐 Network Analysis** - Track network connections, DNS queries, HTTP traffic
- **📈 Behavior Graphs** - Interactive D3.js visualization of malware behavior
- **📝 YARA Generation** - Automatic rule generation from analysis results
- **📄 Report Export** - Export reports in JSON/HTML formats

## 🛠️ Tech Stack

### Backend
- **FastAPI** - Modern Python web framework
- **CAPEv2** - Malware analysis sandbox (Recommended: Cloud-hosted for low RAM)
- **MongoDB Atlas** - Cloud Document database (Recommended for performance)
- **Redis / Upstash** - Cloud Caching and task queue

### Frontend
- **React 18** - UI framework
- **Vite** - Build tool

---
## 📦 Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- [MongoDB Atlas Account](https://www.mongodb.com/cloud/atlas) (Free)

### Quick Start (Low-Resource Method)

1. **Clone & Environment Setup**
   ```bash
   git clone https://github.com/yourusername/cyberay.git
   cd cyberay
   copy .env.example .env
   ```
   *Edit `.env` and add your MongoDB Atlas connection string.*

2. **Backend Setup**
   ```bash
   cd backend
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   python -m uvicorn app.main:app --reload --port 8000
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

Access the dashboard at: `http://localhost:5173`

## 📁 Project Structure

```
cyberay/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── core/
│   │   │   └── config.py        # Configuration
│   │   ├── routes/
│   │   │   ├── analysis.py      # Analysis endpoints
│   │   │   ├── yara.py          # YARA endpoints
│   │   │   └── reports.py       # Report endpoints
│   │   ├── services/
│   │   │   ├── cape_client.py   # CAPEv2 integration
│   │   │   ├── static_analyzer.py
│   │   │   ├── yara_generator.py
│   │   │   └── graph_builder.py
│   │   └── models/
│   │       └── schemas.py       # Pydantic models
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard/
│   │   │   ├── FileUpload/
│   │   │   ├── AnalysisReport/
│   │   │   ├── BehaviorGraph/
│   │   │   └── YARAGenerator/
│   │   ├── services/
│   │   │   └── api.js
│   │   ├── App.jsx
│   │   └── index.css
│   ├── package.json
│   └── Dockerfile
│
├── docker-compose.yml
├── .env.example
└── README.md
```

## 🔧 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analysis/submit` | Submit file for analysis |
| GET | `/api/analysis/status/{id}` | Get analysis status |
| GET | `/api/analysis/report/{id}` | Get full report |
| POST | `/api/yara/generate` | Generate YARA rule |
| GET | `/api/reports/statistics` | Get dashboard stats |

## 📊 Usage

1. **Upload Sample** - Drag and drop or select a file to analyze
2. **View Analysis** - See static and dynamic analysis results
3. **Explore Behavior** - View interactive behavior graph
4. **Generate YARA** - Create detection rules automatically
5. **Export Reports** - Download analysis in JSON/HTML

## 🔒 Security Notes

- Run malware analysis in isolated environments only
- Do not expose this application to the public internet
- Use proper network segmentation
- Regularly update CAPEv2 and dependencies

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

Built with ❤️ for security research and education purposes.
#   C u b e S a n d b o x 
