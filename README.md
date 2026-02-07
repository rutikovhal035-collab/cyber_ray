# CyberAy - Malware Analysis Sandbox

A GUI-based malware analysis platform with CAPEv2 integration, featuring static/dynamic analysis, behavior graphs, and automatic YARA rule generation.

![Dashboard Preview](https://via.placeholder.com/800x400?text=Malware+Analysis+Sandbox)

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
- **CAPEv2** - Malware analysis sandbox
- **MongoDB** - Document database
- **Redis** - Caching and task queue

### Frontend
- **React 18** - UI framework
- **Vite** - Build tool
- **D3.js** - Behavior graph visualization
- **Chart.js** - Statistics charts

## 📦 Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (optional)
- CAPEv2 (for full functionality)

### Quick Start with Docker

```bash
# Clone the repository
cd cyberay

# Start all services
docker-compose up -d

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000/docs
```

### Manual Installation

#### Backend Setup
```bash
cd backend

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Copy environment file
copy ..\.env.example .env

# Run the server
uvicorn app.main:app --reload
```

#### Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

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

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

```env
# CAPEv2 connection
CAPE_API_URL=http://your-cape-server:8000
CAPE_API_TOKEN=your-api-token

# Database
MONGODB_URL=mongodb://localhost:27017
```

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
