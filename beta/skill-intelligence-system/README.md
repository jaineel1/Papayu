# Holistic Academic & Professional Skill Intelligence System

> **Ingenious Hackathon 7.0 – Problem Statement 3**

## 🚀 Overview
A living skill-intelligence platform that uses real job-market data to map user skills to careers, identify gaps, and guide personalized, explainable learning paths. It targets domains like **Healthcare Technology**, **Agricultural Technology**, and **Smart City Systems**.

## 🏗 System Architecture
The system consists of:
- **Backend**: FastAPI (Python) with SQLAlchemy & SQLite/PostgreSQL.
- **Frontend**: React (Vite) with a professional "Deep Blue" theme.
- **Intelligence Engine**: Deterministic skill gap analysis & readiness scoring.

## 🏁 Getting Started

### Prerequisites
- Python 3.9+
- Node.js 16+
- Git

### 1. Backend Setup
```bash
cd backend
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
python -m app.main
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## 🧠 Core Features
- **Role Matching**: Matches your profile against real-world job requirements.
- **Skill Gap Analysis**: Identifies exactly what you're missing.
- **Learning Paths**: Recommends specific resources to close gaps.

## 📚 Documentation
- [Architecture](./docs/architecture.md)
- [Algorithm Logic](./docs/algorithm.md)
- [Datasets](./docs/datasets.md)
- [API Documentation](./docs/api-docs.md)
