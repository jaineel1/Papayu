# Holistic Skill Intelligence Platform

## Problem Statement
Problem Statement 3 – Holistic Academic and Professional Skill Intelligence System for Emerging Sectors

---

## Project Overview
Students and early-career professionals often struggle to understand how their academic performance, projects, and practical skills align with real-world industry requirements. Existing platforms focus on isolated indicators such as grades, certifications, or resumes, without providing integrated insights or actionable guidance for future growth.

This project presents a **Holistic Skill Intelligence Platform** that continuously captures, organizes, and analyzes a user’s academic and professional journey. The system identifies skill gaps, estimates career readiness, recommends personalized learning paths, and visualizes progression for emerging sectors such as **Healthcare Technology, Agricultural Technology, and Smart City Systems**.

Unlike static profiles, this platform functions as a **living system** that evolves with the user over time.

---

## Key Features
- User profile management for skills, courses, projects, and certifications
- Deterministic skill-gap analysis using sector-specific frameworks
- Career readiness scoring (0–100%)
- Personalized course and project recommendations
- Interactive dashboards for skill progression and gaps
- Secure authentication using Firebase
- External API integration (real or simulated)

---

## System Architecture

The system follows a modular, layered architecture to ensure scalability, clarity, and extensibility.

### Frontend Layer
Built with React, the frontend provides user interfaces for profile management, career selection, and dashboard visualization.

### Backend Layer
Implemented using FastAPI, the backend exposes RESTful APIs for profile management, skill processing, and coordination with the intelligence engine.

### Intelligence Engine
A deterministic, weighted skill-gap scoring engine evaluates user skills against role-specific frameworks to compute a **Career Readiness Index** and generate recommendations.

### Data Layer
User data, skill frameworks, and mappings are stored using relational models (SQLite for development, PostgreSQL-ready for production).

### External Integrations
Optional integrations with LinkedIn, GitHub, and learning platforms enhance profile context. Mocked integrations are used where live access is unavailable.

---

## Machine Learning and Skill Intelligence

The platform implements a **deterministic, weighted skill-gap scoring engine** for role readiness estimation.

This is a **rule-based, explainable, and domain-grounded intelligence system**, designed for transparency and reproducibility rather than opaque prediction.

### Skill-Gap Scoring Model
- Each career role has a predefined skill framework
- Each skill is assigned a weight based on industry relevance
- User skills are matched against the framework
- A readiness score is computed (0–100%)

The output is a **Career Readiness Index**, representing alignment between a user’s current skills and the selected role.

### Recommendation Logic
Skills with the highest weighted gaps are prioritized. Learning resources (courses/projects) mapped to those skills are recommended to maximize readiness improvement.

---

## Dataset

The intelligence engine is informed by a publicly available Kaggle dataset:

- **Dataset Name:** LinkedIn Jobs and Skills (1–3M)
- **Source:** Kaggle
- **URL:** https://www.kaggle.com/datasets/asaniczka/1-3m-linkedin-jobs-and-skills-2024

The dataset provides job-role-to-skill mappings at scale. It was used to:
- Identify common skill requirements per role
- Inform skill framework construction
- Support weighting strategies

Preprocessing included filtering domain-relevant roles, normalizing skill names, and aggregating frequencies.

---

## Technology Stack

### Frontend (Client-Side)
- React 18 (Functional Components & Hooks)
- Vite (development and build tool)
- JavaScript (ES6+)
- React Router v6
- Context API (state management)
- Chart.js & react-chartjs-2
- Axios
- Firebase Authentication
- Vanilla CSS3 (dark theme support)

### Backend (Server-Side)
- FastAPI (Python 3.9+)
- Uvicorn (ASGI server)
- SQLAlchemy 2.0
- Pydantic
- Swagger UI (auto-generated docs)

### Intelligence Engine
- Weighted Vector-Space Matching (custom heuristic)
- Python set operations and dictionary lookups
- O(1) access patterns for skill matching

### Database
- SQLite (development)
- PostgreSQL-compatible (production-ready)
- ACID-compliant relational storage

### Infrastructure
- Python virtual environment (venv)
- Windows batch scripts (.bat)
- Git for version control

---

# Installation and Setup (Run Locally)

# Clone the repository
git clone <repository-url>
cd app

# Backend setup
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
Backend runs at http://localhost:8000

# Frontend setup
cd ../frontend
npm install
npm run dev
Frontend runs at http://localhost:5173

### Environment Variables

## Frontend

VITE_API_BASE_URL=http://localhost:8000
VITE_FIREBASE_API_KEY=AIzaSyCdcxP-tfV1YE2nRsllPv59F6Bnn3Cvtk8
VITE_FIREBASE_AUTH_DOMAIN=skill-intelligence-5d5c6.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=skill-intelligence-5d5c6
VITE_FIREBASE_STORAGE_BUCKET=skill-intelligence-5d5c6.firebasestorage.app
VITE_FIREBASE_MESSAGING_SENDER_ID=1046108634118
VITE_FIREBASE_APP_ID=1:1046108634118:web:d60234c7501642d2e7d787
VITE_FIREBASE_MEASUREMENT_ID=G-EHVNMYY1F9

# Backend
DATABASE_URL=sqlite:///./app.db
ENV=development
SECRET_KEY=hackathon-secret-key-change-me
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
---

# Test Login Credentials
For demonstration purposes, the following test credentials may be used:
-Demo Account: demo@skills.ai / password123
-These credentials are limited to demo access and do not expose real user data.
# Basic Error Handling
-Frontend displays user-friendly messages for network and authentication errors
-Backend validates all inputs using Pydantic schemas
-Invalid requests return structured HTTP error responses
-Server errors are logged for debugging without exposing sensitive data
-Security and Secrets
-No API keys, passwords, or secrets are hardcoded
-.env files are excluded via .gitignore
-Firebase credentials are managed via environment variables
-Dataset is referenced by link only; no raw data is committed

# Demonstration

The demonstration includes:

-Sample user profile creation
-Career selection and readiness scoring
-Skill-gap identification
-Personalized learning recommendations
-Dashboard-based visualization of progress
-Future Enhancements
-Role-based access control
-Persistent cloud database
-Real-time external integrations
-Advanced hybrid intelligence models
-Resume and portfolio generation
-Mobile application support

# Team Information

-Hackathon: Ingenious Hackathon 7.0
-Team Name: Papayu
-Problem Statement: 3
-Project Type: Full-stack Skill Intelligence and Career Readiness System

# Conclusion

This project delivers an explainable, secure, and scalable skill intelligence platform that bridges the gap between academic learning and industry requirements. By focusing on career readiness estimation rather than opaque prediction, the system provides meaningful, actionable guidance for long-term professional growth in emerging sectors.
