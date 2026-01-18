# Holistic Skill Intelligence System (SkillMatch)

A context-aware skill intelligence platform that helps users analyze their skills, identify gaps for target roles, and get personalized learning recommendations via an AI-powered assistant.

## Features

-   **Interactive Dashboard**: Visual breakdown of skill coverage and proficiency levels.
-   **Role Explorer**: Analyze readiness for various target roles (e.g., Data Scientist, Backend Dev).
-   **Skill Gap Analysis**: Detailed breakdown of missing skills and required proficiency levels.
-   **Context-Aware Chatbot**: "SkillMatch Assistant" provides personalized explanations and learning path recommendations using user data.
    -   *Multi-turn conversation support.*
    -   *Intelligent resource linking (Database + AI fallback).*
-   **Learning Recommendations**: Direct links to courses and projects to bridge skill gaps.

## Tech Stack

### Backend
-   **Framework**: FastAPI (Python)
-   **Database**: SQLite (via SQLAlchemy)
-   **AI/LLM**: OpenAI GPT-3.5 Turbo (via `openai` lib)
-   **Validation**: Pydantic

### Frontend
-   **Framework**: React (Vite)
-   **Styling**: Vanilla CSS (Custom Dashboard Design)
-   **Visualization**: Chart.js (`react-chartjs-2`)
-   **HTTP Client**: Axios

## Prerequisites

-   Python 3.9+
-   Node.js 16+
-   OpenAI API Key (Optional, for full AI features)

## Setup & Running Locally

### 1. Clone the Repository
```bash
git clone https://github.com/jaineel1/Papayu.git
cd Papayu/beta/skill-intelligence-system
```

### 2. Backend Setup
Navigate to the backend directory, create a virtual environment, and install dependencies.

```bash
cd backend

# Create virtual environment (Windows)
python -m venv venv
.\venv\Scripts\activate

# Create virtual environment (Mac/Linux)
# python3 -m venv venv
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Environment Variables:**
Create a `.env` file in the `backend/` directory:

```env
# backend/.env
DATABASE_URL=sqlite:///./sql_app.db
SECRET_KEY=supersecretkey123
ACCESS_TOKEN_EXPIRE_MINUTES=30

# API Key for Chatbot (Leave empty to use Mock Mode)
OPENAI_API_KEY=sk-your-openai-api-key-here
```

**Run the Backend:**
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
*The API will be available at `http://127.0.0.1:8000`.*

### 3. Frontend Setup
Open a new terminal, navigate to the frontend directory, and install dependencies.

```bash
cd frontend

# Install dependencies
npm install

# Run the frontend
npm run dev
```
*The UI will be available at `http://localhost:5173`.*

## Test Credentials

Use the following credentials to log in and explore the demo data:

| Role | Email | Password |
|------|-------|----------|
| **Demo User** | `demo@skills.ai` | `password123` |

*Note: You can also register a new account.*

## Basic Error Handling

-   **Blank Screen?**: Ensure both Backend (port 8000) and Frontend (port 5173) are running. Check browser console for connection errors.
-   **Chatbot "Mock Mode"**: If you see "Mock Mode" in the chat, it means `OPENAI_API_KEY` is missing or invalid in `backend/.env`. The chatbot will still function with static responses.
-   **Database Errors**: If you encounter DB issues, delete `backend/sql_app.db` and restart the backend to re-initialize with default data (if init scripts are present).

## Security Note

> [!NOTE]
> **No Secrets in Repo**: This repository does not contain any real API keys or secrets. The `.env` file is excluded from version control. Please ensure you do not commit your personal `OPENAI_API_KEY`.
