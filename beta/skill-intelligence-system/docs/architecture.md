# System Architecture

## Overview
The solution follows a standard **Client-Server** architecture.

### 1. Backend Layer (FastAPI)
The backend serves as the source of truth and intelligence engine.
- **Framework**: FastAPI (High performance, auto-docs).
- **ORM**: SQLAlchemy (Relational mapping).
- **Database**: SQLite (for portability/hackathon) or PostgreSQL.
- **Structure**:
  - `routers/`: REST endpoints.
  - `services/`: Business logic (Gap analysis, Recommendations).
  - `models/`: DB Tables.

### 2. Frontend Layer (React)
The frontend provides the interactive dashboard.
- **Framework**: React (Vite).
- **Styling**: CSS Modules / Vanilla CSS (Deep Blue Theme).
- **State**: React Hooks (Context API if needed).
- **Charts**: Chart.js for visualizing skill gaps.

### 3. Data Flow
1. **User Input** -> **API** -> **Normalization Service**
2. **Role Request** -> **Matching Service** -> **DB Query**
3. **Response** -> **Frontend** -> **Rendering**

## Diagram
(Conceptual)
[Frontend] <--> [FastAPI] <--> [SQLAlchemy] <--> [DB]
                     ^
                     |
               [Seed Data Scripts]
