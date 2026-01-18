# Technology Stack Documentation
**Holistic Academic & Professional Skill Intelligence System**

## 1. Frontend Layer (Client-Side)
The user interface is built for performance, interactivity, and responsiveness using modern React ecosystem tools.

*   **Framework**: [React 18](https://react.dev/)
    *   Component-based architecture.
    *   Hooks (`useState`, `useEffect`, `useContext`) for state management.
*   **Build Tool**: [Vite](https://vitejs.dev/)
    *   Lightning-fast HMR (Hot Module Replacement) and optimized production builds.
*   **Routing**: [React Router v6](https://reactrouter.com/)
    *   Client-side routing for seamless navigation (Dashboard, Profile, Role Explorer).
*   **Visualization**: [Chart.js](https://www.chartjs.org/) & [react-chartjs-2](https://react-chartjs-2.js.org/)
    *   Dynamic Doughnut charts for skill coverage visualization.
*   **HTTP Client**: [Axios](https://axios-http.com/)
    *   Promise-based HTTP client for communicating with the backend API.
*   **Authentication**: [Firebase Auth SDK](https://firebase.google.com/docs/auth)
    *   Secure email/password authentication and session management.
*   **Styling**: Vanilla CSS3
    *   Custom dark-mode design system with CSS variables for consistency.

## 2. Backend Layer (Server-Side)
A high-performance, asynchronous REST API powered by Python.

*   **Web Framework**: [FastAPI](https://fastapi.tiangolo.com/)
    *   Modern, fast (high-performance) web framework for building APIs with Python 3.9+.
    *   Automatic interactive API documentation (Swagger UI).
*   **ASGI Server**: [Uvicorn](https://www.uvicorn.org/)
    *   Lightning-fast ASGI server implementation.
*   **Data Validation**: [Pydantic](https://docs.pydantic.dev/)
    *   Robust data validation and settings management using Python type hints (Schemas).
*   **ORM (Object Relational Mapper)**: [SQLAlchemy](https://www.sqlalchemy.org/)
    *   SQL toolkit and Object Relational Mapper for database interactions.

## 3. Data Intelligence Engine (Core Logic)
The "Brain" of the system that matches users to jobs.

*   **Algorithm**: Weighted Vector-Space Matching (Heuristic)
    *   **Custom Implementation**: Python-based logic leveraging Set Theory.
    *   **Features**:
        *   **Readiness Scoring**: Calculates a percentage match (0-100%) based on skill overlaps and weights.
        *   **Gap Analysis**: Identifies missing skills and calculates the difficulty bridge.
        *   **Resource Mapping**: Dynamically links missing skills to educational resources.

## 4. Database Layer
*   **Primary Database**: [SQLite](https://www.sqlite.org/) (Current Development)
    *   Serverless, self-contained SQL engine for easy local setup.
*   **Production Ready**: Compatible with **PostgreSQL** (via `psycopg2-binary` driver installed).
*   **Local Storage**: Browser-based persistence for "Learning Path" / "My Goals" features.

## 5. DevOps & Infrastructure
*   **Automation**: Windows Batch Scripts (`.bat`)
    *   `launch_backend_only.bat`: One-click server start.
    *   `fix_env.bat`: Environment repair and dependency installation.
    *   `repair_database.bat`: Database migration and seeding utility.
*   **Version Control**: Git
