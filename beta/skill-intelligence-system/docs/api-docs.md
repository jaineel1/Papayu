# API Documentation

## Base URL
`http://localhost:8000`

## Endpoints

### Users
- `POST /users/`: Create a profile.
- `GET /users/{id}`: Get profile details.
- `POST /users/{id}/skills`: Add skills to profile.

### Roles
- `GET /roles/`: List all available roles.
- `GET /roles/{id}`: Get role details.
- `GET /roles/recommend/{user_id}`: Get recommended roles based on readiness.

### Analytics
- `GET /analytics/gap/{user_id}/{role_id}`: Get detailed gap analysis.
