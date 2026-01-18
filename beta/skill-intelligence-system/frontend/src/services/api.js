import axios from 'axios';

const API_URL = 'http://localhost:8000';

export const api = axios.create({
    baseURL: API_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

export const userService = {
    create: (data) => api.post('/users/', data),
    get: (id) => api.get(`/users/${id}`),
    getByEmail: (email) => api.get(`/users/by-email/${email}`),
    update: (id, data) => api.put(`/users/${id}`, data),
    addSkill: (userId, skillId, level) => api.post(`/users/${userId}/skills`, {
        skill_id: skillId,
        proficiency_level: level
    }),
    removeSkill: (userId, skillId) => api.delete(`/users/${userId}/skills/${skillId}`),
};

export const roleService = {
    list: () => api.get('/roles/'),
    get: (id) => api.get(`/roles/${id}`),
    recommend: (userId) => api.get(`/roles/recommend/${userId}`),
    simulate: (data) => api.post('/roles/simulate', data),
};

export const projectService = {
    recommend: (userId) => api.get(`/projects/recommend/${userId}`),
};

