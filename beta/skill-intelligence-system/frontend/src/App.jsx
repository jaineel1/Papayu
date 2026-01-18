import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Navbar from './components/Navbar';
import LandingPage from './pages/LandingPage';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import UserProfile from './pages/UserProfile';
import RoleExplorer from './pages/RoleExplorer';
import LearningHub from './pages/LearningHub';
import ProjectsHub from './pages/ProjectsHub';

const ProtectedRoute = ({ children }) => {
    const { user, loading } = useAuth();
    if (loading) return <div style={{ padding: '2rem', color: 'white' }}>Loading...</div>;
    if (!user) return <Navigate to="/login" />;
    return children;
};

function AppRoutes() {
    return (
        <>
            <Navbar />
            <main style={{ flex: 1 }}>
                <Routes>
                    <Route path="/" element={<LandingPage />} />
                    <Route path="/" element={<LandingPage />} />
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />

                    <Route path="/dashboard" element={
                        <ProtectedRoute><Dashboard /></ProtectedRoute>
                    } />
                    <Route path="/profile" element={
                        <ProtectedRoute><UserProfile /></ProtectedRoute>
                    } />
                    <Route path="/roles" element={
                        <ProtectedRoute><RoleExplorer /></ProtectedRoute>
                    } />
                    <Route path="/hub" element={
                        <ProtectedRoute><LearningHub /></ProtectedRoute>
                    } />
                    <Route path="/projects" element={
                        <ProtectedRoute><ProjectsHub /></ProtectedRoute>
                    } />
                </Routes>
            </main>
            <footer style={{
                textAlign: 'center',
                padding: '2rem',
                color: 'var(--text-secondary)',
                borderTop: '1px solid rgba(255,255,255,0.05)'
            }}>
                <p className="text-sm">© 2026 Holistic Skill Intelligence System</p>
            </footer>
        </>
    );
}

export default function App() {
    return (
        <BrowserRouter>
            <AuthProvider>
                <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
                    <AppRoutes />
                </div>
            </AuthProvider>
        </BrowserRouter>
    );
}
