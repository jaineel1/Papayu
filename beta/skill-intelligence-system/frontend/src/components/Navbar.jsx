import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
    const { user, logout } = useAuth();
    const navigate = useNavigate();

    const handleLogout = () => {
        logout();
        navigate('/');
    };

    return (
        <nav style={{
            backgroundColor: 'var(--bg-secondary)',
            borderBottom: '1px solid rgba(255,255,255,0.1)',
            padding: '1rem 2rem'
        }}>
            <div className="container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 0 }}>
                <Link to="/" style={{ color: 'white', fontWeight: 'bold', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '24px', height: '24px', background: 'var(--brand-secondary)', borderRadius: '4px' }}></div>
                    SkillIntel.ai
                </Link>

                {user ? (
                    <>
                        <div style={{ display: 'flex', gap: '2rem' }}>
                            <Link to="/dashboard" style={{ color: 'var(--text-secondary)' }}>Dashboard</Link>
                            <Link to="/roles" style={{ color: 'var(--text-secondary)' }}>Jobs</Link>
                            <Link to="/hub" style={{ color: 'var(--text-secondary)' }}>Learning Hub</Link>
                            <Link to="/projects" style={{ color: 'var(--text-secondary)' }}>Projects</Link>
                            <Link to="/profile" style={{ color: 'var(--text-secondary)' }}>Profile</Link>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                            <span className="text-sm text-secondary">Hi, {user.name.split(' ')[0]}</span>
                            <button
                                onClick={handleLogout}
                                className="btn"
                                style={{ fontSize: '0.9rem', color: 'var(--error)', background: 'transparent', padding: '0.2rem' }}
                            >
                                Logout
                            </button>
                        </div>
                    </>
                ) : (
                    <div style={{ display: 'flex', gap: '1rem' }}>
                        <Link to="/login" className="btn btn-primary">Login</Link>
                    </div>
                )}
            </div>
        </nav>
    );
}
