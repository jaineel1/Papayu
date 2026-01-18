import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function LandingPage() {
    const { user } = useAuth();
    return (
        <div className="animate-fade-in">
            {/* Hero */}
            <section style={{
                textAlign: 'center',
                padding: '6rem 2rem',
                background: 'linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-primary) 100%)'
            }}>
                <div className="container">
                    <h1 style={{ fontSize: '3.5rem', fontWeight: '800', marginBottom: '1.5rem', lineHeight: '1.2' }}>
                        Future-Proof Your Career in <br />
                        <span style={{ color: 'var(--brand-primary)' }}>Healthcare</span>, <span style={{ color: 'var(--brand-secondary)' }}>AgriTech</span> & Smart Cities
                    </h1>
                    <p style={{ fontSize: '1.25rem', color: 'var(--text-secondary)', maxWidth: '800px', margin: '0 auto 2.5rem' }}>
                        A living intelligence platform that maps your skills to real-world job requirements, finds your gaps, and builds a personalized learning path.
                    </p>
                    <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                        <Link to={user ? "/dashboard" : "/login"} className="btn btn-primary" style={{ padding: '0.75rem 2rem', fontSize: '1.1rem' }}>
                            {user ? "Go to Dashboard" : "Get Started"}
                        </Link>
                        <Link to="/about" className="btn btn-secondary" style={{ padding: '0.75rem 2rem', fontSize: '1.1rem', background: 'rgba(255,255,255,0.1)' }}>Learn More</Link>
                    </div>
                </div>
            </section>

            {/* Features */}
            <section className="container" style={{ padding: '4rem 2rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '2rem' }}>
                <div className="card">
                    <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>🎯</div>
                    <h3 className="heading">Role Matching</h3>
                    <p className="text-secondary">AI-driven analysis of your profile against 50+ emerging job roles.</p>
                </div>
                <div className="card">
                    <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>📊</div>
                    <h3 className="heading">Gap Analysis</h3>
                    <p className="text-secondary">Don't just guess. See exactly which skills (and what proficiency level) you are missing.</p>
                </div>
                <div className="card">
                    <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>📚</div>
                    <h3 className="heading">Curated Learning</h3>
                    <p className="text-secondary">Direct links to Coursera, Udemy, and Certification providers to close your gaps.</p>
                </div>
            </section>
        </div>
    );
}
