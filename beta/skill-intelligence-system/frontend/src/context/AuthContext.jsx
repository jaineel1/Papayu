import React, { createContext, useState, useContext, useEffect } from 'react';
import {
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged,
    updateProfile
} from 'firebase/auth';
import { auth } from '../firebase';
import { api } from '../services/api'; // Keep api for data, but not for auth token

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
            if (currentUser) {
                // Try to sync with backend
                let backendId = null;
                try {
                    const res = await api.get(`/users/by-email/${currentUser.email}`);
                    backendId = res.data.id;
                } catch (err) {
                    console.log("Backend user not found, creating new record...");
                    try {
                        // Auto-create if missing
                        const createRes = await api.post('/users/', {
                            full_name: currentUser.displayName || currentUser.email.split('@')[0],
                            email: currentUser.email,
                            current_role_title: "Student", // Default
                            password: "firebase_managed"
                        });
                        backendId = createRes.data.id;
                    } catch (createErr) {
                        console.error("Failed to auto-create backend user", createErr);
                    }
                }

                setUser({
                    uid: currentUser.uid,
                    email: currentUser.email,
                    name: currentUser.displayName || currentUser.email.split('@')[0],
                    photoURL: currentUser.photoURL,
                    id: backendId // Store backend ID
                });
            } else {
                setUser(null);
            }
            setLoading(false);
        });

        return () => unsubscribe();
    }, []);

    const login = async (email, password) => {
        try {
            await signInWithEmailAndPassword(auth, email, password);
            return { success: true };
        } catch (error) {
            console.error("Login failed", error);
            let msg = "Login failed";
            if (error.code === 'auth/invalid-credential') msg = "Invalid email or password.";
            return { success: false, error: msg };
        }
    };

    const register = async (fullName, email, password, role) => {
        try {
            // 1. Create User in Firebase
            const userCredential = await createUserWithEmailAndPassword(auth, email, password);

            // 2. Update Firebase Profile
            await updateProfile(userCredential.user, {
                displayName: fullName
            });

            // 3. Create User in Backend
            let backendId = null;
            try {
                const res = await api.post('/users/', {
                    full_name: fullName,
                    email: email,
                    password: "firebase_managed", // Dummy
                    current_role_title: role || "Student"
                });
                backendId = res.data.id;
            } catch (err) {
                console.error("Backend creation failed", err);
            }

            setUser({
                uid: userCredential.user.uid,
                email: email,
                name: fullName,
                id: backendId
            });
            return { success: true };
        } catch (error) {
            console.error("Register failed", error);
            let msg = "Registration failed";
            if (error.code === 'auth/email-already-in-use') msg = "Email already in use.";
            return { success: false, error: msg };
        }
    };

    const logout = async () => {
        try {
            await signOut(auth);
        } catch (error) {
            console.error("Logout failed", error);
        }
    };

    return (
        <AuthContext.Provider value={{ user, login, register, logout, loading }}>
            {!loading && children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
