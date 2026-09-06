import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api, type AuthResponse } from '../api/client';
import { saveRecentAccount, clearAllRecentAccounts } from '../utils/recentAccounts';
import { sanitizeAvatarUrl } from '../utils/security';

interface User {
    id: string;
    email: string;
    displayName: string;
    avatar?: string;
    bio?: string;
    isEmailVerified: boolean;
    provider?: string;
    createdAt?: string;
}

interface AuthContextType {
    user: User | null;
    isLoading: boolean;
    isAuthenticated: boolean;
    login: (email: string, password: string) => Promise<AuthResponse>;
    register: (email: string, password: string, displayName: string) => Promise<AuthResponse>;
    logout: () => Promise<void>;
    refreshUser: () => Promise<void>;
    setUserFromOAuth: (accessToken: string, refreshToken: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const useAuth = (): AuthContextType => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

interface AuthProviderProps {
    children: React.ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    const refreshUser = useCallback(async () => {
        try {
            let token = api.getAccessToken();
            if (!token) {
                try {
                    await api.refreshToken();
                    token = api.getAccessToken();
                } catch {
                    setUser(null);
                    return;
                }
            }

            const response = await api.getMe();
            if (response.success && response.user) {
                setUser(response.user);
                saveRecentAccount({
                    email: response.user.email,
                    displayName: response.user.displayName,
                    avatar: sanitizeAvatarUrl(response.user.avatar),
                    provider: response.user.provider || 'local',
                });
            } else {
                setUser(null);
                api.clearTokens();
            }
        } catch {
            try {
                await api.refreshToken();
                const response = await api.getMe();
                if (response.success && response.user) {
                    setUser(response.user);
                } else {
                    setUser(null);
                    api.clearTokens();
                }
            } catch {
                setUser(null);
                api.clearTokens();
            }
        }
    }, []);

    useEffect(() => {
        const initAuth = async () => {
            try {
                await api.ensureCsrf();
                await refreshUser();
            } catch {
                // CORS error or gateway unreachable — app still works, just unauthenticated
            } finally {
                setIsLoading(false);
            }
        };
        void initAuth();
    }, [refreshUser]);

    const login = async (email: string, password: string): Promise<AuthResponse> => {
        const response = await api.login(email, password);
        if (response.success && response.user) {
            setUser(response.user);
            saveRecentAccount({
                email: response.user.email,
                displayName: response.user.displayName,
                avatar: sanitizeAvatarUrl(response.user.avatar),
                provider: response.user.provider || 'local'
            });
        }
        return response;
    };

    const register = async (
        email: string,
        password: string,
        displayName: string
    ): Promise<AuthResponse> => {
        const response = await api.register(email, password, displayName);
        if (response.success && response.accessToken) {
            api.setTokens(response.accessToken);
            if (response.user) {
                setUser(response.user);
                saveRecentAccount({
                    email: response.user.email,
                    displayName: response.user.displayName,
                    avatar: sanitizeAvatarUrl(response.user.avatar),
                    provider: response.user.provider || 'local',
                });
            }
        }
        return response;
    };

    const logout = async () => {
        await api.logout();
        setUser(null);
        clearAllRecentAccounts();
    };

    const setUserFromOAuth = async (accessToken: string, _refreshToken: string) => {
        api.setTokens(accessToken);
        await refreshUser();
    };

    const value: AuthContextType = {
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        refreshUser,
        setUserFromOAuth,
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
