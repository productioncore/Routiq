// Calls gateway directly via VITE_API_URL.
import {
    generateCodeVerifier,
    generateCodeChallenge,
    OAUTH_STATE_KEY,
    OAUTH_VERIFIER_KEY,
} from '../utils/pkce';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface ApiResponse {
    success: boolean;
    message?: string;
    errors?: Array<{ field: string; message: string }>;
    [key: string]: unknown;
}

interface AuthResponse extends ApiResponse {
    user?: {
        id: string;
        email: string;
        displayName: string;
        avatar?: string;
        isEmailVerified: boolean;
        provider?: string;
        createdAt?: string;
    };
    accessToken?: string;
    refreshToken?: string;
    verificationPollToken?: string;
}

interface EmailCheckResponse extends ApiResponse {
    available: boolean;
}

interface RedeemEmailLinkResponse extends ApiResponse {
    kind?: string;
    formToken?: string;
    meta?: Record<string, string>;
}

interface MigrationVerifyResponse {
    success: boolean;
    message?: string;
    newEmail?: string;
    redirectTo?: 'login' | 'signup';
    bothVerified?: boolean;
    currentEmailVerified?: boolean;
    newEmailVerified?: boolean;
}

function getCsrfFromCookie(): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(/(?:^|;\s*)uam_csrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : null;
}

class ApiClient {
    private accessToken: string | null = null;
    /** In-memory CSRF — cookie path is /api/auth so document.cookie on /login cannot read it. */
    private csrfToken: string | null = null;
    private csrfInit: Promise<void> | null = null;

    constructor() {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
    }

    setTokens(accessToken: string, _refreshToken?: string): void {
        this.accessToken = accessToken;
    }

    clearTokens(): void {
        this.accessToken = null;
    }

    getAccessToken(): string | null {
        return this.accessToken;
    }

    /** Bootstrap CSRF token before any state-changing auth POST. */
    async ensureCsrf(): Promise<void> {
        if (this.csrfToken) {
            return;
        }
        if (!this.csrfInit) {
            this.csrfInit = fetch(`${API_BASE_URL}/auth/csrf`, {
                credentials: 'include',
            })
                .then((response) =>
                    this.parseJsonResponse<{ success: boolean; csrfToken?: string }>(response),
                )
                .then((data) => {
                    this.csrfToken = data.csrfToken ?? getCsrfFromCookie();
                });
        }
        await this.csrfInit;
    }

    /** Re-sync after login/register — server rotates the CSRF cookie. */
    private async syncCsrf(): Promise<void> {
        this.csrfToken = null;
        this.csrfInit = null;
        await this.ensureCsrf();
    }

    private sessionHeaders(): Record<string, string> {
        const headers: Record<string, string> = {};
        const csrf = this.csrfToken ?? getCsrfFromCookie();
        if (csrf) {
            headers['X-CSRF-Token'] = csrf;
        }
        return headers;
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {},
        opts?: { skipCsrf?: boolean },
    ): Promise<T> {
        const method = (options.method ?? 'GET').toUpperCase();
        if (!opts?.skipCsrf && method !== 'GET' && method !== 'HEAD') {
            await this.ensureCsrf();
        }

        const headers: HeadersInit = {
            'Content-Type': 'application/json',
            ...this.sessionHeaders(),
            ...(options.headers || {}),
        };

        if (this.accessToken) {
            (headers as Record<string, string>)['Authorization'] = `Bearer ${this.accessToken}`;
        }

        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers,
            credentials: 'include',
        });

        const data = await this.parseJsonResponse<T>(response);

        if (!response.ok) {
            throw data;
        }

        return data;
    }

    private async parseJsonResponse<T>(response: Response): Promise<T> {
        const contentType = response.headers.get('content-type') ?? '';
        if (!contentType.includes('application/json')) {
            throw new Error('Unexpected server response');
        }
        return response.json() as Promise<T>;
    }

    async checkEmail(email: string): Promise<EmailCheckResponse> {
        return this.request<EmailCheckResponse>('/auth/check-email', {
            method: 'POST',
            body: JSON.stringify({ email }),
        });
    }

    async register(email: string, password: string, displayName: string): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/register', {
            method: 'POST',
            body: JSON.stringify({ email, password, displayName }),
        });
        if (response.accessToken) {
            this.setTokens(response.accessToken);
        }
        await this.syncCsrf();
        return response;
    }

    async login(email: string, password: string): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });
        if (response.accessToken) {
            this.setTokens(response.accessToken);
        }
        await this.syncCsrf();
        return response;
    }

    async redeemEmailLink(code: string): Promise<RedeemEmailLinkResponse> {
        return this.request<RedeemEmailLinkResponse>('/auth/redeem-email-link', {
            method: 'POST',
            body: JSON.stringify({ code }),
        });
    }

    async verifyEmail(formToken: string, password: string): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/verify-email', {
            method: 'POST',
            body: JSON.stringify({ formToken, password }),
        });
        if (response.accessToken) {
            this.setTokens(response.accessToken);
        }
        return response;
    }

    async resendVerification(email: string): Promise<ApiResponse> {
        return this.request<ApiResponse>('/auth/resend-verification', {
            method: 'POST',
            body: JSON.stringify({ email }),
        });
    }

    async getVerificationStatus(pollToken: string): Promise<{ verified: boolean }> {
        return this.request<{ verified: boolean }>('/auth/verification-status', {
            method: 'POST',
            body: JSON.stringify({ pollToken }),
        });
    }

    async forgotPassword(email: string): Promise<ApiResponse> {
        return this.request<ApiResponse>('/auth/forgot-password', {
            method: 'POST',
            body: JSON.stringify({ email }),
        });
    }

    async resetPassword(formToken: string, password: string): Promise<ApiResponse> {
        return this.request<ApiResponse>('/auth/reset-password', {
            method: 'POST',
            body: JSON.stringify({ formToken, password }),
        });
    }

    async refreshToken(): Promise<AuthResponse> {
        await this.ensureCsrf();
        const response = await fetch(`${API_BASE_URL}/auth/refresh-token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...this.sessionHeaders(),
            },
            credentials: 'include',
            body: JSON.stringify({
                accessToken: this.accessToken ?? undefined,
            }),
        });

        const data = await this.parseJsonResponse<AuthResponse>(response);
        if (!response.ok) {
            throw data;
        }

        if (data.accessToken) {
            this.setTokens(data.accessToken);
        }
        await this.syncCsrf();

        return data;
    }

    async logout(): Promise<void> {
        const accessToken = this.accessToken;
        await this.ensureCsrf();
        try {
            await fetch(`${API_BASE_URL}/auth/logout`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...this.sessionHeaders(),
                },
                credentials: 'include',
                body: JSON.stringify({ accessToken }),
            });
        } catch {
            // best-effort
        }
        this.clearTokens();
        this.csrfToken = null;
        this.csrfInit = null;
    }

    async getMe(): Promise<AuthResponse> {
        return this.request<AuthResponse>('/auth/me');
    }

    async initiateMigration(password: string, newEmail: string, confirmOverride: boolean = false): Promise<ApiResponse & { code?: string; requiresConfirmation?: boolean; warning?: string }> {
        return this.request('/auth/migrate/init', {
            method: 'POST',
            body: JSON.stringify({ password, newEmail, confirmOverride: confirmOverride ? 'true' : undefined }),
        });
    }

    async verifyCurrentEmail(formToken: string): Promise<MigrationVerifyResponse> {
        return this.request<MigrationVerifyResponse>('/auth/migrate/verify-current', {
            method: 'POST',
            body: JSON.stringify({ formToken }),
        });
    }

    async verifyNewEmail(formToken: string): Promise<MigrationVerifyResponse> {
        return this.request<MigrationVerifyResponse>('/auth/migrate/verify-new', {
            method: 'POST',
            body: JSON.stringify({ formToken }),
        });
    }

    async getMigrationStatus(): Promise<{
        success: boolean;
        hasPendingMigration: boolean;
        currentEmail: string;
        newEmail: string | null;
        currentEmailVerified: boolean;
        newEmailVerified: boolean;
        migrationExpiry: string | null;
        cooldownRemaining: number;
        needsFinalization?: boolean;
        message?: string;
    }> {
        return this.request('/auth/migrate/status');
    }

    async finalizeMigration(): Promise<ApiResponse> {
        return this.request<ApiResponse>('/auth/migrate/finalize', {
            method: 'POST',
        });
    }

    async resendMigrationEmails(): Promise<ApiResponse & { cooldownRemaining?: number }> {
        return this.request('/auth/migrate/resend', {
            method: 'POST',
        });
    }

    async getMigrationHistory(): Promise<{
        success: boolean;
        history: Array<{
            fromEmail: string;
            toEmail: string;
            status: 'success' | 'failed' | 'pending' | 'reverted';
            initiatedAt: string;
            completedAt?: string;
            revertedAt?: string;
        }>;
    }> {
        return this.request('/auth/migrate/history');
    }

    async updateBio(bio: string): Promise<ApiResponse> {
        return this.request<ApiResponse>('/auth/profile/bio', {
            method: 'PUT',
            body: JSON.stringify({ bio }),
        });
    }

    async getOAuthProviders(): Promise<{ google: boolean; github: boolean }> {
        const data = await this.request<{ success: boolean; google: boolean; github: boolean }>(
            '/auth/oauth/providers',
            { method: 'GET' },
            { skipCsrf: true },
        );
        return { google: data.google, github: data.github };
    }

    async startOAuth(
        provider: 'google' | 'github',
        options?: { email?: string; prompt?: string },
    ): Promise<void> {
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = await generateCodeChallenge(codeVerifier);

        const prepared = await this.request<{ state: string }>('/auth/oauth/prepare', {
            method: 'POST',
            body: JSON.stringify({ codeChallenge }),
        });

        sessionStorage.setItem(OAUTH_VERIFIER_KEY, codeVerifier);
        sessionStorage.setItem(OAUTH_STATE_KEY, prepared.state);

        const params = new URLSearchParams({ state: prepared.state });
        if (provider === 'google') {
            if (options?.email) params.set('login_hint', options.email);
            if (options?.prompt) params.set('prompt', options.prompt);
            window.location.href = `${API_BASE_URL}/auth/google?${params.toString()}`;
            return;
        }
        window.location.href = `${API_BASE_URL}/auth/github?${params.toString()}`;
    }

    async exchangeOAuthCode(code: string, state: string, codeVerifier: string): Promise<AuthResponse> {
        const response = await this.request<AuthResponse>('/auth/oauth/exchange', {
            method: 'POST',
            body: JSON.stringify({ code, state, codeVerifier }),
        });
        if (response.accessToken) {
            this.setTokens(response.accessToken);
        }
        await this.syncCsrf();
        return response;
    }
}

export const api = new ApiClient();
export type { AuthResponse, EmailCheckResponse, ApiResponse };
