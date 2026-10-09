import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import oidcRoutes, { setupOIDC } from './oidc.js';
import userModel from '../models/user.js';
import internalToken from '../internal/token.js';
import { Issuer, generators } from 'openid-client';

const mockAuthorizationUrl = vi.fn(() => 'http://auth-url');
const mockCallbackParams = vi.fn(() => ({ code: 'test-code' }));
const mockCallback = vi.fn();

vi.mock('openid-client', async () => {
    const actual = await vi.importActual('openid-client');
    return {
        ...actual,
        Issuer: {
            discover: vi.fn(async () => {
                return {
                    Client: class {
                        constructor(config) {
                            this.config = config;
                        }
                        authorizationUrl = mockAuthorizationUrl;
                        callbackParams = mockCallbackParams;
                        callback = mockCallback;
                    }
                };
            })
        },
        generators: {
            state: vi.fn(() => 'test-state'),
            codeVerifier: vi.fn(() => 'test-verifier'),
            codeChallenge: vi.fn(() => 'test-challenge')
        }
    };
});

const mockQuery = {
    findOne: vi.fn(),
    insertAndFetch: vi.fn(),
    patchAndFetchById: vi.fn()
};

vi.mock('../models/user.js', () => ({
    default: {
        query: () => mockQuery
    }
}));
vi.mock('../internal/token.js', () => ({
    default: {
        getTokenFromUser: vi.fn(() => Promise.resolve({ token: 'test-jwt' }))
    }
}));
vi.mock('../logger.js', () => ({
    debug: vi.fn(),
    express: vi.fn()
}));

const app = express();
app.use(express.json());
app.use((req, res, next) => {
    if (req.headers.cookie) {
        req.cookies = {};
        req.headers.cookie.split(';').forEach(cookie => {
            const parts = cookie.split('=');
            req.cookies[parts.shift().trim()] = decodeURI(parts.join('='));
        });
    } else {
        req.cookies = {};
    }
    
    // Polyfill res.cookie and res.clearCookie for supertest if needed, 
    // but express already provides them! 
    next();
});
app.use('/api/oidc', oidcRoutes);

describe('OIDC Routes', () => {
    beforeEach(async () => {
        vi.clearAllMocks();
        process.env.OIDC_ISSUER_URL = 'http://test-issuer';
        process.env.OIDC_CLIENT_ID = 'test-client';
        process.env.OIDC_CLIENT_SECRET = 'test-secret';
        process.env.OIDC_ADMIN_GROUP = 'admin-group';
        await setupOIDC();
    });

    it('should return config enabled when configured', async () => {
        const res = await request(app).get('/api/oidc/config');
        expect(res.statusCode).toBe(200);
        expect(res.body.enabled).toBe(true);
    });

    it('should redirect to auth url on login', async () => {
        const res = await request(app).get('/api/oidc/login');
        expect(res.statusCode).toBe(302);
        expect(res.header.location).toBe('http://auth-url');
        expect(res.header['set-cookie'][0]).toContain('oidc_state=test-state');
    });

    it('should handle callback for new user and provision admin', async () => {
        mockCallback.mockResolvedValueOnce({
            claims: () => ({ email: 'test@example.com', groups: ['admin-group'], name: 'Test User' })
        });
        mockQuery.findOne.mockResolvedValueOnce(null);
        mockQuery.insertAndFetch.mockResolvedValueOnce({ id: 1, email: 'test@example.com', roles: ['admin'] });

        const res = await request(app)
            .get('/api/oidc/callback')
            .set('Cookie', ['oidc_state=test-state', 'oidc_code_verifier=test-verifier']);
        
        expect(res.statusCode).toBe(200);
        expect(res.text).toContain("localStorage.setItem('token', 'test-jwt')");
        expect(mockQuery.insertAndFetch).toHaveBeenCalledWith(expect.objectContaining({
            email: 'test@example.com',
            roles: ['admin']
        }));
    });

    it('should handle callback for existing user and update roles', async () => {
        mockCallback.mockResolvedValueOnce({
            claims: () => ({ email: 'test2@example.com', groups: ['admin-group'] })
        });
        mockQuery.findOne.mockResolvedValueOnce({ id: 2, email: 'test2@example.com', roles: [] });
        mockQuery.patchAndFetchById.mockResolvedValueOnce({ id: 2, email: 'test2@example.com', roles: ['admin'] });

        const res = await request(app)
            .get('/api/oidc/callback')
            .set('Cookie', ['oidc_state=test-state', 'oidc_code_verifier=test-verifier']);
        
        expect(res.statusCode).toBe(200);
        expect(mockQuery.patchAndFetchById).toHaveBeenCalledWith(2, { roles: ['admin'] });
    });
    
    it('should strip admin role if group removed', async () => {
        mockCallback.mockResolvedValueOnce({
            claims: () => ({ email: 'test3@example.com', groups: [] })
        });
        mockQuery.findOne.mockResolvedValueOnce({ id: 3, email: 'test3@example.com', roles: ['admin'] });
        mockQuery.patchAndFetchById.mockResolvedValueOnce({ id: 3, email: 'test3@example.com', roles: [] });

        const res = await request(app)
            .get('/api/oidc/callback')
            .set('Cookie', ['oidc_state=test-state', 'oidc_code_verifier=test-verifier']);
        
        expect(res.statusCode).toBe(200);
        expect(mockQuery.patchAndFetchById).toHaveBeenCalledWith(3, { roles: [] });
    });

    it('should fail if missing state in cookie', async () => {
        const res = await request(app).get('/api/oidc/callback');
        expect(res.statusCode).toBe(400);
        expect(res.body.error).toContain('Missing OIDC state');
    });
    
    it('should fail if OIDC provider returns no email', async () => {
        mockCallback.mockResolvedValueOnce({
            claims: () => ({ name: 'Test User' })
        });
        const res = await request(app)
            .get('/api/oidc/callback')
            .set('Cookie', ['oidc_state=test-state', 'oidc_code_verifier=test-verifier']);
            
        expect(res.statusCode).toBe(400);
        expect(res.body.error).toContain('email claim');
    });
});
