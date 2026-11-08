// frontend/src/services/auth.js
import api from './api';
import { clearTokens, getAccessToken, saveTokens } from './authStorage';

export const login = async (username, password) => {
    clearTokens();
    const response = await api.post('token/', { username, password });
    const { access, refresh } = response.data || {};
    if (typeof access !== 'string' || !access || typeof refresh !== 'string' || !refresh) {
        clearTokens();
        const error = new Error('The server returned an invalid sign-in response. Please try again.');
        error.code = 'AUTH_INVALID_TOKEN_RESPONSE';
        throw error;
    }

    saveTokens({ access, refresh });
    return response.data;
};

export const register = async (username, password, email = '') => {
    return api.post('register/', { username, password, email });
};

export const logout = clearTokens;

export const getCurrentUser = () => {
    return getAccessToken();
};
