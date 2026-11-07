// frontend/src/services/auth.js
import api from './api';
import { clearTokens, getAccessToken, saveTokens } from './authStorage';

export const login = async (username, password) => {
    const response = await api.post('token/', { username, password });
    if (response.data.access) {
        saveTokens(response.data);
    }

    return response.data;
};

export const register = async (username, password, email = '') => {
    return api.post('register/', { username, password, email });
};

export const logout = clearTokens;

export const getCurrentUser = () => {
    return getAccessToken();
};
