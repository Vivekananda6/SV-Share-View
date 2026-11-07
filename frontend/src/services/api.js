// frontend/src/services/api.js
import axios from 'axios';
import {
    clearTokens,
    getAccessToken,
    getRefreshToken,
    saveAccessToken,
} from './authStorage';

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL
    || '/api/';

const api = axios.create({
    baseURL: apiBaseUrl,
});

api.interceptors.request.use(
    (config) => {
        const token = getAccessToken();
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

const expireAuthentication = () => {
    clearTokens();
    window.dispatchEvent(new Event('sv:auth-expired'));
};

api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const request = error.config;
        const refresh = getRefreshToken();
        const isTokenRequest = request?.url?.includes('token/');

        if (error.response?.status !== 401 || !request || request._retry || isTokenRequest) {
            return Promise.reject(error);
        }

        if (!refresh) {
            expireAuthentication();
            return Promise.reject(error);
        }

        request._retry = true;
        try {
            const response = await axios.post(`${apiBaseUrl}token/refresh/`, { refresh });
            saveAccessToken(response.data.access);
            request.headers.Authorization = `Bearer ${response.data.access}`;
            return api(request);
        } catch (refreshError) {
            expireAuthentication();
            return Promise.reject(refreshError);
        }
    }
);

export default api;
