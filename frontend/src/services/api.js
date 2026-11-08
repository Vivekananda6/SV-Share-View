// frontend/src/services/api.js
import axios from 'axios';
import {
    clearTokens,
    getAccessToken,
    getRefreshToken,
    saveAccessToken,
} from './authStorage';

const configuredApiBaseUrl = (
    import.meta.env.VITE_API_BASE_URL || 'https://sv-share-view.onrender.com/api/'
).trim();
const markdownApiLink = configuredApiBaseUrl.match(/^\[([^\]]+)\]\((https?:\/\/[^)]+)\)$/);
const normalizedApiBaseUrl = markdownApiLink?.[1] === markdownApiLink?.[2]
    ? markdownApiLink[2]
    : configuredApiBaseUrl;
const apiBaseUrl = normalizedApiBaseUrl.endsWith('/')
    ? normalizedApiBaseUrl
    : `${normalizedApiBaseUrl}/`;

const api = axios.create({
    baseURL: apiBaseUrl,
    timeout: 90000,
});

export const getApiErrorMessage = (error, fallback) => {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;

    if (error.code === 'ECONNABORTED') {
        return 'The server did not respond in time. Wait a moment and retry; if this continues, check the backend service status.';
    }

    if (!error.response) {
        return 'Cannot reach the API server. Check that the backend service is running and that its URL is configured correctly.';
    }

    const endpoint = error.config?.url;
    return endpoint
        ? `${fallback} (request ${endpoint}, HTTP ${error.response.status}).`
        : fallback;
};

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
            const response = await axios.post(
                `${apiBaseUrl}token/refresh/`,
                { refresh },
                { timeout: api.defaults.timeout },
            );
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
