const ACCESS_TOKEN_KEY = 'access';
const REFRESH_TOKEN_KEY = 'refresh';

localStorage.removeItem(ACCESS_TOKEN_KEY);
localStorage.removeItem(REFRESH_TOKEN_KEY);

export const getAccessToken = () => sessionStorage.getItem(ACCESS_TOKEN_KEY);

export const getRefreshToken = () => sessionStorage.getItem(REFRESH_TOKEN_KEY);

export const saveTokens = ({ access, refresh }) => {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, access);
    sessionStorage.setItem(REFRESH_TOKEN_KEY, refresh);
};

export const saveAccessToken = (access) => {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, access);
};

export const clearTokens = () => {
    sessionStorage.removeItem(ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(REFRESH_TOKEN_KEY);
};
