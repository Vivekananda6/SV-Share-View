import { useEffect, useState } from 'react';
import api from '../services/api';

const getInitials = (text) => (text || '?')
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0])
    .join('')
    .toUpperCase();

const AuthenticatedAvatar = ({ username, fallbackText, src, className = '' }) => {
    const [loadedImage, setLoadedImage] = useState(null);

    useEffect(() => {
        if (!src) return undefined;

        const controller = new AbortController();
        let objectUrl = '';
        let active = true;
        api.get(src, { responseType: 'blob', signal: controller.signal })
            .then((response) => {
                if (!active) return;
                if (!response.data.type.startsWith('image/')) {
                    setLoadedImage({ src, url: '', unavailable: true });
                    return;
                }
                objectUrl = window.URL.createObjectURL(response.data);
                if (active) setLoadedImage({ src, url: objectUrl });
            })
            .catch(() => {
                if (active && !controller.signal.aborted) {
                    setLoadedImage({ src, url: '', unavailable: true });
                }
            });

        return () => {
            active = false;
            controller.abort();
            if (objectUrl) window.URL.revokeObjectURL(objectUrl);
        };
    }, [src]);

    const imageUrl = loadedImage?.src === src ? loadedImage.url : '';
    return imageUrl
        ? <img className={className} src={imageUrl} alt={`${username}'s profile`} />
        : <span
            className={className}
            role="img"
            title={loadedImage?.src === src && loadedImage.unavailable ? 'Profile photo unavailable; showing initials.' : undefined}
            aria-label={`${username}'s initials`}
        >
            {getInitials(fallbackText || username)}
        </span>;
};

export default AuthenticatedAvatar;
