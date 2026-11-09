// src/pages/Dashboard.jsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
    Shield, Upload, FileText, LogOut, Lock, Download, Share2, Users,
    RefreshCw, Clock3, Files, Activity,
} from 'lucide-react';
import api, { getApiErrorMessage } from '../services/api';
import { logout } from '../services/auth';
import AuthenticatedAvatar from '../components/AuthenticatedAvatar';

const localDateTimeValue = (date) => {
    const localDate = new Date(date);
    localDate.setMinutes(localDate.getMinutes() - localDate.getTimezoneOffset());
    return localDate.toISOString().slice(0, 16);
};

const describeResponseShape = (data) => {
    if (data === null) return 'null';
    if (Array.isArray(data)) return `array with ${data.length} items`;
    if (typeof data === 'object') {
        const keys = Object.keys(data);
        return `object with keys: ${keys.length ? keys.join(', ') : '(none)'}`;
    }
    return typeof data;
};

const getListData = (data, resource) => {
    const list = Array.isArray(data) ? data : data?.results;
    if (!Array.isArray(list)) {
        throw new Error(
            `The API returned an invalid ${resource} response (expected a list; received ${describeResponseShape(data)}).`,
        );
    }
    return list;
};

const Dashboard = ({ onLogout }) => {
    const [files, setFiles] = useState([]);
    const [shares, setShares] = useState([]);
    const [sharedFiles, setSharedFiles] = useState([]);
    const [shareUsernames, setShareUsernames] = useState({});
    const [shareExpiries, setShareExpiries] = useState({});
    const [sharePermissions, setSharePermissions] = useState({});
    const [revisionFiles, setRevisionFiles] = useState({});
    const [documentMetadata, setDocumentMetadata] = useState({});
    const [filePasscodes, setFilePasscodes] = useState({});
    const [sharedPasscodes, setSharedPasscodes] = useState({});
    const [logs, setLogs] = useState([]);
    const [recentActivityCount, setRecentActivityCount] = useState(0);
    const [account, setAccount] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [updatingAvatar, setUpdatingAvatar] = useState(false);
    const [uploadCategory, setUploadCategory] = useState('Uncategorized');
    const [searchText, setSearchText] = useState('');
    const [categoryFilter, setCategoryFilter] = useState('');
    const [ownerFilter, setOwnerFilter] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [refreshing, setRefreshing] = useState(false);
    const [lastUpdated, setLastUpdated] = useState(null);
    const fetchInProgress = useRef(false);
    const refreshQueued = useRef(false);
    const fetchDataRef = useRef(null);

    const fetchData = useCallback(async () => {
        if (fetchInProgress.current) {
            refreshQueued.current = true;
            return;
        }
        fetchInProgress.current = true;
        setRefreshing(true);
        const requests = [
            ['documents', api.get('files/')],
            ['activity', api.get('activity/summary/')],
            ['shares', api.get('shares/')],
            ['shared documents', api.get('shared-with-me/')],
            ['account', api.get('account/')],
        ];
        try {
            const results = await Promise.allSettled(requests.map(([, request]) => request));
            const failures = [];

            results.forEach((result, index) => {
                if (result.status === 'rejected') {
                    failures.push(
                        `${requests[index][0]}: ${getApiErrorMessage(
                            result.reason,
                            'request failed',
                        )}`,
                    );
                    return;
                }

                try {
                    switch (index) {
                        case 0:
                            setFiles(getListData(result.value.data, 'documents'));
                            break;
                        case 1: {
                            const activity = result.value.data;
                            const events = getListData(activity?.events, 'activity');
                            setLogs(events);
                            setRecentActivityCount(activity.count_24h);
                            break;
                        }
                        case 2:
                            setShares(getListData(result.value.data, 'shares'));
                            break;
                        case 3:
                            setSharedFiles(getListData(result.value.data, 'shared documents'));
                            break;
                        case 4:
                            setAccount(result.value.data);
                            break;
                        default:
                            break;
                    }
                } catch (responseError) {
                    failures.push(
                        `${requests[index][0]}: ${responseError.message}`,
                    );
                }
            });

            if (!failures.length) {
                setLastUpdated(new Date());
            }
            setError(failures.length ? `Some vault data could not be loaded — ${failures.join(' ')}` : '');
        } finally {
            fetchInProgress.current = false;
            setLoading(false);
            setRefreshing(false);
            if (refreshQueued.current) {
                refreshQueued.current = false;
                window.setTimeout(() => fetchDataRef.current?.(), 0);
            }
        }
    }, []);

    useEffect(() => {
        fetchDataRef.current = fetchData;
        const refreshWhenVisible = () => {
            if (document.visibilityState === 'visible') fetchData();
        };
        const initialRefresh = window.setTimeout(() => fetchDataRef.current?.(), 0);
        const interval = window.setInterval(refreshWhenVisible, 15000);
        window.addEventListener('focus', refreshWhenVisible);
        document.addEventListener('visibilitychange', refreshWhenVisible);
        return () => {
            window.clearTimeout(initialRefresh);
            window.clearInterval(interval);
            window.removeEventListener('focus', refreshWhenVisible);
            document.removeEventListener('visibilitychange', refreshWhenVisible);
        };
    }, [fetchData]);

    const handleFileUpload = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);
        formData.append('title', file.name);
        formData.append('category', uploadCategory);
        setUploading(true);
        setError('');

        try {
            await api.post('files/', formData);
            await fetchData();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Failed to upload file.');
        } finally {
            setUploading(false);
            e.target.value = '';
        }
    };

    const handleAvatarUpload = async (event) => {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) return;
        if (file.size > 2 * 1024 * 1024) {
            setError('Profile photos must be no larger than 2 MB.');
            return;
        }
        if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
            setError('Choose a JPEG, PNG, or WebP profile photo.');
            return;
        }

        const formData = new FormData();
        formData.append('avatar', file);
        setUpdatingAvatar(true);
        setError('');
        try {
            await api.patch('account/profile-photo/', formData);
            await fetchData();
        } catch (requestError) {
            setError(getApiErrorMessage(requestError, 'Could not update your profile photo.'));
        } finally {
            setUpdatingAvatar(false);
        }
    };

    const handleAvatarRemove = async () => {
        setUpdatingAvatar(true);
        setError('');
        try {
            await api.delete('account/profile-photo/');
            await fetchData();
        } catch (requestError) {
            setError(getApiErrorMessage(requestError, 'Could not remove your profile photo.'));
        } finally {
            setUpdatingAvatar(false);
        }
    };

    const handleFileDownload = async (fileId, fileName) => {
        try {
            const response = await api.get(`files/${fileId}/download/`, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', fileName);
            document.body.appendChild(link);
            link.click();
            link.remove();
            fetchData(); // Refresh logs to show the new download action
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Failed to download file.');
        }
    };

    const handleMetadataSave = async (e, file) => {
        e.preventDefault();
        const metadata = documentMetadata[file.id] || {};
        try {
            await api.patch(`files/${file.id}/`, {
                title: metadata.title ?? file.title,
                category: metadata.category ?? file.category,
            });
            setDocumentMetadata((current) => {
                const next = { ...current };
                delete next[file.id];
                return next;
            });
            await fetchData();
        } catch (requestError) {
            const data = requestError.response?.data;
            const detail = data?.detail || (data && Object.values(data).flat().join(' '));
            setError(typeof detail === 'string' ? detail : 'Could not update document details.');
        }
    };

    const handleFileDelete = async (file) => {
        if (!window.confirm(`Permanently delete "${file.title}" and revoke all shares?`)) {
            return;
        }
        try {
            await api.delete(`files/${file.id}/`);
            await fetchData();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not delete the document.');
        }
    };

    const handleSharedFileDownload = async (e, shareId, fileName) => {
        e.preventDefault();
        try {
            const response = await api.post(
                `shared-with-me/${shareId}/download/`,
                { passcode: sharedPasscodes[shareId] || '' },
                { responseType: 'blob' },
            );
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
            setSharedPasscodes((current) => ({ ...current, [shareId]: '' }));
            await fetchData();
        } catch (requestError) {
            let message = 'Could not download. Check the PIN and sharing status.';
            let responseData = requestError.response?.data;
            if (responseData instanceof Blob) {
                const responseText = await responseData.text();
                if (responseText) {
                    try {
                        responseData = JSON.parse(responseText);
                    } catch {
                        responseData = null;
                    }
                }
            }
            if (typeof responseData?.detail === 'string') {
                message = responseData.detail;
            }
            setError(message);
        }
    };

    const handleRevisionDownload = async (revisionId, fileName) => {
        try {
            const response = await api.get(`revisions/${revisionId}/download/`, {
                responseType: 'blob',
            });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
            await fetchData();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not download the edited copy.');
        }
    };

    const handleSharedFileReplace = async (e, shareId) => {
        e.preventDefault();
        const file = revisionFiles[shareId];
        if (!file) {
            setError('Choose the replacement file.');
            return;
        }
        if (!window.confirm(
            'Replace the original file for its owner and all recipients? This cannot be undone.',
        )) {
            return;
        }
        const formData = new FormData();
        formData.append('file', file);
        formData.append('passcode', sharedPasscodes[shareId] || '');
        try {
            await api.post(`shared-with-me/${shareId}/replace/`, formData);
            setRevisionFiles((current) => ({ ...current, [shareId]: null }));
            setSharedPasscodes((current) => ({ ...current, [shareId]: '' }));
            await fetchData();
        } catch (requestError) {
            const data = requestError.response?.data;
            const detail = data?.detail || (data && Object.values(data).flat().join(' '));
            setError(typeof detail === 'string' ? detail : 'Could not replace the original file.');
        }
    };

    const handleSetPasscode = async (e, fileId) => {
        e.preventDefault();
        setError('');
        try {
            await api.put(`files/${fileId}/passcode/`, {
                passcode: filePasscodes[fileId] || '',
            });
            setFilePasscodes((current) => ({ ...current, [fileId]: '' }));
            await fetchData();
        } catch (requestError) {
            const data = requestError.response?.data;
            const detail = data?.detail || (data && Object.values(data).flat().join(' '));
            setError(typeof detail === 'string' ? detail : 'Could not set the file passcode.');
        }
    };

    const handleRemovePasscode = async (fileId) => {
        try {
            await api.delete(`files/${fileId}/passcode/`);
            await fetchData();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not remove the file passcode.');
        }
    };

    const handleShare = async (e, fileId) => {
        e.preventDefault();
        setError('');
        const username = shareUsernames[fileId]?.trim();
        const expiry = shareExpiries[fileId];
        const payload = {
            username,
            permission: sharePermissions[fileId] || 'view',
        };
        if (expiry) payload.expires_at = new Date(expiry).toISOString();

        try {
            await api.post(`files/${fileId}/share/`, payload);
            setShareUsernames((current) => ({ ...current, [fileId]: '' }));
            setShareExpiries((current) => ({ ...current, [fileId]: '' }));
            setSharePermissions((current) => ({ ...current, [fileId]: 'view' }));
            await fetchData();
        } catch (requestError) {
            const data = requestError.response?.data;
            const detail = data?.detail || (data && Object.values(data).flat().join(' '));
            setError(typeof detail === 'string' ? detail : 'Could not share this file.');
        }
    };

    const handleRevokeShare = async (shareId) => {
        try {
            await api.delete(`shares/${shareId}/`);
            await fetchData();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not revoke file access.');
        }
    };

    const handleLogout = async () => {
        try {
            await api.post('logout/');
            logout();
            onLogout();
        } catch (requestError) {
            setError(
                requestError.response?.data?.detail
                    || 'Could not revoke your sessions. Please retry while connected.',
            );
        }
    };

    const normalizedSearch = searchText.trim().toLowerCase();
    const matchesFilters = (document) => {
        const owner = document.owner_username || '';
        const searchable = `${document.title} ${owner} ${document.category || ''}`.toLowerCase();
        return (!normalizedSearch || searchable.includes(normalizedSearch))
            && (!ownerFilter || owner.toLowerCase().includes(ownerFilter.trim().toLowerCase()))
            && (!categoryFilter || document.category === categoryFilter);
    };
    const visibleFiles = files.filter(matchesFilters);
    const visibleSharedFiles = sharedFiles.filter(matchesFilters);
    const categories = [...new Set(
        [...files, ...sharedFiles].map((document) => document.category).filter(Boolean),
    )].sort();

    return (
        <div className="dashboard-shell min-h-screen p-8 text-white max-w-7xl mx-auto">
            {/* Header */}
            <div className="dashboard-header flex justify-between items-center mb-8 glass-panel p-6">
                <div className="dashboard-brand flex items-center space-x-3">
                    <span className="brand-mark"><Shield aria-hidden="true" /></span>
                    <div>
                        <h1 className="text-xl font-bold tracking-wider">SV</h1>
                        <p className="text-xs text-slate-400">Share securely. View with confidence.</p>
                    </div>
                </div>
                <div className="dashboard-header-actions">
                    {account && (
                        <div className="dashboard-profile">
                            <AuthenticatedAvatar
                                className="dashboard-avatar"
                                username={account.username}
                                src={account.avatar_url}
                            />
                            <div className="dashboard-profile-actions">
                                <span className="dashboard-profile-name">{account.username}</span>
                                <div>
                                    <label className="dashboard-avatar-upload">
                                        {updatingAvatar ? 'Updating…' : account.has_avatar ? 'Change photo' : 'Add photo'}
                                        <input
                                            type="file"
                                            accept="image/jpeg,image/png,image/webp"
                                            aria-label="Upload profile photo"
                                            disabled={updatingAvatar}
                                            onChange={handleAvatarUpload}
                                        />
                                    </label>
                                    {account.has_avatar && (
                                        <button
                                            className="dashboard-avatar-remove"
                                            type="button"
                                            disabled={updatingAvatar}
                                            onClick={handleAvatarRemove}
                                        >
                                            Remove
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                    {account?.is_staff && (
                        <Link className="secondary-button admin-link" to="/control">
                            Admin portal
                        </Link>
                    )}
                    <span className="refresh-status" aria-live="polite">
                        <span className={`status-dot${refreshing ? ' is-refreshing' : ''}`} />
                        {lastUpdated
                            ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
                            : 'Connecting'}
                    </span>
                    <button
                        type="button"
                        onClick={() => fetchData()}
                        disabled={refreshing}
                        className="secondary-button"
                        aria-label="Refresh dashboard data"
                    >
                        <RefreshCw size={16} className={refreshing ? 'spin' : ''} />
                        <span>Refresh</span>
                    </button>
                    <button onClick={handleLogout} className="logout-button">
                    <LogOut size={16} aria-hidden="true" />
                    <span>Logout</span>
                    </button>
                </div>
            </div>

            {error && <div className="mb-4 p-3 bg-red-500/20 border border-red-500/50 rounded-lg text-red-200 text-sm">{error}</div>}

            <section className="dashboard-summary" aria-label="Vault overview">
                <article className="summary-card">
                    <span className="summary-icon"><Files size={18} /></span>
                    <div><p>Your documents</p><strong>{files.length}</strong></div>
                </article>
                <article className="summary-card">
                    <span className="summary-icon summary-icon-violet"><Users size={18} /></span>
                    <div><p>Shared with you</p><strong>{sharedFiles.length}</strong></div>
                </article>
                <article className="summary-card">
                    <span className="summary-icon summary-icon-green"><Activity size={18} /></span>
                    <div><p>Activity in the last 24 hours</p><strong>{recentActivityCount}</strong></div>
                </article>
            </section>

            <div className="dashboard-grid">
                {/* Upload & Files Section */}
                <div className="dashboard-primary space-y-6">
                    <div className="dashboard-card glass-panel p-6">
                        <h2 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                            <Lock size={18} className="text-blue-400" />
                            <span>Secure Vault Upload</span>
                        </h2>
                        <label className="flex flex-col gap-1 text-xs text-slate-400 mb-3">
                            Category
                            <input
                                type="text"
                                value={uploadCategory}
                                maxLength={100}
                                onChange={(e) => setUploadCategory(e.target.value)}
                                placeholder="e.g. Contracts, Reports"
                                className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                            />
                            <span className="text-slate-500">
                                Categories help organize and filter documents; they do not change who can access them.
                            </span>
                        </label>
                        <label className="border-2 border-dashed border-white/20 rounded-2xl p-8 flex flex-col items-center justify-center cursor-pointer hover:border-blue-500 transition-colors block text-center">
                            <Upload className="text-blue-400 w-10 h-10 mb-2 mx-auto" />
                            <span className="text-sm font-medium block">{uploading ? 'Encrypting & Uploading...' : 'Choose a file to secure'}</span>
                            <span className="text-xs text-slate-400 mt-1 block">Files are encrypted with AES-256-GCM before storage (100 MB limit)</span>
                            <input type="file" onChange={handleFileUpload} className="hidden" disabled={uploading} />
                        </label>
                    </div>

                    <div className="dashboard-card glass-panel p-6">
                        <div className="section-heading">
                            <div>
                                <span className="eyebrow">YOUR WORKSPACE</span>
                                <h2 className="text-lg font-semibold">Documents</h2>
                            </div>
                            <span className="result-count">{visibleFiles.length + visibleSharedFiles.length} matching</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 mb-4">
                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                Search name, owner, or category
                                <input
                                    type="search"
                                    value={searchText}
                                    onChange={(e) => setSearchText(e.target.value)}
                                    placeholder="Search documents"
                                    className="min-w-0 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white"
                                />
                            </label>
                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                Owner
                                <input
                                    type="search"
                                    value={ownerFilter}
                                    onChange={(e) => setOwnerFilter(e.target.value)}
                                    placeholder="Username"
                                    className="min-w-0 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white"
                                />
                            </label>
                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                Category
                                <select
                                    value={categoryFilter}
                                    onChange={(e) => setCategoryFilter(e.target.value)}
                                    className="min-w-0 bg-slate-900 border border-white/10 rounded-lg px-3 py-2 text-sm text-white"
                                >
                                    <option value="">All categories</option>
                                    {categories.map((category) => <option key={category} value={category}>{category}</option>)}
                                </select>
                            </label>
                        </div>
                        <div className="space-y-3">
                            {loading && <p className="text-sm text-slate-400">Loading your vault...</p>}
                            {!loading && visibleFiles.length === 0 ? (
                                <p className="text-sm text-slate-400">
                                    {files.length ? 'No owned documents match these filters.' : 'No files in your vault yet.'}
                                </p>
                            ) : !loading && (
                                visibleFiles.map(f => {
                                    const fileShares = shares.filter((share) => share.file_id === f.id);
                                    return (
                                    <div key={f.id} className="bg-white/5 p-4 rounded-xl border border-white/10 space-y-3">
                                        <div className="flex justify-between items-center gap-3">
                                            <div className="flex items-center space-x-3 min-w-0">
                                                <FileText className="text-blue-400 shrink-0" size={20} />
                                                <div className="min-w-0">
                                                    <p className="font-medium text-sm break-all">{f.title}</p>
                                                    <p className="text-xs text-slate-400">
                                                        {f.category} · Uploaded {new Date(f.uploaded_at).toLocaleDateString()} · {f.file_size} bytes
                                                    </p>
                                                </div>
                                            </div>
                                            <div className="flex gap-2 shrink-0">
                                                <button
                                                    onClick={() => handleFileDownload(f.id, f.title)}
                                                    className="flex items-center space-x-1.5 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/50 px-3 py-1.5 rounded-lg text-blue-200 text-xs transition-colors"
                                                >
                                                    <Download size={14} />
                                                    <span>Download</span>
                                                </button>
                                                <button
                                                    onClick={() => handleFileDelete(f)}
                                                    className="rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 px-3 py-1.5 text-red-200 text-xs"
                                                >
                                                    Delete
                                                </button>
                                            </div>
                                        </div>

                                        <form onSubmit={(e) => handleMetadataSave(e, f)} className="grid grid-cols-1 sm:grid-cols-[1fr_1fr_auto] gap-2 border-t border-white/10 pt-3">
                                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                                Document name
                                                <input
                                                    type="text"
                                                    maxLength={255}
                                                    value={documentMetadata[f.id]?.title ?? f.title}
                                                    onChange={(e) => setDocumentMetadata((current) => ({
                                                        ...current,
                                                        [f.id]: { ...current[f.id], title: e.target.value },
                                                    }))}
                                                    required
                                                    className="min-w-0 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white"
                                                />
                                            </label>
                                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                                Category
                                                <input
                                                    type="text"
                                                    maxLength={100}
                                                    value={documentMetadata[f.id]?.category ?? f.category}
                                                    onChange={(e) => setDocumentMetadata((current) => ({
                                                        ...current,
                                                        [f.id]: { ...current[f.id], category: e.target.value },
                                                    }))}
                                                    required
                                                    className="min-w-0 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white"
                                                />
                                            </label>
                                            <button type="submit" className="self-end rounded-lg bg-blue-500/20 border border-blue-500/50 px-3 py-2 text-sm text-blue-200">
                                                Save details
                                            </button>
                                        </form>

                                        <form onSubmit={(e) => handleSetPasscode(e, f.id)} className="grid grid-cols-1 sm:grid-cols-[1fr_auto_auto] gap-2 border-t border-white/10 pt-3">
                                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                                {f.has_passcode ? 'Change file PIN' : 'Set a 6-digit file PIN before sharing'}
                                                <input
                                                    type="password"
                                                    inputMode="numeric"
                                                    pattern="[0-9]{6}"
                                                    minLength={6}
                                                    maxLength={6}
                                                    autoComplete="new-password"
                                                    value={filePasscodes[f.id] || ''}
                                                    onChange={(e) => setFilePasscodes((current) => ({ ...current, [f.id]: e.target.value }))}
                                                    placeholder="6 digits"
                                                    aria-label={`Set or change PIN for ${f.title}`}
                                                    required
                                                    className="min-w-0 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                                                />
                                            </label>
                                            <button
                                                type="submit"
                                                className="self-end rounded-lg bg-blue-500/20 border border-blue-500/50 px-3 py-2 text-sm text-blue-200 hover:bg-blue-500/30"
                                            >
                                                {f.has_passcode ? 'Update PIN' : 'Set PIN'}
                                            </button>
                                            {f.has_passcode && (
                                                <button
                                                    type="button"
                                                    onClick={() => handleRemovePasscode(f.id)}
                                                    className="self-end rounded-lg bg-red-500/20 border border-red-500/50 px-3 py-2 text-sm text-red-200 hover:bg-red-500/30"
                                                >
                                                    Remove PIN
                                                </button>
                                            )}
                                        </form>

                                        <form onSubmit={(e) => handleShare(e, f.id)} className="dashboard-share-form grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1fr)_auto] gap-2">
                                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                                Recipient username
                                                <input
                                                    type="text"
                                                    value={shareUsernames[f.id] || ''}
                                                    onChange={(e) => setShareUsernames((current) => ({ ...current, [f.id]: e.target.value }))}
                                                    placeholder="Must have an SV account"
                                                    aria-label={`Recipient username for ${f.title}`}
                                                    required
                                                    className="min-w-0 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                                                />
                                            </label>
                                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                                Access
                                                <select
                                                    value={sharePermissions[f.id] || 'view'}
                                                    onChange={(e) => setSharePermissions((current) => ({ ...current, [f.id]: e.target.value }))}
                                                    aria-label={`Access permission for ${f.title}`}
                                                    className="min-w-0 bg-slate-900 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                                                >
                                                    <option value="view">View / download</option>
                                                    <option value="edit">Edit and replace the original</option>
                                                </select>
                                            </label>
                                            <label className="flex flex-col gap-1 text-xs text-slate-400">
                                                Recipient access ends (optional)
                                                <input
                                                    type="datetime-local"
                                                    min={localDateTimeValue(new Date())}
                                                    value={shareExpiries[f.id] || ''}
                                                    onChange={(e) => setShareExpiries((current) => ({ ...current, [f.id]: e.target.value }))}
                                                    aria-label={`Recipient access end date for ${f.title}`}
                                                    className="min-w-0 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white [color-scheme:dark] focus:outline-none focus:border-blue-500"
                                                />
                                                <span className="text-slate-500">
                                                    Only this recipient loses access at the selected time. The owner keeps the file.
                                                </span>
                                            </label>
                                            <button
                                                type="submit"
                                                className="dashboard-share-submit self-end flex items-center justify-center gap-2 rounded-lg bg-indigo-500/20 border border-indigo-500/50 px-3 py-2 text-sm text-indigo-200 hover:bg-indigo-500/30"
                                            >
                                                <Share2 size={15} />
                                                Share
                                            </button>
                                        </form>

                                        {fileShares.length > 0 && (
                                            <div className="space-y-2 border-t border-white/10 pt-3">
                                                {fileShares.map((share) => (
                                                    <div key={share.id} className="flex items-center justify-between gap-3 text-xs">
                                                        <span className="text-slate-300">
                                                            Shared with <strong>{share.username}</strong>
                                                            {' · '}{share.permission === 'edit' ? 'can edit' : 'view only'}
                                                            {share.permission === 'edit'
                                                                ? ' · can replace original'
                                                                : ''}
                                                            {share.revoked_at ? ' · revoked' : !share.active ? ' · expired' : ''}
                                                            {share.expires_at && share.active ? ` · expires ${new Date(share.expires_at).toLocaleString()}` : ''}
                                                        </span>
                                                        {share.active && (
                                                            <button
                                                                onClick={() => handleRevokeShare(share.id)}
                                                                className="text-red-300 hover:text-red-200 underline"
                                                            >
                                                                Revoke
                                                            </button>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                        {f.shared_copies?.length > 0 && (
                                            <div className="space-y-2 border-t border-white/10 pt-3">
                                                <p className="text-xs font-medium text-slate-300">Edited copies shared back with you</p>
                                                {f.shared_copies.map((copy) => (
                                                    <div key={copy.id} className="flex items-center justify-between gap-3 text-xs">
                                                        <span className="text-slate-400 break-all">
                                                            {copy.title} · by {copy.editor_username} · {copy.file_size} bytes
                                                        </span>
                                                        <button
                                                            type="button"
                                                            onClick={() => handleRevisionDownload(copy.id, copy.title)}
                                                            className="text-blue-200 hover:text-blue-100 underline shrink-0"
                                                        >
                                                            Download
                                                        </button>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    );
                                })
                            )}
                        </div>
                    </div>
                    <footer className="app-credit">SV · Built by Vivekananda</footer>
                </div>

                <div className="dashboard-shared dashboard-card glass-panel p-6">
                    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Users size={18} className="text-indigo-300" />
                        Shared with me ({sharedFiles.length})
                    </h2>
                    {loading ? (
                        <p className="text-sm text-slate-400">Loading shared files...</p>
                    ) : visibleSharedFiles.length === 0 ? (
                        <p className="text-sm text-slate-400">
                            {sharedFiles.length ? 'No shared documents match these filters.' : 'No one has shared a file with you yet.'}
                        </p>
                    ) : (
                        <div className="space-y-3">
                            {visibleSharedFiles.map((sharedFile) => (
                                <div key={sharedFile.share_id} className="flex flex-wrap items-end justify-between gap-3 bg-white/5 p-4 rounded-xl border border-white/10">
                                    <div className="flex items-center gap-3 min-w-0">
                                        <FileText className="text-indigo-300 shrink-0" size={20} />
                                        <div className="min-w-0">
                                            <p className="font-medium text-sm break-all">{sharedFile.title}</p>
                                            <p className="text-xs text-slate-400">
                                                Shared by {sharedFile.owner_username} · {sharedFile.category} · Uploaded {new Date(sharedFile.uploaded_at).toLocaleDateString()} · {sharedFile.file_size} bytes
                                                {' · '}{sharedFile.permission === 'edit' ? 'edit access' : 'view only'}
                                                {sharedFile.expires_at ? ` · expires ${new Date(sharedFile.expires_at).toLocaleString()}` : ''}
                                            </p>
                                        </div>
                                    </div>
                                    <form
                                        onSubmit={(e) => handleSharedFileDownload(e, sharedFile.share_id, sharedFile.title)}
                                        className="flex flex-wrap items-end gap-2"
                                    >
                                        <label className="flex flex-col gap-1 text-xs text-slate-400">
                                            File PIN from sender
                                            <input
                                                type="password"
                                                inputMode="numeric"
                                                pattern="[0-9]{6}"
                                                minLength={6}
                                                maxLength={6}
                                                autoComplete="one-time-code"
                                                value={sharedPasscodes[sharedFile.share_id] || ''}
                                                onChange={(e) => setSharedPasscodes((current) => ({ ...current, [sharedFile.share_id]: e.target.value }))}
                                                placeholder="6 digits"
                                                aria-label={`File PIN for ${sharedFile.title}`}
                                                required
                                                className="w-36 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                                            />
                                        </label>
                                        <button
                                            type="submit"
                                            className="flex items-center gap-1.5 bg-indigo-500/20 hover:bg-indigo-500/30 border border-indigo-500/50 px-3 py-2 rounded-lg text-indigo-200 text-xs"
                                        >
                                            <Download size={14} />
                                            Download
                                        </button>
                                    </form>
                                    {sharedFile.permission === 'edit' && (
                                        <form
                                            onSubmit={(e) => handleSharedFileReplace(e, sharedFile.share_id)}
                                            className="flex flex-wrap items-end gap-2 w-full border-t border-white/10 pt-3"
                                        >
                                            {sharedFile.can_replace_original ? (
                                                <>
                                                    <label className="flex flex-col gap-1 text-xs text-slate-400">
                                                        Select replacement file (enter the PIN above first)
                                                        <input
                                                            type="file"
                                                            onChange={(e) => setRevisionFiles((current) => ({
                                                                ...current,
                                                                [sharedFile.share_id]: e.target.files?.[0] || null,
                                                            }))}
                                                            aria-label={`Replacement file for ${sharedFile.title}`}
                                                            required
                                                            className="max-w-full text-xs text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-indigo-500/20 file:px-3 file:py-2 file:text-indigo-200"
                                                        />
                                                    </label>
                                                    <button
                                                        type="submit"
                                                        className="rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 border border-indigo-500/50 px-3 py-2 text-indigo-200 text-xs"
                                                    >
                                                        Replace original file
                                                    </button>
                                                    <p className="w-full text-xs text-amber-200">
                                                        The owner granted edit access. Replacing the file updates it for the owner and all recipients.
                                                    </p>
                                                </>
                                            ) : (
                                                <p className="text-xs text-amber-200">
                                                    The owner granted view-only access. Ask them to change your permission to Edit if you need to replace the original.
                                                </p>
                                            )}
                                        </form>
                                    )}
                                    {sharedFile.revisions?.length > 0 && (
                                        <div className="w-full border-t border-white/10 pt-3 space-y-2">
                                            <p className="text-xs font-medium text-slate-300">Earlier uploaded copies</p>
                                            {sharedFile.revisions.map((copy) => (
                                                <div key={copy.id} className="flex items-center justify-between gap-3 text-xs">
                                                    <span className="text-slate-400 break-all">
                                                        {copy.title} · {copy.file_size} bytes
                                                    </span>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleRevisionDownload(copy.id, copy.title)}
                                                        className="text-indigo-200 hover:text-indigo-100 underline shrink-0"
                                                    >
                                                        Download
                                                    </button>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Audit Logs Sidebar */}
                <div className="dashboard-audit dashboard-card glass-panel p-6 h-fit">
                    <h2 className="text-lg font-semibold mb-1">Activity trail</h2>
                    <p className="audit-caption"><Clock3 size={13} /> Updates automatically every 15 seconds</p>
                    <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2">
                        {loading ? (
                            <p className="text-sm text-slate-400">Loading activity...</p>
                        ) : logs.length === 0 ? (
                            <p className="text-sm text-slate-400">No activity recorded yet.</p>
                        ) : (
                            logs.map(log => (
                                <div key={log.id} className="audit-entry bg-white/5 p-3 rounded-xl border border-white/10 text-xs space-y-1">
                                    <div className="flex justify-between font-semibold text-blue-400">
                                        <span>{log.action}</span>
                                        <span className={`audit-status ${log.outcome === 'failure' ? 'is-failure' : 'is-success'}`}>
                                            {log.outcome}
                                        </span>
                                    </div>
                                    <p className="text-slate-400">
                                        {log.username || 'Anonymous'}
                                        {log.file_title ? ` · ${log.file_title}` : ''}
                                    </p>
                                    <p className="text-slate-300">{log.details}</p>
                                    {log.ip_address && <p className="text-[10px] text-slate-500">IP: {log.ip_address}</p>}
                                    <p className="text-[10px] text-slate-500">{new Date(log.timestamp).toLocaleString()}</p>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
