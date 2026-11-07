import { Fragment, useCallback, useEffect, useState } from 'react';
import { Activity, ArrowLeft, Ban, CheckCircle2, Clock3, LogOut, RefreshCw, Search, Share2, ShieldAlert, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import { logout } from '../services/auth';

const initialCounts = {
    users: 0,
    active_users: 0,
    blocked_users: 0,
    timed_out_users: 0,
    documents: 0,
    shares: 0,
    recent_events_24h: 0,
};

const AdminDashboard = ({ onLogout }) => {
    const [overview, setOverview] = useState({ counts: initialCounts, users: [], users_truncated: false, users_page: 1, users_page_count: 0, users_count: 0 });
    const [audit, setAudit] = useState([]);
    const [auditSearchText, setAuditSearchText] = useState('');
    const [auditSearch, setAuditSearch] = useState('');
    const [documents, setDocuments] = useState({ count: 0, page: 1, page_count: 0, results: [] });
    const [searchText, setSearchText] = useState('');
    const [search, setSearch] = useState('');
    const [userPage, setUserPage] = useState(1);
    const [documentSearchText, setDocumentSearchText] = useState('');
    const [documentSearch, setDocumentSearch] = useState('');
    const [documentPage, setDocumentPage] = useState(1);
    const [expandedDocument, setExpandedDocument] = useState(null);
    const [editingDocument, setEditingDocument] = useState(null);
    const [duration, setDuration] = useState('60');
    const [note, setNote] = useState('');
    const [busyUser, setBusyUser] = useState(null);
    const [busyDocument, setBusyDocument] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [notice, setNotice] = useState('');
    const [unauthorized, setUnauthorized] = useState(false);

    const loadData = useCallback(async () => {
        setLoading(true);
        setError('');
        try {
            const documentQuery = new URLSearchParams({
                page: String(documentPage),
                page_size: '50',
            });
            const userQuery = new URLSearchParams({
                page: String(userPage),
                page_size: '50',
            });
            if (search) userQuery.set('search', search);
            if (documentSearch) documentQuery.set('search', documentSearch);
            const auditQuery = new URLSearchParams({ limit: '100' });
            if (auditSearch) auditQuery.set('search', auditSearch);
            const [overviewResponse, auditResponse, documentsResponse] = await Promise.all([
                api.get(`admin/overview/?${userQuery.toString()}`),
                api.get(`admin/audit/?${auditQuery.toString()}`),
                api.get(`admin/documents/?${documentQuery.toString()}`),
            ]);
            setOverview(overviewResponse.data);
            setAudit(auditResponse.data);
            setDocuments(documentsResponse.data);
            setUnauthorized(false);
        } catch (requestError) {
            const statusCode = requestError.response?.status;
            if (statusCode === 403) {
                setUnauthorized(true);
                setError('This account is not authorized to use the administration portal.');
            } else {
                setError(requestError.response?.data?.detail || 'Unable to load administration data.');
            }
        } finally {
            setLoading(false);
        }
    }, [auditSearch, documentPage, documentSearch, search, userPage]);

    useEffect(() => {
        const initialLoad = window.setTimeout(() => {
            loadData();
        }, 0);
        const refreshWhenVisible = () => {
            if (document.visibilityState === 'visible') loadData();
        };
        const refreshInterval = window.setInterval(refreshWhenVisible, 15000);
        window.addEventListener('focus', refreshWhenVisible);
        document.addEventListener('visibilitychange', refreshWhenVisible);
        return () => {
            window.clearTimeout(initialLoad);
            window.clearInterval(refreshInterval);
            window.removeEventListener('focus', refreshWhenVisible);
            document.removeEventListener('visibilitychange', refreshWhenVisible);
        };
    }, [loadData]);

    const handleAction = async (user, action) => {
        setBusyUser(user.id);
        setError('');
        setNotice('');
        try {
            await api.post(`admin/users/${user.id}/action/`, {
                action,
                ...(action === 'timeout' ? { duration_minutes: Number(duration) } : {}),
                ...(note.trim() ? { note: note.trim() } : {}),
            });
            setNotice(`${action.replaceAll('_', ' ')} applied to ${user.username}.`);
            await loadData();
        } catch (requestError) {
            const responseData = requestError.response?.data;
            const message = responseData?.detail
                || Object.values(responseData || {}).flat().join(' ')
                || 'The moderation action could not be completed.';
            setError(typeof message === 'string' ? message : 'The moderation action could not be completed.');
        } finally {
            setBusyUser(null);
        }
    };

    const handleLogout = async () => {
        try {
            await api.post('logout/');
            logout();
            onLogout();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not revoke your sessions. Please retry while connected.');
        }
    };

    const handleDocumentDownload = async (document) => {
        setBusyDocument(document.id);
        setError('');
        try {
            const response = await api.get(
                `admin/documents/${document.id}/download/`,
                { responseType: 'blob' },
            );
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = window.document.createElement('a');
            link.href = url;
            link.download = document.title;
            window.document.body.appendChild(link);
            link.click();
            link.remove();
            window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
            setNotice(`Downloaded “${document.title}” from ${document.owner_username}'s vault.`);
            await loadData();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not download the document.');
        } finally {
            setBusyDocument(null);
        }
    };

    const handleDocumentSave = async (event) => {
        event.preventDefault();
        if (!editingDocument) return;
        setBusyDocument(editingDocument.id);
        setError('');
        try {
            await api.patch(`admin/documents/${editingDocument.id}/`, {
                title: editingDocument.title,
                category: editingDocument.category,
            });
            setNotice(`Updated “${editingDocument.title}”.`);
            setEditingDocument(null);
            await loadData();
        } catch (requestError) {
            const responseData = requestError.response?.data;
            setError(responseData?.detail || Object.values(responseData || {}).flat().join(' ') || 'Could not update the document.');
        } finally {
            setBusyDocument(null);
        }
    };

    const handleDocumentDelete = async (document) => {
        if (!window.confirm(`Permanently delete “${document.title}” and all its shares and edited copies?`)) {
            return;
        }
        setBusyDocument(document.id);
        setError('');
        try {
            await api.delete(`admin/documents/${document.id}/`);
            setNotice(`Deleted “${document.title}”.`);
            if (documents.results.length === 1 && documentPage > 1) {
                setDocumentPage((page) => page - 1);
            } else {
                await loadData();
            }
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not delete the document.');
        } finally {
            setBusyDocument(null);
        }
    };

    const handleDocumentReplace = async (document, file) => {
        if (!file) return;
        if (!window.confirm(`Replace “${document.title}” with “${file.name}” for its owner and all recipients?`)) {
            return;
        }
        const formData = new FormData();
        formData.append('file', file);
        setBusyDocument(document.id);
        setError('');
        try {
            const response = await api.post(
                `admin/documents/${document.id}/replace/`,
                formData,
            );
            setNotice(`Replaced the contents of “${response.data.title}”.`);
            await loadData();
        } catch (requestError) {
            const responseData = requestError.response?.data;
            setError(responseData?.detail || Object.values(responseData || {}).flat().join(' ') || 'Could not replace the document.');
        } finally {
            setBusyDocument(null);
        }
    };

    const handleShareRevoke = async (share) => {
        if (!window.confirm(`Revoke ${share.username}'s access to this document now?`)) return;
        setBusyDocument(share.fileId);
        setError('');
        try {
            await api.post(`admin/shares/${share.id}/action/`, { action: 'revoke' });
            setNotice(`Revoked ${share.username}'s document access.`);
            await loadData();
        } catch (requestError) {
            setError(requestError.response?.data?.detail || 'Could not revoke the share.');
        } finally {
            setBusyDocument(null);
        }
    };

    const counts = overview.counts || initialCounts;
    const countCards = [
        { label: 'Total accounts', value: counts.users, icon: Users, tone: 'blue' },
        { label: 'Active accounts', value: counts.active_users, icon: CheckCircle2, tone: 'green' },
        { label: 'Blocked accounts', value: counts.blocked_users, icon: Ban, tone: 'red' },
        { label: 'Timed out now', value: counts.timed_out_users, icon: Clock3, tone: 'amber' },
        { label: 'Documents', value: counts.documents, icon: ShieldAlert, tone: 'violet' },
        { label: 'Shares', value: counts.shares, icon: Share2, tone: 'blue' },
        { label: 'Activity events (24h)', value: counts.recent_events_24h, icon: Activity, tone: 'blue' },
    ];

    if (unauthorized) {
        return (
            <main className="admin-shell">
                <header className="admin-header">
                    <div>
                        <p className="admin-kicker">SV · PLATFORM CONTROL</p>
                        <h1>Administration</h1>
                    </div>
                    <Link to="/" className="admin-button"><ArrowLeft size={16} /> Workspace</Link>
                </header>
                <div className="admin-message admin-error" role="alert">{error}</div>
                <footer className="app-credit">SV · Built by Vivekananda</footer>
            </main>
        );
    }

    return (
        <main className="admin-shell">
            <header className="admin-header">
                <div>
                    <p className="admin-kicker">SV · PLATFORM CONTROL</p>
                    <h1>Administration</h1>
                    <p className="admin-subtitle">Account status, moderation, and platform activity.</p>
                </div>
                <div className="admin-header-actions">
                    <Link to="/" className="admin-button">
                        <ArrowLeft size={16} /> Workspace
                    </Link>
                    <button className="admin-button admin-logout" type="button" onClick={handleLogout}>
                        <LogOut size={16} /> Sign out
                    </button>
                </div>
            </header>

            {error && <div className="admin-message admin-error" role="alert">{error}</div>}
            {notice && <div className="admin-message admin-success" role="status">{notice}</div>}

            <section className="admin-count-grid" aria-label="Platform metrics">
                {countCards.map(({ label, value, icon: Icon, tone }) => (
                    <article className={`admin-count-card tone-${tone}`} key={label}>
                        <span className="admin-count-icon"><Icon size={19} /></span>
                        <div><p>{label}</p><strong>{value}</strong></div>
                    </article>
                ))}
            </section>

            <section className="admin-panel">
                <div className="admin-section-heading">
                    <div>
                        <p className="admin-kicker">GLOBAL DOCUMENT CONTROL</p>
                        <h2>All documents <span className="admin-total">({documents.count})</span></h2>
                        <p className="admin-section-description">Staff can inspect and download every account’s documents, manage metadata and shares, replace contents, or delete files.</p>
                    </div>
                    <button className="admin-button" type="button" onClick={loadData} disabled={loading}>
                        <RefreshCw size={15} className={loading ? 'admin-spin' : ''} /> Refresh
                    </button>
                </div>
                <form
                    className="admin-search-form"
                    onSubmit={(event) => {
                        event.preventDefault();
                        setDocumentPage(1);
                        setDocumentSearch(documentSearchText.trim());
                    }}
                >
                    <label className="admin-search-field">
                        <Search size={16} aria-hidden="true" />
                        <input
                            type="search"
                            value={documentSearchText}
                            onChange={(event) => setDocumentSearchText(event.target.value)}
                            placeholder="Search document name, owner, or category"
                            aria-label="Search all documents by name, owner, or category"
                        />
                    </label>
                    <button className="admin-button admin-primary" type="submit">Search documents</button>
                </form>

                <div className="admin-table-wrap">
                    <table className="admin-table admin-documents-table">
                        <thead>
                            <tr>
                                <th>Document</th>
                                <th>Owner</th>
                                <th>Category</th>
                                <th>Uploaded</th>
                                <th>Size</th>
                                <th>Controls</th>
                            </tr>
                        </thead>
                        <tbody>
                            {documents.results.map((document) => (
                                <Fragment key={document.id}>
                                    <tr>
                                        <td>
                                            <strong>{document.title}</strong>
                                            <span>{document.encryption_algorithm} · {document.revision_count} edited copies · {document.shares.length} grants</span>
                                        </td>
                                        <td>{document.owner_username}</td>
                                        <td>{document.category}</td>
                                        <td>{new Date(document.uploaded_at).toLocaleString()}</td>
                                        <td>{Number(document.file_size).toLocaleString()} bytes</td>
                                        <td className="admin-actions-cell">
                                            <div className="admin-action-buttons">
                                                <button type="button" disabled={busyDocument === document.id} onClick={() => handleDocumentDownload(document)}>Download</button>
                                                <button type="button" disabled={busyDocument === document.id} onClick={() => setEditingDocument(
                                                    editingDocument?.id === document.id
                                                        ? null
                                                        : { id: document.id, title: document.title, category: document.category },
                                                )}>Edit details</button>
                                                <label className="admin-action-upload">
                                                    Replace
                                                    <input
                                                        type="file"
                                                        aria-label={`Replace ${document.title}`}
                                                        disabled={busyDocument === document.id}
                                                        onChange={(event) => {
                                                            handleDocumentReplace(document, event.target.files?.[0]);
                                                            event.target.value = '';
                                                        }}
                                                    />
                                                </label>
                                                <button type="button" disabled={busyDocument === document.id} onClick={() => setExpandedDocument(
                                                    expandedDocument === document.id ? null : document.id,
                                                )}>{expandedDocument === document.id ? 'Hide grants' : 'Manage grants'}</button>
                                                <button className="danger" type="button" disabled={busyDocument === document.id} onClick={() => handleDocumentDelete(document)}>Delete</button>
                                            </div>
                                        </td>
                                    </tr>
                                    {editingDocument?.id === document.id && (
                                        <tr key={`${document.id}-edit`} className="admin-detail-row">
                                            <td colSpan="6">
                                                <form className="admin-document-edit" onSubmit={handleDocumentSave}>
                                                    <label>Document name<input required maxLength={255} value={editingDocument.title} onChange={(event) => setEditingDocument((current) => ({ ...current, title: event.target.value }))} /></label>
                                                    <label>Category<input required maxLength={100} value={editingDocument.category} onChange={(event) => setEditingDocument((current) => ({ ...current, category: event.target.value }))} /></label>
                                                    <button className="admin-button admin-primary" type="submit" disabled={busyDocument === document.id}>Save details</button>
                                                    <button className="admin-button" type="button" onClick={() => setEditingDocument(null)}>Cancel</button>
                                                </form>
                                            </td>
                                        </tr>
                                    )}
                                    {expandedDocument === document.id && (
                                        <tr key={`${document.id}-shares`} className="admin-detail-row">
                                            <td colSpan="6">
                                                <div className="admin-grants">
                                                    <strong>Recipient grants</strong>
                                                    {document.shares.length === 0 ? (
                                                        <p>No recipient grants for this document.</p>
                                                    ) : document.shares.map((share) => (
                                                        <div className="admin-grant-row" key={share.id}>
                                                            <span>
                                                                {share.username} · {share.permission}
                                                                {share.permission === 'edit' && share.can_replace_original ? ' / can replace' : ''}
                                                                {' · '}{share.revoked_at ? 'revoked' : share.active ? 'active' : 'expired'}
                                                                {share.expires_at ? ` · ends ${new Date(share.expires_at).toLocaleString()}` : ''}
                                                            </span>
                                                            {!share.revoked_at && share.active && (
                                                                <button className="admin-action-danger" type="button" disabled={busyDocument === document.id} onClick={() => handleShareRevoke({ ...share, fileId: document.id })}>Revoke access</button>
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </Fragment>
                            ))}
                            {!loading && documents.results.length === 0 && (
                                <tr><td className="admin-empty" colSpan="6">No documents matched the search.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
                <div className="admin-pagination">
                    <span>Page {documents.page} of {Math.max(documents.page_count, 1)}</span>
                    <div>
                        <button className="admin-button" type="button" disabled={loading || documents.page <= 1} onClick={() => setDocumentPage((page) => page - 1)}>Previous</button>
                        <button className="admin-button" type="button" disabled={loading || documents.page >= documents.page_count} onClick={() => setDocumentPage((page) => page + 1)}>Next</button>
                    </div>
                </div>
                <p className="admin-hint">Document downloads, metadata changes, content replacements, deletions, and revoked grants are recorded in the platform audit trail.</p>
            </section>

            <section className="admin-panel">
                <div className="admin-section-heading">
                    <div>
                        <p className="admin-kicker">ACCOUNT MANAGEMENT</p>
                        <h2>Users</h2>
                    </div>
                    <button className="admin-button" type="button" onClick={loadData} disabled={loading}>
                        <RefreshCw size={15} className={loading ? 'admin-spin' : ''} /> Refresh
                    </button>
                </div>

                <form
                    className="admin-search-form"
                    onSubmit={(event) => {
                        event.preventDefault();
                        setUserPage(1);
                        setSearch(searchText.trim());
                    }}
                >
                    <label className="admin-search-field">
                        <Search size={16} aria-hidden="true" />
                        <input
                            type="search"
                            value={searchText}
                            onChange={(event) => setSearchText(event.target.value)}
                            placeholder="Search username or email"
                            aria-label="Search users by username or email"
                        />
                    </label>
                    <button className="admin-button admin-primary" type="submit">Search</button>
                </form>

                <label className="admin-note-field">
                    Moderation note (optional; required for a warning)
                    <input
                        value={note}
                        onChange={(event) => setNote(event.target.value)}
                        maxLength={500}
                        placeholder="Reason for this action"
                    />
                </label>
                <label className="admin-duration-field">
                    Timeout duration
                    <select value={duration} onChange={(event) => setDuration(event.target.value)}>
                        <option value="60">1 hour</option>
                        <option value="1440">24 hours</option>
                        <option value="10080">7 days</option>
                        <option value="43200">30 days</option>
                    </select>
                </label>

                {overview.users_truncated && (
                    <p className="admin-hint">Showing page {overview.users_page} of {overview.users_page_count} matching accounts.</p>
                )}
                <div className="admin-table-wrap">
                    <table className="admin-table">
                        <thead>
                            <tr>
                                <th>Account</th>
                                <th>Status</th>
                                <th>Warnings</th>
                                <th>Documents</th>
                                <th>Joined</th>
                                <th>Last login</th>
                                <th>Moderation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {overview.users.map((user) => (
                                <tr key={user.id}>
                                    <td>
                                        <strong>{user.username}</strong>
                                        <span>{user.email || 'No email set'}</span>
                                        {user.is_staff && <span className="admin-role">Staff</span>}
                                        {user.is_superuser && <span className="admin-role">Superuser</span>}
                                    </td>
                                    <td>
                                        <span className={`admin-badge ${user.is_active ? 'badge-active' : 'badge-blocked'}`}>
                                            {user.is_active ? (user.timed_out ? 'Timed out' : 'Active') : 'Blocked'}
                                        </span>
                                        {user.timed_out && user.suspended_until && (
                                            <span>Until {new Date(user.suspended_until).toLocaleString()}</span>
                                        )}
                                        {user.last_note && <span className="admin-last-note">{user.last_note}</span>}
                                    </td>
                                    <td>{user.warning_count}</td>
                                    <td>{user.file_count}</td>
                                    <td>{new Date(user.date_joined).toLocaleDateString()}</td>
                                    <td>{user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</td>
                                    <td className="admin-actions-cell">
                                        {user.protected_admin ? (
                                            <span className="admin-protected">Protected admin</span>
                                        ) : (
                                            <div className="admin-action-buttons">
                                                <button type="button" disabled={busyUser === user.id} onClick={() => handleAction(user, 'warn')}>Warn</button>
                                                {user.is_active ? (
                                                    <>
                                                        <button type="button" disabled={busyUser === user.id} onClick={() => handleAction(user, 'timeout')}>Timeout {duration}m</button>
                                                        {user.timed_out && <button type="button" disabled={busyUser === user.id} onClick={() => handleAction(user, 'clear_timeout')}>Clear timeout</button>}
                                                        <button className="danger" type="button" disabled={busyUser === user.id} onClick={() => handleAction(user, 'block')}>Block</button>
                                                    </>
                                                ) : (
                                                    <button type="button" disabled={busyUser === user.id} onClick={() => handleAction(user, 'unblock')}>Unblock</button>
                                                )}
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))}
                            {!loading && overview.users.length === 0 && (
                                <tr><td className="admin-empty" colSpan="7">No accounts matched the search.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
                <div className="admin-pagination">
                    <span>{overview.users_count} accounts · page {overview.users_page} of {Math.max(overview.users_page_count, 1)}</span>
                    <div>
                        <button className="admin-button" type="button" disabled={loading || overview.users_page <= 1} onClick={() => setUserPage((page) => page - 1)}>Previous</button>
                        <button className="admin-button" type="button" disabled={loading || overview.users_page >= overview.users_page_count} onClick={() => setUserPage((page) => page + 1)}>Next</button>
                    </div>
                </div>
                <p className="admin-hint">Blocking and timeouts revoke existing login tokens. Staff and superuser accounts cannot be moderated here.</p>
            </section>

            <section className="admin-panel">
                <div className="admin-section-heading">
                    <div>
                        <p className="admin-kicker">RECENT PLATFORM EVENTS</p>
                        <h2>Audit activity</h2>
                    </div>
                    <span className="admin-hint">Latest {audit.length} events · list is capped at 100</span>
                </div>
                <form
                    className="admin-search-form"
                    onSubmit={(event) => {
                        event.preventDefault();
                        setAuditSearch(auditSearchText.trim());
                    }}
                >
                    <label className="admin-search-field">
                        <Search size={16} aria-hidden="true" />
                        <input
                            type="search"
                            value={auditSearchText}
                            onChange={(event) => setAuditSearchText(event.target.value)}
                            placeholder="Search actor, action, document, or details"
                            aria-label="Search audit activity"
                        />
                    </label>
                    <button className="admin-button admin-primary" type="submit">Search activity</button>
                </form>
                <div className="admin-audit-list">
                    {audit.map((event) => (
                        <article className="admin-audit-row" key={event.id}>
                            <div>
                                <strong>{event.action}</strong>
                                <p>{event.username || 'Anonymous'}{event.file_title ? ` · ${event.file_title}` : ''}</p>
                                {event.details && <small>{event.details}</small>}
                            </div>
                            <div className="admin-audit-meta">
                                <span className={`admin-badge ${event.outcome === 'success' ? 'badge-active' : 'badge-blocked'}`}>{event.outcome}</span>
                                <time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time>
                            </div>
                        </article>
                    ))}
                    {!loading && audit.length === 0 && <p className="admin-empty">No audit activity recorded.</p>}
                </div>
            </section>

            <footer className="app-credit">SV · Built by Vivekananda</footer>
        </main>
    );
};

export default AdminDashboard;
