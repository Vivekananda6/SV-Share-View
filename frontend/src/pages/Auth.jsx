import { useState } from 'react';
import {
    Activity, Check, Eye, EyeOff, FileKey2, LockKeyhole, Shield,
    UserRound, X,
} from 'lucide-react';
import { login, register } from '../services/auth';

const passwordRules = [
    { id: 'length', label: 'At least 8 characters', test: (password) => password.length >= 8 },
    { id: 'numeric', label: 'Not entirely numeric', test: (password) => password.length > 0 && !/^\d+$/.test(password) },
];

const Auth = ({ onLoginSuccess }) => {
    const [isLogin, setIsLogin] = useState(true);
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmation, setShowConfirmation] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    const switchMode = () => {
        setIsLogin((current) => !current);
        setPassword('');
        setConfirmPassword('');
        setError('');
        setSuccess('');
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        setError('');
        setSuccess('');
        if (!isLogin && password !== confirmPassword) {
            setError('The passwords do not match.');
            return;
        }
        if (!isLogin && /^\d+$/.test(password)) {
            setError('Choose a password that is not entirely numeric.');
            return;
        }

        setIsSubmitting(true);
        try {
            if (isLogin) {
                await login(username, password);
                onLoginSuccess();
            } else {
                await register(username, password, email);
                setIsLogin(true);
                setPassword('');
                setConfirmPassword('');
                setSuccess('Your account is ready. Sign in with your new credentials.');
            }
        } catch (requestError) {
            const details = requestError.response?.data;
            const message = details?.detail
                || details?.error
                || (details && Object.values(details).flat().join(' '));
            setError(typeof message === 'string'
                ? message
                : (isLogin ? 'Sign in failed. Check your username and password.' : 'Account creation failed. Check the details and try again.'));
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <main className="auth-shell">
            <section className="auth-frame" aria-label="SV account access">
                <aside className="auth-aside">
                    <a className="auth-logo" href="/" aria-label="SV home">
                        <span className="auth-logo-mark"><Shield aria-hidden="true" /></span>
                        <span>SV</span>
                    </a>
                    <div className="auth-aside-content">
                        <span className="auth-kicker"><span className="auth-live-dot" /> PRIVATE FILE SHARING</span>
                        <h1>Share what matters.<br /><span>Stay in control.</span></h1>
                        <p>One secure place to store your files, choose who can access them, and see what happens next.</p>
                        <ul className="auth-benefits">
                            <li><span><LockKeyhole size={16} /></span><div><strong>Private by design</strong><small>Access is checked on every request.</small></div></li>
                            <li><span><FileKey2 size={16} /></span><div><strong>Your permissions, your rules</strong><small>Share with named people. Revoke at any time.</small></div></li>
                            <li><span><Activity size={16} /></span><div><strong>Clear activity history</strong><small>Review document and sharing activity.</small></div></li>
                        </ul>
                    </div>
                    <p className="auth-aside-footer">SV — Share · View · Built by Vivekananda</p>
                </aside>

                <div className="auth-main">
                    <div className="auth-form-heading">
                        <span className="auth-form-kicker">{isLogin ? 'WELCOME BACK' : 'GET STARTED'}</span>
                        <h2>{isLogin ? 'Sign in to your account' : 'Create your account'}</h2>
                        <p>{isLogin ? 'Enter your credentials to continue to your secure workspace.' : 'Create an account to securely share and access files.'}</p>
                    </div>

                    {error && <div role="alert" className="auth-message auth-error"><X size={17} />{error}</div>}
                    {success && <div role="status" className="auth-message auth-success"><Check size={17} />{success}</div>}

                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="auth-field">
                            <label htmlFor="auth-username">Username</label>
                            <div className="auth-input-wrap">
                                <UserRound className="auth-input-icon" size={18} aria-hidden="true" />
                                <input
                                    id="auth-username"
                                    type="text"
                                    value={username}
                                    onChange={(event) => setUsername(event.target.value)}
                                    placeholder="Your username"
                                    autoComplete="username"
                                    autoCapitalize="none"
                                    maxLength={150}
                                    required
                                />
                            </div>
                        </div>

                        {!isLogin && (
                            <div className="auth-field">
                                <label htmlFor="auth-email">Email <span className="auth-optional">Optional</span></label>
                                <div className="auth-input-wrap">
                                    <input
                                        id="auth-email"
                                        className="auth-input-no-icon"
                                        type="email"
                                        value={email}
                                        onChange={(event) => setEmail(event.target.value)}
                                        placeholder="you@example.com"
                                        autoComplete="email"
                                    />
                                </div>
                            </div>
                        )}

                        <div className="auth-field">
                            <label htmlFor="auth-password">Password</label>
                            <div className="auth-input-wrap">
                                <LockKeyhole className="auth-input-icon" size={18} aria-hidden="true" />
                                <input
                                    id="auth-password"
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(event) => setPassword(event.target.value)}
                                    placeholder={isLogin ? 'Enter your password' : 'Create a strong password'}
                                    autoComplete={isLogin ? 'current-password' : 'new-password'}
                                    minLength={isLogin ? undefined : 8}
                                    required
                                />
                                <button
                                    type="button"
                                    className="password-visibility"
                                    onClick={() => setShowPassword((visible) => !visible)}
                                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                                >
                                    {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                                </button>
                            </div>
                        </div>

                        {!isLogin && (
                            <>
                                <div className="password-requirements" aria-live="polite">
                                    <p>Password requirements</p>
                                    {passwordRules.map((rule) => {
                                        const passed = rule.test(password);
                                        return (
                                            <span key={rule.id} className={passed ? 'requirement is-met' : 'requirement'}>
                                                {passed ? <Check size={14} /> : <span className="requirement-dot" />}
                                                {rule.label}
                                            </span>
                                        );
                                    })}
                                    <span className="requirement-hint">Avoid common passwords and ones too similar to your username. The server checks these when you create your account.</span>
                                </div>
                                <div className="auth-field">
                                    <label htmlFor="auth-confirm-password">Confirm password</label>
                                    <div className="auth-input-wrap">
                                        <LockKeyhole className="auth-input-icon" size={18} aria-hidden="true" />
                                        <input
                                            id="auth-confirm-password"
                                            type={showConfirmation ? 'text' : 'password'}
                                            value={confirmPassword}
                                            onChange={(event) => setConfirmPassword(event.target.value)}
                                            placeholder="Enter your password again"
                                            autoComplete="new-password"
                                            required
                                        />
                                        <button
                                            type="button"
                                            className="password-visibility"
                                            onClick={() => setShowConfirmation((visible) => !visible)}
                                            aria-label={showConfirmation ? 'Hide confirmation password' : 'Show confirmation password'}
                                        >
                                            {showConfirmation ? <EyeOff size={17} /> : <Eye size={17} />}
                                        </button>
                                    </div>
                                    {confirmPassword && (
                                        <span className={`confirmation-status${password === confirmPassword ? ' is-matched' : ''}`}>
                                            {password === confirmPassword ? <Check size={13} /> : <X size={13} />}
                                            {password === confirmPassword ? 'Passwords match' : 'Passwords do not match'}
                                        </span>
                                    )}
                                </div>
                            </>
                        )}

                        <button type="submit" className="auth-submit" disabled={isSubmitting}>
                            {isSubmitting
                                ? (isLogin ? 'Signing in…' : 'Creating account…')
                                : (isLogin ? 'Sign in securely' : 'Create account')}
                        </button>
                    </form>

                    <div className="auth-switch">
                        <span>{isLogin ? 'New to SV?' : 'Already have an account?'}</span>
                        <button type="button" onClick={switchMode}>
                            {isLogin ? 'Create an account' : 'Sign in'}
                        </button>
                    </div>
                    <p className="auth-security-note"><LockKeyhole size={13} /> Your account is protected with secure sign-in.</p>
                </div>
            </section>
        </main>
    );
};

export default Auth;
