// src/App.jsx
import { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Auth from './pages/Auth';
import AdminDashboard from './pages/AdminDashboard';
import { getCurrentUser } from './services/auth';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!getCurrentUser());

  useEffect(() => {
    const handleAuthExpired = () => setIsAuthenticated(false);
    window.addEventListener('sv:auth-expired', handleAuthExpired);
    return () => window.removeEventListener('sv:auth-expired', handleAuthExpired);
  }, []);

  return (
    <Router>
      <Routes>
        <Route
          path="/"
          element={isAuthenticated ? <Dashboard onLogout={() => setIsAuthenticated(false)} /> : <Navigate to="/auth" />}
        />
        <Route
          path="/control"
          element={isAuthenticated ? <AdminDashboard onLogout={() => setIsAuthenticated(false)} /> : <Navigate to="/auth" />}
        />
        <Route
          path="/auth"
          element={!isAuthenticated ? <Auth onLoginSuccess={() => setIsAuthenticated(true)} /> : <Navigate to="/" />}
        />
        <Route path="*" element={<Navigate to={isAuthenticated ? "/" : "/auth"} replace />} />
      </Routes>
    </Router>
  );
}

export default App;
