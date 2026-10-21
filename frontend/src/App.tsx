import { useCallback, useEffect, useState } from 'react';
import { BrowserRouter, Navigate, NavLink, Route, Routes } from 'react-router-dom';

import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { SettingsPage } from './pages/SettingsPage';
import { VaultPage } from './pages/VaultPage';
import { AuthProvider } from './state/AuthProvider';
import { useAuth } from './state/useAuth';

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Shell />
      </AuthProvider>
    </BrowserRouter>
  );
}

function Shell() {
  const { status, user, logout } = useAuth();
  const [toast, setToast] = useState<string | null>(null);

  const notify = useCallback((message: string) => setToast(message), []);

  useEffect(() => {
    if (!toast) {
      return;
    }

    const timer = window.setTimeout(() => setToast(null), 2200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  if (status === 'locked') {
    return (
      <Routes>
        <Route path="/register" element={<RegisterPage />} />
        <Route path="*" element={<LoginPage />} />
      </Routes>
    );
  }

  return (
    <>
      <div className="shell">
        <nav className="rail">
          <p className="rail-mark">SecureVault</p>

          <div className="rail-nav">
            <NavLink to="/vault" className={({ isActive }) => `rail-link ${isActive ? 'active' : ''}`}>
              Vault
            </NavLink>
            <NavLink to="/settings" className={({ isActive }) => `rail-link ${isActive ? 'active' : ''}`}>
              Settings
            </NavLink>
          </div>

          <div className="rail-foot">
            <p className="rail-account">{user?.email}</p>
            <button type="button" className="btn-secondary" onClick={() => void logout()}>
              Lock vault
            </button>
          </div>
        </nav>

        <Routes>
          <Route path="/vault" element={<VaultPage notify={notify} />} />
          <Route path="/settings" element={<SettingsPage notify={notify} />} />
          <Route path="*" element={<Navigate to="/vault" replace />} />
        </Routes>
      </div>

      {toast ? (
        <div className="toast" role="status">
          {toast}
        </div>
      ) : null}
    </>
  );
}
