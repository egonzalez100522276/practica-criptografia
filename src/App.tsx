import { useState } from 'react';
import { User, ViewType } from './types';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import AdminPanel from './components/AdminPanel';

function App() {
  const [currentView, setCurrentView] = useState<ViewType>('login');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 3000);
  };

  const handleLogin = (email: string, password: string) => {
    const mockUser: User = {
      id: 'user-123',
      username: email.split('@')[0],
      email: email,
      role: email.includes('admin') ? 'admin' : 'agent',
    };

    setCurrentUser(mockUser);
    setCurrentView('dashboard');
    showNotification('success', 'Login successful! Welcome back, agent.');
  };

  const handleRegister = (username: string, email: string, password: string) => {
    const mockUser: User = {
      id: `user-${Date.now()}`,
      username: username,
      email: email,
      role: 'agent',
    };

    setCurrentUser(mockUser);
    setCurrentView('dashboard');
    showNotification('success', 'Registration successful! Welcome to the agency.');
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setCurrentView('login');
    showNotification('success', 'Logged out successfully.');
  };

  return (
    <>
      {notification && (
        <div className="fixed top-4 right-4 z-50 animate-slide-up">
          <div className={`rounded-lg px-6 py-4 shadow-lg ${
            notification.type === 'success'
              ? 'bg-green-600 text-white'
              : 'bg-red-600 text-white'
          }`}>
            {notification.message}
          </div>
        </div>
      )}

      {currentView === 'login' && (
        <Login
          onLogin={handleLogin}
          onSwitchToRegister={() => setCurrentView('register')}
        />
      )}

      {currentView === 'register' && (
        <Register
          onRegister={handleRegister}
          onSwitchToLogin={() => setCurrentView('login')}
        />
      )}

      {currentView === 'dashboard' && currentUser && (
        <Dashboard
          user={currentUser}
          onLogout={handleLogout}
          onSwitchToAdmin={() => setCurrentView('admin')}
        />
      )}

      {currentView === 'admin' && currentUser && currentUser.role === 'admin' && (
        <AdminPanel
          user={currentUser}
          onBack={() => setCurrentView('dashboard')}
        />
      )}
    </>
  );
}

export default App;
