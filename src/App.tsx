import { useState } from "react";
import { User, ViewType } from "./types";
import Login from "./components/Login";
import Register from "./components/Register";
import Dashboard from "./components/Dashboard";
import AdminPanel from "./components/AdminPanel";

function App() {
  const [currentView, setCurrentView] = useState<ViewType>("login");
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [notification, setNotification] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const showNotification = (type: "success" | "error", message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 3000);
  };

  const handleLogin = (email: string, password: string) => {
    const mockUser: User = {
      id: "user-123",
      username: email.split("@")[0],
      email: email,
      role: email.includes("admin") ? "admin" : "agent",
    };

    setCurrentUser(mockUser);
    setCurrentView("dashboard");
    showNotification("success", "Login successful! Welcome back, agent.");
  };

  const handleRegister = async (
    username: string,
    email: string,
    password: string
  ) => {
    try {
      const response = await fetch("http://127.0.0.1:8000/auth/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, email, password }),
      });

      if (response.ok) {
        // En un caso real, la respuesta del backend podría devolver los datos del usuario.
        const mockUser: User = {
          id: `user-${Date.now()}`,
          username: username,
          email: email,
          role: "agent",
        };
        setCurrentUser(mockUser);
        setCurrentView("dashboard");
        showNotification(
          "success",
          "Registration successful! Welcome to the agency."
        );
      } else {
        const errorData = await response.json();
        showNotification(
          "error",
          errorData.detail || "An unknown error occurred."
        );
      }
    } catch (err) {
      console.error("Error de conexión:", err);
      showNotification(
        "error",
        "Could not connect to the server. Please try again later."
      );
    }
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setCurrentView("login");
    showNotification("success", "Logged out successfully.");
  };

  return (
    <>
      {notification && (
        <div className="fixed top-4 right-4 z-50 animate-slide-up">
          <div
            className={`rounded-lg px-6 py-4 shadow-lg ${
              notification.type === "success"
                ? "bg-green-600 text-white"
                : "bg-red-600 text-white"
            }`}
          >
            {notification.message}
          </div>
        </div>
      )}

      {currentView === "login" && (
        <Login
          onLogin={handleLogin}
          onSwitchToRegister={() => setCurrentView("register")}
        />
      )}

      {currentView === "register" && (
        <Register
          onRegister={handleRegister}
          onSwitchToLogin={() => setCurrentView("login")}
        />
      )}

      {currentView === "dashboard" && currentUser && (
        <Dashboard
          user={currentUser}
          onLogout={handleLogout}
          onSwitchToAdmin={() => setCurrentView("admin")}
        />
      )}

      {currentView === "admin" &&
        currentUser &&
        currentUser.role === "admin" && (
          <AdminPanel
            user={currentUser}
            onBack={() => setCurrentView("dashboard")}
          />
        )}
    </>
  );
}

export default App;
