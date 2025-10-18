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

  const handleLogin = async (username: string, password: string) => {
    try {
      const loginFormData = new URLSearchParams();
      loginFormData.append("username", username);
      loginFormData.append("password", password);

      const response = await fetch("http://127.0.0.1:8000/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: loginFormData.toString(),
      });

      if (response.ok) {
        const loggedInUser = await response.json();
        setCurrentUser({
          id: loggedInUser.id,
          username: loggedInUser.username,
          email: loggedInUser.email,
          role: loggedInUser.username.includes("admin") ? "admin" : "agent", // Mock role logic
        });
        setCurrentView("dashboard");
        showNotification("success", "Login successful! Welcome back, agent.");
      } else {
        const errorData = await response.json();
        showNotification("error", errorData.detail || "Login failed.");
      }
    } catch (err) {
      console.error("Connection error:", err);
      showNotification(
        "error",
        "Could not connect to the server. Please try again later."
      );
    }
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
        showNotification("success", "Registration successful! Logging in...");

        // Now, automatically log the user in
        const loginFormData = new URLSearchParams();
        loginFormData.append("username", username);
        loginFormData.append("password", password);

        const loginResponse = await fetch("http://127.0.0.1:8000/auth/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: loginFormData.toString(),
        });

        if (loginResponse.ok) {
          const loggedInUser = await loginResponse.json();
          setCurrentUser({
            id: loggedInUser.id,
            username: loggedInUser.username,
            email: loggedInUser.email,
            role: loggedInUser.username.includes("admin") ? "admin" : "agent", // Mock role logic
          });
          setCurrentView("dashboard");
        } else {
          // This should ideally not happen if registration was successful
          showNotification("error", "Auto-login failed after registration.");
        }
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
