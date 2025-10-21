import { useState, useEffect } from "react";
import { User, ViewType } from "./types";
import Login from "./components/Login";
import Register from "./components/Register";
import Dashboard from "./components/Dashboard";
import AdminPanel from "./components/AdminPanel";

/**
 * Decodes a JWT token to extract its payload without verifying the signature.
 * @param token The JWT string.
 * @returns The payload as a JavaScript object.
 */
function parseJwt(token: string) {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => `%${`00${c.charCodeAt(0).toString(16)}`.slice(-2)}`)
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}
function App() {
  const [currentView, setCurrentView] = useState<ViewType>("login");
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [notification, setNotification] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true); // Nuevo estado para manejar la carga inicial

  // Efecto para cargar el token y el usuario desde localStorage al iniciar la app
  useEffect(() => {
    console.log("DEBUG: Checking for JWT in localStorage on page load...");
    const storedToken = localStorage.getItem("jwt_token");
    if (storedToken) {
      console.log("DEBUG: JWT found in localStorage:", storedToken);
      const payload = parseJwt(storedToken);
      if (payload && payload.exp * 1000 > Date.now()) {
        // Token válido y no expirado
        console.log(
          "DEBUG: JWT is valid. Restoring session for user:",
          payload.sub
        );
        setToken(storedToken);
        setCurrentUser({
          id: payload.user_id,
          username: payload.sub,
          email: payload.email || "", // Asume que el email podría estar en el token o ser vacío
          role: payload.role,
        });
        setCurrentView("dashboard");
      } else {
        // Token expirado o inválido, lo eliminamos
        console.warn(
          "DEBUG: JWT found but it is expired or invalid. Removing it."
        );
        localStorage.removeItem("jwt_token");
      }
    } else {
      console.log("DEBUG: No JWT found in localStorage.");
    }
    setIsLoading(false); // La carga inicial ha terminado
  }, []);

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
        const { access_token } = await response.json();
        setToken(access_token);
        console.log("DEBUG: Login successful. Storing JWT in localStorage.");
        localStorage.setItem("jwt_token", access_token); // Guardar en localStorage

        const payload = parseJwt(access_token);
        setCurrentUser({
          id: payload.user_id,
          username: payload.sub,
          email: "", // Email is not in the token, adjust if needed
          role: payload.role,
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
        const { access_token } = await response.json();
        setToken(access_token);
        console.log(
          "DEBUG: Registration successful. Storing JWT in localStorage."
        );
        localStorage.setItem("jwt_token", access_token); // Guardar en localStorage
        showNotification("success", "Registration successful! Logging in...");

        const payload = parseJwt(access_token);
        setCurrentUser({
          id: payload.user_id,
          username: payload.sub,
          email: email, // We have the email from the form
          role: payload.role,
        });
        setCurrentView("dashboard");
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
    setToken(null);
    console.log("DEBUG: Logging out. Removing JWT from localStorage.");
    localStorage.removeItem("jwt_token"); // Eliminar de localStorage
    setCurrentView("login");
    showNotification("success", "Logged out successfully.");
  };

  if (isLoading) {
    return <div>Loading session...</div>; // O un spinner de carga
  }

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
