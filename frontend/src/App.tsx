import { useState, useEffect, useCallback } from "react";
import { User, ViewType } from "./types";
import Login from "./components/Login";
import Register from "./components/Register";
import Dashboard from "./components/Dashboard";
import AdminPanel from "./components/AdminPanel";
import * as forge from "node-forge";

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
  const [decryptedPrivateKey, setDecryptedPrivateKey] = useState<string | null>(
    null
  );

  // Efecto para cargar el token y el usuario desde localStorage al iniciar la app
  useEffect(() => {
    const controller = new AbortController();
    const signal = controller.signal;

    const checkSession = async () => {
      console.log("DEBUG: Checking for active session on page load...");
      const storedToken = localStorage.getItem("jwt_token");
      const encryptedKey = localStorage.getItem("encrypted_private_key");

      if (storedToken) {
        try {
          const response = await fetch(
            "http://127.0.0.1:8000/sessions/validate",
            {
              headers: { Authorization: `Bearer ${storedToken}` },
              signal, // Asocia la petición con el AbortController
            }
          );

          if (response.ok) {
            const user: User = await response.json();
            console.log(
              "DEBUG: Session is valid. Restoring for user:",
              user.username
            );
            setToken(storedToken);
            setCurrentUser(user);

            if (encryptedKey) {
              // Try to get password from sessionStorage first for seamless refresh
              let sessionPassword = sessionStorage.getItem("session_password");

              // If not found, prompt the user as a fallback
              if (!sessionPassword) {
                sessionPassword = prompt(
                  "Please enter your password to re-authenticate your session:"
                );
              }

              if (sessionPassword) {
                try {
                  const pki = forge.pki;
                  const privateKey = pki.decryptRsaPrivateKey(
                    encryptedKey,
                    sessionPassword
                  );
                  const privateKeyPem = pki.privateKeyToPem(privateKey);
                  setDecryptedPrivateKey(privateKeyPem);
                  // If decryption was successful, ensure the password is in sessionStorage for the next refresh
                  sessionStorage.setItem("session_password", sessionPassword);
                  console.log(
                    "DEBUG: Private key decrypted and loaded into memory."
                  );
                } catch (e) {
                  showNotification(
                    "error",
                    "Failed to decrypt session. Incorrect password."
                  );
                  handleLogout(); // Log out if password is wrong
                  return;
                }
              } else {
                // User cancelled the prompt
                handleLogout();
                return;
              }
            }
            setCurrentView("dashboard");
          } else {
            console.warn("DEBUG: Session validation failed. Removing token.");
          }
          // If the session is invalid, we must also clear the in-memory private key
          if (!response.ok) {
            handleLogout();
          }
        } catch (error: any) {
          if (error.name !== "AbortError") {
            console.error("DEBUG: Error validating session:", error);
            handleLogout();
          }
        }
      } else {
        console.log("DEBUG: No token found. User is not logged in.");
        // Clean up any lingering keys if token is missing
        localStorage.removeItem("encrypted_private_key");
        sessionStorage.removeItem("session_password");
      }
      setIsLoading(false);
    };

    checkSession();

    // Función de limpieza: se ejecuta cuando el componente se desmonta
    return () => controller.abort();
  }, []);

  const showNotification = useCallback(
    (type: "success" | "error", message: string) => {
      setNotification({ type, message });
      setTimeout(() => setNotification(null), 3000);
    },
    []
  );

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
        const { access_token, encrypted_private_key } = await response.json();
        setToken(access_token);
        console.log("DEBUG: Login successful. Storing JWT in localStorage.");
        localStorage.setItem("jwt_token", access_token); // Guardar en localStorage
        localStorage.setItem("encrypted_private_key", encrypted_private_key);

        const payload = parseJwt(access_token);

        // --- SECURE: Decrypt private key on client and store in memory ---
        try {
          const pki = forge.pki;
          const privateKey = pki.decryptRsaPrivateKey(
            encrypted_private_key,
            password
          );
          const privateKeyPem = pki.privateKeyToPem(privateKey);
          setDecryptedPrivateKey(privateKeyPem);
          console.log("DEBUG: Private key decrypted and stored in memory.");
          // --- NEW: Store password in sessionStorage for seamless refresh ---
          sessionStorage.setItem("session_password", password);
          console.log("DEBUG: Session password stored in sessionStorage.");
        } catch (e) {
          console.error("Failed to decrypt private key on client:", e);
          showNotification("error", "Incorrect password or corrupted key.");
          handleLogout(); // Clean up if decryption fails
          return;
        }

        setCurrentUser({
          id: payload.user_id,
          username: payload.sub,
          email: "",
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
        // The registration endpoint should also return the encrypted key
        const { access_token, encrypted_private_key } = await response.json();
        setToken(access_token);
        console.log(
          "DEBUG: Registration successful. Storing JWT in localStorage."
        );
        localStorage.setItem("jwt_token", access_token); // Guardar en localStorage
        localStorage.setItem("encrypted_private_key", encrypted_private_key);
        showNotification("success", "Registration successful! Logging in...");

        // --- SECURE: Decrypt private key on client and store in memory ---
        try {
          const pki = forge.pki;
          const privateKey = pki.decryptRsaPrivateKey(
            encrypted_private_key,
            password
          );
          const privateKeyPem = pki.privateKeyToPem(privateKey);
          setDecryptedPrivateKey(privateKeyPem);
          console.log(
            "DEBUG: Private key decrypted and stored in memory after registration."
          );
          // --- NEW: Store password in sessionStorage for seamless refresh ---
          sessionStorage.setItem("session_password", password);
          console.log(
            "DEBUG: Session password stored in sessionStorage after registration."
          );
        } catch (e) {
          console.error(
            "Failed to decrypt private key on client after registration:",
            e
          );
          handleLogout();
          // Re-throw to show error notification
          throw new Error(
            "Could not decrypt private key. Registration failed post-creation."
          );
        }

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
        throw new Error(errorData.detail || "An unknown error occurred.");
      }
    } catch (err) {
      const errorMessage =
        err instanceof Error
          ? err.message
          : "Could not connect to the server. Please try again later.";
      showNotification("error", errorMessage);
    }
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setToken(null);
    setDecryptedPrivateKey(null); // Clear the in-memory private key
    console.log("DEBUG: Logging out. Removing JWT from localStorage.");
    localStorage.removeItem("jwt_token"); // Delete from localStorage
    localStorage.removeItem("encrypted_private_key"); // Delete encrypted key on logout
    sessionStorage.removeItem("session_password"); // Delete session password
    setCurrentView("login");
    showNotification("success", "Logged out successfully.");
  };

  const renderView = () => {
    if (isLoading) {
      return <div>Loading session...</div>;
    }
    switch (currentView) {
      case "login":
        return (
          <Login
            onLogin={handleLogin}
            onSwitchToRegister={() => setCurrentView("register")}
          />
        );
      case "register":
        return (
          <Register
            onRegister={handleRegister}
            onSwitchToLogin={() => setCurrentView("login")}
          />
        );
      case "dashboard":
        return currentUser ? (
          <Dashboard
            user={currentUser}
            onLogout={handleLogout}
            onSwitchToAdmin={() => undefined}
            token={token}
            privateKeyPem={decryptedPrivateKey}
            showNotification={showNotification}
          />
        ) : null;
      case "admin":
        return currentUser && currentUser.role === "leader" ? (
          <AdminPanel
            user={currentUser}
            onBack={() => setCurrentView("dashboard")}
          />
        ) : null;
      default:
        return null;
    }
  };

  return (
    <>
      {notification && (
        <div className="z-[9999] fixed top-4 right-4 animate-slide-up">
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

      {renderView()}
    </>
  );
}

export default App;
