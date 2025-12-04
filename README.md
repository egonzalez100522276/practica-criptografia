# Spy Agency Web Project 🔒

This project is a web application for a fictional spy agency, featuring a React frontend and a Python (FastAPI) backend. It's designed to practice web development and cryptography concepts.

## Quick Start Guide 🚀

This guide will help you get the project running on your local machine for development and testing purposes.

### Prerequisites 📋

* [Node.js](https://nodejs.org/) (v18 or later recommended)
* [Python](https://www.python.org/) (v3.10 or later recommended)

---

### 1. Backend Setup (Python / FastAPI) 🐍

First, let's get the API server running.

#### 1. **Navigate to the backend directory:**

```
cd backend
```

#### 2. **Create and activate a virtual environment:**

This isolates the project's Python dependencies. Since the `.venv` folder is not in the repository, you need to create it.

```
# Create the virtual environment. You might need to use 'python3' on macOS/Linux.
python -m venv .venv

# Activate on Windows
.\.venv\Scripts\activate

# Activate on macOS/Linux
source .venv/bin/activate
```

#### 3. **Install Python dependencies:**

```
pip install -r requirements.txt
```

#### 4. **Make sure the Database is set up**

Run the following command to initialize the database.

```
python -m app.db.init_db
```

> Note: this just creates the tables. If they are already created, YOU CAN STILL RUN THIS SAFELY AND THE EXISTING TABLES WILL BE IGNORED.

#### 5. **Run the backend server:**

```
uvicorn app.main:app --reload
```

The API will now be running at `http://127.0.0.1:8000`.

> Note: If that URL does not work, try `http://localhost:8000`.

---

### 🔐 Decrypting the CA's Private Key

The Certificate Authority (CA) private key stored in the backend database is **encrypted** for security. To decrypt it, you need the password stored in your environment variables.

1. Copy `.env.example` to `.env`:

```
cp .env.example .env
```

2. Inside `.env.example`, you will find an example of the variable required to decrypt the CA private key:

```
CA_PRIVATE_KEY_PASSWORD="your-password-here"
```

3. The CA private key is automatically decrypted whenever it is needed. You do not need to do anything else.

> Note: *Check `/backend/app/core/ca.py` for the full implementation.*


---

### 2. Frontend Setup (React / Vite) ⚛️

With the backend running, open a **new terminal** to set up the frontend.

1. **Navigate to the project's root directory:**
   (The one containing the `backend` folder and the `package.json` file).

2. **Install Node.js dependencies:**

```bash
npm install
```

3. **Run the frontend development server:**

```bash
npm run dev
```

The web application will now be accessible in your browser, typically at `http://localhost:5173`.
