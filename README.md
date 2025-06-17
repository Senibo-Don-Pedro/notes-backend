# 🧠 Notes App — Backend (Spring Boot)

A robust and secure **Spring Boot** REST API that serves as the powerhouse for a feature-rich notes application. Equipped with full **CRUD functionality**, secure authentication with **JWT + Google Authenticator MFA**, OAuth login (Google, GitHub), and a powerful admin panel, this backend is production-ready and thoughtfully designed for scalability and security.

🌐 **[View API Documentation (Swagger)](https://notes-backend-deployment-latest.onrender.com/swagger-ui/index.html#/)**

---

## 🔑 Core Features

### 1. Authentication & MFA
- Secure login with **JWT tokens** featuring expiration
- Optional **Google Authenticator** two-factor authentication
- OAuth integration with **GitHub** and **Google**

### 2. Notes Management
Comprehensive API endpoints for notes:
- `GET /api/notes` – Retrieve all your notes
- `POST /api/notes` – Add a new note
- `PUT /api/notes/{id}` – Modify an existing note
- `DELETE /api/notes/{id}` – Remove a note

All endpoints require a valid JWT bearer token.

### 3. Admin Panel
Accessible only to `ADMIN`-role users:
- View **audit logs** for all actions (user login, CRUD operations)
- Manage users: view, edit roles, deactivate accounts
- Audit each action with timestamps and performing user info

> *Check `SecurityConfig` for default dummy credentials to log in as admin or test users without sign-up.*

### 4. Email Notifications
Automated SMTP-triggered emails for:
- New user registration
- Note creation/update
- Login events (including MFA)

Configured via environment variables.

### 5. Configuration & CORS
- Seamless connection with frontend via CORS and `FRONTEND_URL` environment variable
- Easy connection to Aiven MySQL database via JDBC URL

---

## 🧩 Prerequisites
- JDK 17 or higher
- Maven (or use included `./mvnw`)
- A MySQL database (e.g., Aiven) with a `securenotes` schema
- SMTP credentials (e.g., Gmail, SendGrid)

---

## ⚙️ Setup

1. **Clone repository**
   ```bash
   git clone https://github.com/Senibo-Don-Pedro/notes-backend.git
   cd notes-backend
   ```

2. **Set environment variables**
   Create a `.env` file (or export in your shell):
   ```ini
   DATASOURCE_URL=jdbc:mysql://<HOST>:<PORT>/securenotes?sslmode=require
   DATASOURCE_USER=<DB_USERNAME>
   DATASOURCE_PASSWORD=<DB_PASSWORD>

   JWT_SECRET=<random_secret>
   JWT_EXPIRATION=172800000

   FRONTEND_URL=your-frontend-url

   SMTP_USERNAME=<smtp_user>
   SMTP_PASSWORD=<smtp_password>

   GITHUB_CLIENT_ID=<github_id>
   GITHUB_CLIENT_SECRET=<github_secret>
   GITHUB_CLIENT_SCOPE=user:email,read:user

   GOOGLE_CLIENT_ID=<google_id>
   GOOGLE_CLIENT_SECRET=<google_secret>
   ```

3. **Run application**
   ```bash
   ./mvnw spring-boot:run
   ```

   Or build and execute:
   ```bash
   ./mvnw package
   java -jar target/notes-backend-0.0.1-SNAPSHOT.jar
   ```

The service will be available at http://localhost:8080/.

---

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | Login with credentials + MFA |
| `/auth/oauth/github` | GET | OAuth login via GitHub |
| `/auth/oauth/google` | GET | OAuth login via Google |
| `/api/notes` | GET | Get all notes for authenticated user |
| `/api/notes` | POST | Create a new note |
| `/api/notes/{id}` | PUT | Update an existing note |
| `/api/notes/{id}` | DELETE | Delete a note by ID |
| `/admin/**` | ANY | Admin-only audit logs and user management |

Use `Authorization: Bearer <token>` header for protected endpoints.

---

## 🧪 Testing
Run tests with:

```bash
./mvnw test
```

---

## 🐳 Docker (Optional)
```bash
docker build -t notes-backend .
docker run -d --env-file .env -p 8080:8080 notes-backend
```

---

## 🚀 Deployment
Deploy to Heroku, Render, AWS, GCP, or Azure—just set environment variables/secrets.

---

## 🤝 Contributing
Pull requests and issues are welcome! Please open an issue for major changes before you begin contributing.

---

## 👤 Author
**Senibo Don‑Pedro**  
[LinkedIn](https://linkedin.com/in/senibo-don-pedro)

---

## 📄 License
MIT © 2025 Senibo Don‑Pedro
