# JWT Authentication – ASP.NET Core 2.1

This project provides a simple and clean implementation of **JWT-based authentication** using **ASP.NET Core 2.1 Web API**. It demonstrates how to generate JSON Web Tokens, validate incoming requests, and protect API endpoints using authorization middleware.

---

## 📌 Architecture Overview

The project uses a lightweight layered structure suitable for .NET Core 2.1 applications:

- **Controllers** – API endpoints for authentication and user actions  
- **Data** – In-memory or database-backed data access (repository or context)  
- **Model** – Request/response DTOs and entity models  
- **Startup.cs** – JWT configuration, authentication middleware, DI setup  
- **Program.cs** – Application bootstrap  
- **appsettings.json** – JWT secret key and token configuration  

---

## 🧩 Key JWT Flow

1. User sends login credentials  
2. Server validates credentials  
3. A JWT token is generated using a configured secret  
4. User includes token in request headers:  
