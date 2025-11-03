# 📘 Data Web API – TCSS 460 Production Sprint

### University of Washington Tacoma  
**Course:** TCSS 460 – Software Engineering  
**Team Members:** Balkirat Singh, Kobe Benavente, MD Khan (Shanto), Pham Nguyen  
**Branch:** `Testing 2` (work in progress; not yet merged into `main`)

---

## 🧩 Project Overview

The **Data Web API** is a RESTful backend service developed using **Node.js**, **Express**, and **PostgreSQL**.  
It provides endpoints for managing TV show data, authentication, and administrative operations.  
The API integrates with a companion **Credentials Web API** that handles user authentication, email verification, and authorization.  

Both APIs are hosted on **Render** for production deployment and tested through **Postman collections** during the Production Sprint.

---

## 🗂️ Project Structure

project_root/
├── project_files/
│ ├── images/ # ER diagrams, hosting plans, and schema docs
│ ├── Initialize_TVShowdatabase.sql # Database initialization script
│ ├── TVShow_ERDiagram.pdf # Entity Relationship Diagram
│ ├── WebAPI_Cloud_Hosting_Options.md # Render and hosting documentation
│ └── WebAPI_Functionality_Plan.md # Feature planning document
│
├── src/
│ ├── config/
│ │ └── db.js # Database connection configuration
│ ├── middleware/
│ │ └── authMiddleware.js # Middleware handling authentication tokens
│ ├── routes/
│ │ └── shows.js # Endpoints for TV show CRUD operations
│ └── app.js # Main Express application setup
│
├── testing/ # Postman and automated test collections
│
├── openapi.json # API documentation for Swagger
├── package.json # Project dependencies and scripts
├── package-lock.json # Dependency lock file
├── .gitignore
└── README.md # Current documentation


**Notes:**  
- The project is actively maintained in the `Testing 2` branch.  
- Final changes will be merged into `main` after validation and review.  

---

## 🌐 Deployed API URLs

- **Data Web API (Render):** [https://tcss460-group5-tv-api.onrender.com](https://tcss460-group5-tv-api.onrender.com)  
- **Credentials Web API (Render):** [https://tcss460-group5-credentials-api.onrender.com](https://tcss460-group5-credentials-api.onrender.com)
  
---

## 🧠 Production Sprint Contribution

### **Balkirat Singh**  
Set up the **PostgreSQL database** for the Credentials API, created schemas and relations, and implemented **admin endpoints**.  
Also assisted with integration between authentication and show routes. Supported deployment to Render and database debugging.

### **Kobe Benavente**  
Implemented and tested **admin-related routes**, working closely on role-based access and endpoint validation.  
Contributed to middleware refinement and assisted in refactoring shared logic across routes.

### **MD Khan (Shanto)**  
Developed the **email verification and confirmation** flow for the Credentials API.  
Handled email service configuration, testing verification logic, and ensuring secure token expiration handling.

### **Pham Nguyen**  
Led work on **authentication and login/register logic** in the Credentials API.  
Configured JWT authentication, integrated middleware into routes, and assisted with user testing using Postman.

**Team Collaboration:**  
All members contributed equally, providing code review, testing, and documentation support.  
The sprint focused on shared ownership—no feature was completed in isolation.

---

## 🤝 Production Sprint Meetings

**Format:**  
We met twice weekly via **Discord voice calls** and coordinated continuously through **Discord chat** and **GitHub Discussions**.

**Meeting Schedule:**  
- **Wednesdays (5 PM)** – Discussed weekly progress, route structure, and database setup.  
- **Saturdays (noon)** – Focused on testing endpoints and Render deployment troubleshooting.  

**Topics Discussed:**  
- Database design and ER diagram consistency  
- Integration between Data and Credentials APIs  
- Testing and deployment workflow (Postman → Render → GitHub)  
- Resolving environment variable and CORS configuration issues  

**Communication Tools:**  
- **Discord** for daily communication and code debugging  
- **GitHub** for issue tracking and pull requests  
- **Postman** for API validation and endpoint documentation  

---

## 💬 Production Sprint Comments

- Encountered **CORS issues** during deployment; resolved by adjusting Express middleware configuration.  
- Identified **redundant logic** in admin routes and refactored shared database calls into controllers.  
- Adjusted **connection pooling** in `db.js` after observing memory spikes during concurrent requests.  
- Minor inconsistencies found in **error handling** between shows and authentication routes; standardization is planned for the next sprint.  
- Testing suite currently local-only—Render-hosted automated testing is planned for future iteration.  

---

## 🧾 Summary

The Data Web API and Credentials Web API together form the backbone of our **TV Show Management System**.  
The system demonstrates real-world web development principles, including modular API design, secure authentication, RESTful structure, and cloud deployment.  
Our Production Sprint emphasized collaboration, debugging, and refinement of critical features before merging to the main branch.

---

## 👩‍💻 Team Members

| Name | Role | Main Contribution |
|------|------|-------------------|
| **Balkirat Singh** | Database & Admin Routes | Database setup, admin endpoints, deployment |
| **Kobe Benavente** | Backend Logic & Testing | Admin routes, middleware, and testing |
| **MD Khan (Shanto)** | Email Verification | Email service configuration and verification logic |
| **Pham Nguyen** | Authentication | JWT and credential endpoints |

