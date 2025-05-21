Okay, I've updated the README.md for your Vaultix project to be more comprehensive, incorporating details from all the project files you've provided. I've also added the commands for generating SSL certificates and RSA public/private keys.

Here is the updated `README.md`:

```markdown
# Vaultix - Secure Document Management System

Vaultix is a comprehensive, secure document management system designed to protect sensitive information through robust security features including encryption, digital signatures, access controls, and detailed audit logging. It provides a platform for users to upload, manage, sign, and verify documents while ensuring data integrity and compliance with various regulatory standards.

## Table of Contents

1.  [Features](#features)
2.  [Technology Stack](#technology-stack)
3.  [Project Structure](#project-structure)
4.  [Setup and Installation](#setup-and-installation)
    * [Prerequisites](#prerequisites)
    * [Environment Variables](#environment-variables)
    * [Generating Keys and Certificates](#generating-keys-and-certificates)
    * [Database Setup](#database-setup)
    * [Running the Application](#running-the-application)
5.  [Key Functionalities](#key-functionalities)
    * [User Authentication](#user-authentication)
    * [Two-Factor Authentication (2FA)](#two-factor-authentication-2fa)
    * [Document Management](#document-management)
    * [Digital Signatures](#digital-signatures)
    * [Approval Workflows](#approval-workflows)
    * [Admin Panel](#admin-panel)
    * [Audit Logging](#audit-logging)
    * [Compliance](#compliance)
6.  [Error Handling and Logging](#error-handling-and-logging)
7.  [API Reference](#api-reference)
8.  [Contributing](#contributing)
9.  [License](#license)

---

## Features

* **Secure Document Upload & Storage**: Documents are encrypted at rest (AES-256 GCM) and in transit (HTTPS/SSL).
* **Digital Signatures**:
    * Server-side: RSA-based digital signatures (PSS padding with SHA-256) for document integrity upon upload.
    * User-side: Individual RSA key pairs (2048-bit) for users to sign documents. Private keys are encrypted with the master key.
* **Document Verification**: Allows verification of document integrity and signature validity for both server and user signatures.
* **User Authentication**:
    * Standard email/password registration and login with password complexity checks.
    * OAuth integration with Okta/Auth0 for enterprise-grade authentication.
    * Two-Factor Authentication (2FA) for email/password accounts using TOTP (Time-based One-Time Password).
* **Access Control**: Role-based access control (User, Admin) and ownership permissions for documents.
* **Approval Workflows**:
    * Admin approval for new user registrations (both email/password and OAuth).
    * Admin approval for document uploads before they become active and downloadable.
* **Audit Logging**: Comprehensive logging of user actions, system events, document interactions, and HTTP requests. Logs can be exported to CSV.
* **Admin Panel**: Centralized dashboard for:
    * User management (view, update role, update username/email, delete users and their documents).
    * Document oversight (view all, edit name, delete).
    * User and document approval/rejection workflows with reasons.
    * Viewing system statistics (total users, documents, pending/approved/rejected counts).
    * Reviewing detailed audit logs with pagination.
    * Checking Okta configuration status.
* **Compliance Features**:
    * Management of compliance templates (add, view).
    * Application of compliance templates to documents with metadata.
    * (Note: Full compliance record storage in `DocumentCompliance` table requires further implementation beyond current audit logging of application).
* **Profile Management**: Users can update their profile information (name, email for local accounts) and manage security settings (password change for local accounts, 2FA setup).
* **Password Complexity**: Enforces strong password policies for local accounts (length, uppercase, lowercase, digit, special character).
* **Error Handling**: Custom error pages for common HTTP errors (400, 401, 403, 404, 500) and detailed exception logging.
* **Responsive Design**: User interface designed using Bootstrap 5 to work across various devices.
* **Security Focused Configuration**:
    * Requires `MASTER_ENCRYPTION_KEY` for cryptographic operations.
    * Utilizes separate RSA key pairs for server-level digital signatures.
    * HTTPS enforced by default through `PREFERRED_URL_SCHEME` and SSL context loading.

---

## Technology Stack

* **Backend**: Python, Flask
* **Database**: SQLAlchemy (designed for relational databases like MySQL, PostgreSQL, SQLite)
* **Database Migrations**: Flask-Migrate, Alembic
* **Authentication**:
    * Flask-Login (Session-based authentication)
    * Authlib (OAuth for Okta/Auth0)
    * pyotp (For 2FA)
    * Werkzeug (Password Hashing)
* **Cryptography**:
    * `cryptography` library (AES-GCM for encryption, RSA for digital signatures, PBKDF2HMAC for key derivation)
    * `hashlib` (SHA256 for hashing)
* **Frontend**: HTML, CSS, JavaScript, Bootstrap 5, jQuery, Font Awesome
* **Templating**: Jinja2
* **Environment Management**: `python-dotenv`
* **QR Code Generation**: `qrcode`
* **WSGI Server (Development)**: Werkzeug (Flask's development server). For production, Gunicorn or uWSGI is recommended.
* **Other Libraries**: See `requirements.txt` for a full list.

---

## Project Structure

```
Vaultix/
├── app.py                    # Main Flask application, routes, and core logic
├── create_db.py              # Script to initialize the database (use migrations instead)
├── run.py                    # Script to apply database migrations
├── requirements.txt          # Python dependencies
├── .env.example              # Example environment variables file
├── certs/                    # SSL certificates
│   ├── server.crt            # SSL Certificate
│   └── server.key            # SSL Private Key
├── private_key.pem           # Server's RSA private key for document signing
├── public_key.pem            # Server's RSA public key for document verification
├── uploads/                  # Directory for storing uploaded (encrypted) files
├── migrations/               # Flask-Migrate/Alembic migration files
│   ├── alembic.ini           # Alembic configuration
│   ├── env.py                # Alembic environment setup
│   ├── script.py.mako      # Alembic migration script template
│   └── versions/             # Migration scripts (e.g., 0d23c3be02cb_....py)
└── templates/                # HTML templates
    ├── admin_panel/          # Admin-specific templates (refactored for clarity)
    │   ├── admin_audit_logs.html
    │   ├── admin_compliance_templates.html
    │   ├── admin_dashboard.html
    │   ├── admin_document_approvals.html
    │   ├── admin_documents.html
    │   ├── admin_panel.html      # Base for admin section
    │   ├── admin_statistics.html
    │   ├── admin_user_approvals.html
    │   └── admin_users.html
    ├── auth/                 # Authentication-related templates
    │   ├── 2fa_setup.html
    │   ├── 2fa_verify.html
    │   ├── login.html
    │   ├── signup.html
    │   └── okta_error.html
    │   └── okta_config_check.html # Admin Okta config check page
    ├── documents/            # Document-related templates
    │   ├── documents_list.html
    │   ├── sign_document.html
    │   ├── upload_document.html
    │   ├── use_compliance_template.html
    │   ├── verify_document.html
    │   └── signature_certificate.html
    ├── errors/               # Custom error page templates
    │   ├── 400.html, 401.html, 403.html, 404.html, 500.html
    │   └── error_base.html     # Base for error pages
    ├── features/             # Static feature information pages
    │   ├── approval_workflows.html
    │   ├── audit_logs.html
    │   ├── compliance.html
    │   ├── digital_signatures.html
    │   └── document_security.html
    ├── resources/            # Static resource pages
    │   ├── api_reference.html
    │   ├── documentation.html
    │   ├── knowledge_base.html
    │   ├── support.html
    │   └── tutorials.html
    ├── user/                 # User-specific pages
    │   ├── dashboard.html
    │   ├── edit_username.html  # Also used by admin for editing user info
    │   └── profile.html
    ├── demos/                # Demonstration pages
    │   ├── signature_demo.html
    │   └── verification_demo.html
    ├── base.html               # Base template with common layout
    └── landing.html            # Application landing page
```

---

## Setup and Installation

### Prerequisites

* Python 3.8+
* pip (Python package installer)
* A relational database (e.g., PostgreSQL, MySQL, SQLite)
* OpenSSL (for generating keys and certificates)

### Environment Variables

Create a `.env` file in the project root directory by copying `.env.example` and fill in the required values:

```bash
cp .env.example .env
```

**Required variables in `.env`:**

* `SECRET_KEY`: A strong, random string for Flask session security. Generate one using `python -c 'import secrets; print(secrets.token_hex(32))'`.
* `DATABASE_URL`: SQLAlchemy database URI (e.g., `postgresql://user:password@host:port/dbname`, `mysql://user:password@host/dbname`, `sqlite:///vaultix.db`).
* `MASTER_ENCRYPTION_KEY`: A **64-character hexadecimal string** (32 bytes) used for encrypting user private keys and deriving document encryption keys. **CRITICAL: Keep this key extremely secure and backed up. Loss of this key means irreversible loss of access to encrypted data.**
    * Generate using: `python -c 'import os; print(os.urandom(32).hex())'`
* **Okta/Auth0 Configuration (Optional, for OAuth login):**
    * `OKTA_DOMAIN`: Your Okta/Auth0 domain (e.g., `https://your-tenant.okta.com` or `https://your-domain.auth0.com`).
    * `OKTA_CLIENT_ID`: Client ID from your Okta/Auth0 application.
    * `OKTA_CLIENT_SECRET`: Client Secret from your Okta/Auth0 application.

### Generating Keys and Certificates

**1. SSL Certificate and Key (for HTTPS)**

These files are used to enable HTTPS for the Flask development server. For production, use a proper reverse proxy (like Nginx or Caddy) with SSL termination.

* Create a `certs` directory in the project root: `mkdir certs`
* Generate a self-signed certificate and private key:
    ```bash
    openssl req -x509 -newkey rsa:4096 -nodes -out certs/server.crt -keyout certs/server.key -days 365 \
    -subj "/C=US/ST=California/L=SanFrancisco/O=VaultixDev/OU=Development/CN=localhost" \
    -addext "subjectAltName = DNS:localhost"
    ```
    (Adjust subject details as needed. For development, `CN=localhost` is common.)

**2. Server RSA Key Pair (for Document Signing)**

These keys are used by the server to sign documents upon upload.

* Generate RSA private key (`private_key.pem`):
    ```bash
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    ```
* Extract public key from private key (`public_key.pem`):
    ```bash
    openssl rsa -pubout -in private_key.pem -out public_key.pem
    ```
    Place `private_key.pem` and `public_key.pem` in the project root directory.

**Security Note:** The `MASTER_ENCRYPTION_KEY` is paramount. User-specific RSA private keys (generated on-the-fly for users who sign documents) are encrypted using this master key before being stored in the database.

### Database Setup

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    Ensure you have the correct database driver installed (e.g., `psycopg2-binary` for PostgreSQL, `mysqlclient` for MySQL).

2.  **Initialize Migrations (if first time and `migrations` folder doesn't exist)**:
    ```bash
    flask db init
    ```

3.  **Create Initial Migration (if models exist but no migrations yet)**:
    The project includes an initial migration `0d23c3be02cb_initial_schema_based_on_current_models_.py`. If you are starting from scratch or have modified models significantly before the first migration, you might need to generate a new one.
    ```bash
    flask db migrate -m "Initial schema based on current models"
    ```
    This command inspects your models (defined in `app.py`) and generates a new migration script in the `migrations/versions/` directory.

4.  **Apply Migrations**:
    This will create or update your database tables according to the models and migration scripts.
    ```bash
    flask db upgrade
    ```
    Alternatively, you can use the provided `run.py` script:
    ```bash
    python run.py
    ```

    The `run.py` script essentially calls `flask db upgrade`. The `create_db.py` script uses `db.create_all()`, which is less flexible for schema changes than migrations and generally not recommended once migrations are in use.

### Running the Application

1.  **Ensure all environment variables** in `.env` are correctly set.
2.  **Ensure SSL certificates (`certs/server.crt`, `certs/server.key`) and RSA keys (`private_key.pem`, `public_key.pem`) are in place.**
3.  **Start the Flask Development Server**:
    ```bash
    python app.py
    ```
    The application will attempt to run with HTTPS if `certs/server.crt` and `certs/server.key` are found. Otherwise, it will run in HTTP mode.
    By default, it will be accessible at `https://localhost:5000` or `http://localhost:5000`.

---

## Key Functionalities

### User Authentication

* **Local Accounts**: Users can sign up with an email and password. Passwords are hashed using `werkzeug.security.generate_password_hash`. Password complexity is enforced.
* **Okta/Auth0 Integration**: Supports OAuth login via Okta or Auth0 using the `Authlib` library. Configuration requires `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, and `OKTA_CLIENT_SECRET` in the `.env` file.
* **Admin Approval for New Users**: All new user registrations (local or OAuth) are set to `pending` status and require admin approval before the user can log in. Admins are notified of new registrations.

### Two-Factor Authentication (2FA)

* Available for local (email/password) accounts.
* Uses TOTP (Time-based One-Time Password) via `pyotp` library.
* Users can set up 2FA in their profile, which involves scanning a QR code generated by `qrcode`.
* Once enabled, users will be prompted for a TOTP code after password verification during login.
* OAuth users' MFA is managed by the identity provider (Okta/Auth0).

### Document Management

* **Upload**: Users can upload documents (allowed types: `txt`, `docx`, `pdf`) up to 16MB.
    * Uploaded files are saved with a UUID-based filename to avoid collisions.
    * Original filename and metadata are stored in the database.
* **Encryption**: All uploaded documents are encrypted using AES-256 GCM. A unique salt is generated for each document, and a key is derived using PBKDF2HMAC with the `MASTER_ENCRYPTION_KEY`. The salt and nonce are stored in the database with the document record.
* **Server-Side Digital Signature**: Upon upload, a SHA256 hash of the *original* file content is calculated. This hash is then signed by the server's RSA private key (`private_key.pem`) using PSS padding. The signature is stored with the document.
* **Download**: Documents are decrypted on-the-fly before being sent to the user. Only the document owner or an admin can download.
* **Deletion**: Users can delete their own documents. Admins can delete any document. Deleting a document also removes its associated physical file from the `uploads/` folder and related database entries (signatures, compliance records).
* **Document Listing & Search**: Users see their own documents; admins see all documents. Basic search functionality is available on the documents list page.
* **Name Update**: Users can update the display name of their documents. Admins can update the name of any document.
* **Approval Workflow**: Uploaded documents are initially `pending` and require admin approval. Admins can approve or reject documents (with a reason). Rejected documents' physical files are deleted.

### Digital Signatures (User-Specific)

* **Key Generation**: When a user first attempts to sign a document, if they don't have an RSA key pair, one is generated (2048-bit). The user's private key is encrypted using `serialization.BestAvailableEncryption(MASTER_KEY)` and stored in their user record. The public key is stored in PEM format.
* **Signing Process**:
    1.  The document owner (user) initiates signing for an *approved* document.
    2.  The system retrieves the (potentially encrypted) document content. If the document is encrypted in the database, its stored SHA256 hash is used directly for signing. Otherwise, the content is hashed.
    3.  The user's encrypted private key is retrieved and decrypted using the `MASTER_KEY`.
    4.  The document hash is signed using the user's decrypted private key (RSA with PSS padding and SHA256).
    5.  The signature, document hash at the time of signing, timestamp, and user details are stored in the `DocumentSignature` table.
* **Verification Process**:
    1.  Anyone can view the verification page for an *approved* document.
    2.  The system recalculates the current hash of the document. If the document is encrypted, its stored original hash is used for comparison with the signature's hash.
    3.  For each signature associated with the document:
        * The signer's public key is retrieved.
        * The signature is verified against the hash stored *with that signature* (i.e., `DocumentSignature.document_hash`) using the signer's public key.
        * The hash stored with the signature is compared to the document's *current* hash (or original stored hash if encrypted) to check for tampering since signing.
    * A signature certificate page can be generated, showing verification details.

### Approval Workflows

* **User Approval**:
    * New users (both local and OAuth sign-ups) are created with `approval_status = 'pending'` and `is_approved = False`.
    * Admins are notified (via audit log entries that could trigger external notifications).
    * Admins can approve or reject users from the "User Approvals" section in the admin dashboard.
    * Approved users can log in. Rejected users cannot.
* **Document Approval**:
    * New documents are uploaded with `approval_status = 'pending'` and `is_approved = False`.
    * Admins are notified.
    * Admins can approve or reject documents from the "Document Approvals" section.
    * Only approved documents are downloadable or available for signing. Rejected documents have their physical files deleted.

### Admin Panel

Accessible only to users with the 'admin' role.
Key sections:
* **Overview/Dashboard**: Summary statistics (pending users/documents, total users/documents).
* **User Management (`/admin/users`)**: List all users, change roles, update user email/name, delete users (which also deletes their documents).
* **User Approvals (`/admin/user-approvals`)**: Approve or reject pending user registrations, view recent approval actions.
* **Document Approvals (`/admin/document-approvals`)**: Approve or reject pending document uploads, view recent approval actions.
* **Document Management (`/admin/documents`)**: View all documents, edit names, download, delete.
* **Audit Logs (`/admin/audit_logs`)**: View detailed system audit logs with pagination and export to CSV functionality.
* **Okta Configuration Check (`/admin/okta-config-check`)**: Displays status of Okta environment variables and fetched server metadata.
* **Statistics (`/admin/statistics`)**: Detailed counts for users and documents (total, pending, approved, rejected), and recent audit logs.
* **Compliance Templates (`/admin/compliance_templates`)**: Manage compliance templates (add, view, activate/deactivate - though activate/deactivate functionality is a placeholder in the template).

### Audit Logging

* A detailed `AuditLog` model captures actions.
* Logged information includes: timestamp, user ID (if applicable), action type, target user/document IDs, IP address, user agent, request details (method, path, referer, HTTP version, status code, response size), and JSON-formatted details about the event.
* Actions logged include:
    * User actions: login (success, failure, 2FA steps), logout, registration (pending, OAuth), profile updates, 2FA enablement.
    * Document actions: upload (pending, errors), download (success, forbidden, errors, decryption status), deletion, name updates, signing, verification.
    * Admin actions: user/document approvals/rejections, role changes, user/document deletions, audit log export, Okta config check.
    * System events: HTTP errors (400, 401, 403, 404, 500), unhandled exceptions, request serving.
    * Compliance actions: Template additions, template applications to documents (logged in details).
* Audit logs are viewable and exportable by admins.

### Compliance

* **Compliance Templates**: Admins can create `ComplianceTemplate` records, specifying name, description, regulation type (e.g., GDPR, HIPAA), a template file path, and a JSON list of required fields.
* **Applying Templates**: Users (document owner or admin) can apply a compliance template to a document. This involves filling out the `required_fields` defined in the template. The action and provided metadata are logged in the audit trail.
    * The `DocumentCompliance` model is designed to store these applied records linking documents to templates and storing the compliance data, but the route `use_compliance_template` currently only logs this information rather than creating `DocumentCompliance` entries. This part may require further implementation for full DB-backed compliance tracking.
* The feature aims to help standardize documents according to specific regulations by ensuring necessary metadata is captured.

---

## Error Handling and Logging

* **Custom Error Pages**: The application uses custom HTML templates for HTTP errors 400, 401, 403, 404, and 500, inheriting from `error_base.html`.
* **Exception Handling**: A global exception handler catches unhandled exceptions, logs them in detail (including traceback) to both the Flask logger and the audit log, and displays a generic 500 error page.
* **HTTPException Handling**: Specific HTTPExceptions (like 404 Not Found) are also caught by the global handler if not handled by a more specific `errorhandler` decorator, logging them and rendering an appropriate error page.
* **Audit Logging of Errors**: All handled HTTP errors (4xx, 5xx) and unhandled exceptions are recorded in the audit log with relevant details, status codes, and tracebacks where applicable.
* **After Request Logging**: An `after_request` hook logs details of served or failed requests (non-static assets) to the audit log.

---

## API Reference

The application includes an `/resources/api-reference` route which renders `templates/resources/api_reference.html`. This page provides an overview of the (placeholder) API, including:
* **Base URL**: `https://api.vaultix.com/v1`
* **Authentication**: Bearer token authentication.
* **Endpoints**:
    * Documents API: List, Upload, Get, Delete documents.
    * Signatures API: Sign document, List signatures, Verify signature.
    * Users API: Get current user, List users (admin).
    * Audit Logs API: Get audit logs (admin).
    *Query parameters and request body details are mentioned for some endpoints.

This API is currently a conceptual outline presented in the template and would require full backend implementation to be functional.

---

## Contributing

Contributions to Vaultix are welcome! Please follow these general guidelines:
1.  Fork the repository.
2.  Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature-name` or `git checkout -b fix/your-bug-fix`.
3.  Make your changes and commit them with clear, descriptive messages.
4.  Ensure your code adheres to existing coding standards.
5.  Write unit tests for new functionality.
6.  Push your changes to your fork: `git push origin feature/your-feature-name`.
7.  Submit a pull request to the main repository's `develop` or `main` branch.
8.  Clearly describe your changes in the pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details (assuming one would be added).
```
