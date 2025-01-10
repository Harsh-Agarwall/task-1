# Password Reset API - Node.js & Express

A complete and secure API for managing user authentication and password reset workflows. Built using **Node.js**, **Express.js**, and **MongoDB**, this project handles user registration, login, and password reset functionalities with ease and security.

---

## Features
- **User Registration**: Register users securely with hashed passwords using **bcrypt**.
- **User Login**: Authenticate users with their username and password.
- **Forgot Password**: Generate and send a secure reset token via email.
- **Password Reset**: Validate reset tokens and update passwords securely.
- **Token Expiration**: Ensures reset tokens are valid for a limited time.

---

## Tech Stack
- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **Email Service**: Nodemailer with SMTP (e.g., Gmail)
- **Security**: Bcrypt for password hashing, crypto for token generation

