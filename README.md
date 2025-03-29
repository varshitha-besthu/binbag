# User Authentication API

This is an Express.js-based User Authentication API that supports user registration, login, and logout functionalities.

## Features
- User registration with validation
- Secure password hashing using bcrypt
- JSON Web Token (JWT) authentication
- User login
- User logout

## Technologies Used
- Node.js
- Express.js
- MongoDB (Mongoose ORM)
- bcrypt for password hashing
- JSON Web Token (JWT)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/varshitha-besthu/binbag.git
   cd BIBA
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up environment variables:
   Create a `.env` file and add the following variables:
   ```env
   PORT=5000
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_secret_key
   ```

4. Run the server:
   ```bash
   node index.js
   ```

## API Endpoints

### 1. **User Registration**
**Endpoint:** `POST /create`

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "johndoe@example.com",
  "password": "Secure@123",
  "address": "123 Main Street",
  "bio": "Software developer",
  "pfp": "https://example.com/profile.jpg"
}
```

**Response:**
```json
{
  "message": "User registered successfully"
}
```

### 2. **User Login**
**Endpoint:** `POST /login`

**Request Body:**
```json
{
  "email": "johndoe@example.com",
  "password": "Secure@123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "your_jwt_token_here"
}
```

### 3. **User Logout**
**Endpoint:** `POST /logout`

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

## Security Measures
- Passwords are hashed using bcrypt before storing in the database.
- JWT is used for authentication to secure user sessions.
- Request validation is handled using `zod` to ensure input integrity.

## Postman-Documentation 
- https://documenter.getpostman.com/view/40612987/2sB2cPj5oj

## License
This project is licensed under the MIT License.

---

Feel free to contribute or raise issues to improve this API! 🚀

