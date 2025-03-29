const jwt = require("jsonwebtoken");
require("dotenv").config(); // Load environment variables

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization; // Extract token from "Bearer <token>"

    if (!token) {
        return res.status(401).json({ message: "Access Denied: No Token Provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token
        req.user = decoded; // Attach user data to request
        next(); // Proceed to next middleware or route
    } catch (error) {
        return res.status(403).json({ message: "Invalid or Expired Token", error: error.message });
    }
};

module.exports = authMiddleware;
