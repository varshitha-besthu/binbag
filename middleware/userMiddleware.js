const jwt = require("jsonwebtoken");
require("dotenv").config();

const authMiddleware = (req, res, next) => {
  const authcookie = req.cookies["authcookie"];

  if (!authcookie) return res.status(401).json({ message: "Access Denied: No Token Provided" });

  try {
    const decoded = jwt.verify(authcookie, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or Expired Token", error: error.message });
  }
};

module.exports = authMiddleware;
