const z = require("zod");
const express = require("express");
const { Router } = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const helmet = require("helmet"); 
const cookieParser = require("cookie-parser");
const { userModel } = require("../model/userModel");
const authMiddleware = require("../middleware/userMiddleware");

const userRouter = Router();

userRouter.use(express.json());
userRouter.use(cookieParser());
userRouter.use(
  helmet({
    contentSecurityPolicy: false, 
    frameguard: { action: "deny" }, 
    hidePoweredBy: true, 
    hsts: { maxAge: 31536000, includeSubDomains: true }, 
  })
);

if (!process.env.JWT_SECRET) {
  console.error("FATAL ERROR: JWT_SECRET is not set");
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

userRouter.post("/signup", async (req, res) => {
    const requiredBody = z.object({
      name: z.string().min(3).max(50),
      email: z.string().email(),
      password: z
        .string()
        .min(8)
        .regex(/[A-Z]/, "Must have 1 uppercase letter")
        .regex(/[a-z]/, "Must have 1 lowercase letter")
        .regex(/[0-9]/, "Must have 1 number")
        .regex(/[^A-Za-z0-9]/, "Must have 1 special character"),
      address: z.string().min(5),
      bio: z.string().optional(),
      pfp: z.string().url().optional(),
    });
  
    const parsedData = requiredBody.safeParse(req.body);
    if (!parsedData.success) {
      return res.status(400).json({ message: "Incorrect format", errors: parsedData.error.format() });
    }
  
    const { name, email, password, address, bio, pfp } = req.body;
  
    try {
      if (await userModel.findOne({ email })) {
        return res.status(400).json({ message: "Email already in use" });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      await userModel.create({
        name,
        email,
        password: hashedPassword,
        address,
        bio,
        pfp,
      });
  
      // ✅ Sending a response after successful signup
      res.status(201).json({ message: "User signed up successfully. Please log in." });
  
    } catch (error) {
      res.status(500).json({ message: "Internal Server Error", error: error.message });
    }
});
  
userRouter.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid email or password" });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    res
      .cookie("authcookie", token, { maxAge: 90000, httpOnly: true, secure: true, sameSite: "Strict" })
      .json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Login failed", error: error.message });
  }
});


userRouter.post("/logout", async (req, res) => {
  try {
    res.clearCookie("token", { httpOnly: true, secure: true, sameSite: "strict" });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error", error: error.message });
  }
});


userRouter.get("/retrieve", authMiddleware, async (req, res) => {
  try {
    const user = await userModel.findById(req.user.id, { password: 0 });
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Failed to retrieve user", error: error.message });
  }
});

userRouter.put("/update/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const updateSchema = z.object({
    name: z.string().optional(),
    email: z.string().email().optional(),
    password: z
      .string()
      .min(8)
      .regex(/[A-Z]/)
      .regex(/[a-z]/)
      .regex(/[0-9]/)
      .regex(/[^A-Za-z0-9]/)
      .optional(),
    address: z.string().optional(),
    bio: z.string().optional(),
    pfp: z.string().url().optional(),
  });

  const parsedData = updateSchema.safeParse(req.body);
  if (!parsedData.success) {
    return res.status(400).json({ message: "Invalid update data", errors: parsedData.error.format() });
  }

  try {
    let { password, ...updateData } = req.body;
    if (password) updateData.password = await bcrypt.hash(password, 10);

    const updatedUser = await userModel.findByIdAndUpdate(id, updateData, { new: true, select: "-password" });

    if (!updatedUser) return res.status(404).json({ message: "User not found" });

    res.json({ message: "User updated successfully", user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: "Failed to update user", error: error.message });
  }
});

module.exports = { userRouter };
