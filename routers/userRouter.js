const z = require('zod');
const express = require('express');
const { Router } = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { userModel } = require('../model/userModel');
const authMiddleware = require('../middleware/userMiddleware'); 

const userRouter = Router();
userRouter.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key"; 


userRouter.post("/create", async (req, res) => {
    const requiredBody = z.object({
        name: z.string().min(3, "Minimum 3 characters required").max(50, "Maximum 50 characters required"),
        email: z.string().email("Invalid email format"),
        password: z.string()
            .min(8, "Password must be at least 8 characters long")
            .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
            .regex(/[a-z]/, "Password must contain at least one lowercase letter")
            .regex(/[0-9]/, "Password must contain at least one number")
            .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character"),
        address: z.string().min(5, "Address must be at least 5 characters long"),
        bio: z.string().optional(),
        pfp: z.string().url("Invalid URL format for profile picture").optional()
    });

    const parsedData = requiredBody.safeParse(req.body);
    if (!parsedData.success) {
        return res.status(400).json({
            message: "Incorrect format",
            errors: parsedData.error.format()
        });
    }

    const { name, email, password, address, bio, pfp } = req.body;
    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already in use" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await userModel.create({
            name,
            email,
            password: hashedPassword,
            address,
            bio,
            pfp
        });
        const token = jwt.sign({ id: newUser._id, email: newUser.email }, JWT_SECRET, { expiresIn: "1h" });

        res.status(201).json({
            message: "User Signed Up Successfully",
            token
        });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message });
    }
});

userRouter.post("/login",  async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

        res.json({ message: "Login successful", token });
    } catch (error) {
        res.status(500).json({ message: "Login failed", error: error.message });
    }
});
userRouter.get("/retrieve", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id; 

        const user = await userModel.findById(userId, { password: 0 }); 

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

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
        password: z.string()
            .min(8, "Password must be at least 8 characters long")
            .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
            .regex(/[a-z]/, "Password must contain at least one lowercase letter")
            .regex(/[0-9]/, "Password must contain at least one number")
            .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character")
            .optional(),
        address: z.string().optional(),
        bio: z.string().optional(),
        pfp: z.string().url("Invalid URL format for profile picture").optional()
    });

    const parsedData = updateSchema.safeParse(req.body);
    if (!parsedData.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsedData.error.format() });
    }

    try {
        let { password, ...updateData } = req.body;

        if (password) {
            password = await bcrypt.hash(password, 10);
            updateData.password = password;
        }

        const updatedUser = await userModel.findByIdAndUpdate(id, updateData, { new: true, select: "-password" });

        if (!updatedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: "User updated successfully", user: updatedUser });
    } catch (error) {
        res.status(500).json({ message: "Failed to update user", error: error.message });
    }
});

module.exports = {userRouter};
