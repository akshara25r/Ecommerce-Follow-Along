const express = require("express");
const path = require("path");
const fs = require("fs"); 
const User = require("../model/user");
const router = express.Router();
const { upload } = require("../multer");
const ErrorHandler = require("../utils/ErrorHandler");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const jwt = require("jsonwebtoken");
const sendMail = require("../utils/sendMail");

// Create User
router.post("/create-user", upload.single("file"), async (req, res, next) => {
    try {
        const { name, email, password } = req.body;
        const userEmail = await User.findOne({ email });

        if (userEmail) {
            console.log("User already exists:", userEmail);
            if (req.file) {
                const filename = req.file.filename;
                const filepath = path.join(__dirname, "../uploads", filename);

                if (fs.existsSync(filepath)) {
                    try {
                        fs.unlinkSync(filepath);
                    } catch (err) {
                        console.error("Failed to delete file:", err);
                    }
                }
            }
            return next(new ErrorHandler("User already exists", 400));
        }

        const filename = req.file.filename;
        const fileUrl = `/uploads/${filename}`;

        const user = { name, email, password, avatar: fileUrl };
        const activationToken = createActivationToken(user);
        const activationUrl = `http://localhost:8000/activation/${activationToken}`;

        try {
            await sendMail({
                email: user.email,
                subject: "Account Activation",
                message: `Please click on the link to activate your account: ${activationUrl}`,
            });
        } catch (error) {
            return next(new ErrorHandler(error.message, 400));
        }

        console.log("User registration initiated:", user);
        res.status(201).json({
            success: true,
            message: "User registered successfully. Please check your email for activation.",
        });

    } catch (error) {
        return next(new ErrorHandler(error.message, 500));
    }
});

// Function to create activation token
const createActivationToken = (user) => {
    return jwt.sign(user, process.env.ACTIVATION_SECRET, { expiresIn: "5m" });
};

// Activate User
router.post("/activation", catchAsyncErrors(async (req, res, next) => {
    try {
        console.log("Activation request received");
        const { activation_token } = req.body;

        const newUser = jwt.verify(activation_token, process.env.ACTIVATION_SECRET);
        if (!newUser) {
            return next(new ErrorHandler("Invalid activation token", 400));
        }

        const { name, email, password, avatar } = newUser;
        let existingUser = await User.findOne({ email });

        if (existingUser) {
            return next(new ErrorHandler("User already exists", 400));
        }

        let user = await User.create({ name, email, avatar, password });
        
        res.status(200).json({
            success: true,
            message: "Account activated successfully",
            user,
        });

    } catch (error) {
        return next(new ErrorHandler("Invalid or expired token", 400));
    }
}));

module.exports = router;
