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
const sendToken = require("../utils/jwtToken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

// Create user
router.post(
  "/create-user",
  upload.single("file"),
  catchAsyncErrors(async (req, res, next) => {
    console.log("Creating user...");
    const { name, email, password } = req.body;

    const userEmail = await User.findOne({ email });
    if (userEmail) {
      if (req.file) {
        const filepath = path.join(__dirname, "../uploads", req.file.filename);
        try {
          fs.unlinkSync(filepath);
        } catch (err) {
          console.log("Error removing file:", err);
          return res.status(500).json({ message: "Error removing file" });
        }
      }
      return next(new ErrorHandler("User already exists", 400));
    }

    let fileUrl = "";
    if (req.file) {
      fileUrl = path.join("uploads", req.file.filename);
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      avatar: {
        public_id: req.file?.filename || "",
        url: fileUrl,
      },
    });

    const activationToken = createActivationToken(user);
    const activationUrl = `http://localhost:3000/activation/${activationToken}`;

    try {
      await sendMail({
        email: user.email,
        subject: "Account Activation",
        message: `Please click on the link to activate your account: ${activationUrl}`,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 400));
    }

    console.log("User created:", user);
    res.status(201).json({ success: true, user });
  })
);

// User login
router.post(
  "/login",
  catchAsyncErrors(async (req, res, next) => {
    console.log("Logging in user...");
    const { email, password } = req.body;

    if (!email || !password) {
      return next(new ErrorHandler("Please provide email and password", 400));
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return next(new ErrorHandler("Invalid Email or Password", 401));
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);
    if (!isPasswordMatched) {
      return next(new ErrorHandler("Invalid Email or Password", 401));
    }

    user.password = undefined;
    res.status(200).json({
      success: true,
      user,
    });
  })
);

// Account activation
// router.post(
//   "/activation",
//   catchAsyncErrors(async (req, res, next) => {
//     const { activation_token } = req.body;

//     try {
//       const newUser = jwt.verify(activation_token, process.env.ACTIVATION_SECRET);

//       if (!newUser) {
//         return next(new ErrorHandler("Invalid token", 400));
//       }

//       const { name, email, password, avatar } = newUser;

//       const existingUser = await User.findOne({ email });
//       if (existingUser) {
//         return next(new ErrorHandler("User already exists", 400));
//       }

//       const user = await User.create({
//         name,
//         email,
//         password,
//         avatar,
//       });

//       sendToken(user, 200, res);
//     } catch (error) {
//       console.log("Activation error:", error);
//       return next(new ErrorHandler("Invalid token", 400));
//     }
//   })
// );

// const createActivationToken = (user) => {
//   return jwt.sign(user, process.env.ACTIVATION_SECRET, { expiresIn: "35m" });
// };

module.exports = router;
