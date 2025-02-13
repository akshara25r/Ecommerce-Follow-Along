// backend/app.js

const express = require("express");
const path = require("path");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const ErrorHandler = require("./middleware/error");

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Configure CORS to allow requests from React frontend
app.use(cors({
  // origin: 'http://localhost:3000', // Update this if your frontend is hosted elsewhere
  origin:'*',
  credentials: true, // Enable if you need to send cookies or authentication headers
}));

app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));

// Serve static files for uploads and products
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/products', express.static(path.join(__dirname, 'products')));

// Import Routes
const userRoutes = require("./controller/user");
const productRoutes = require('./controller/product');

// Route Handling
app.use("/api/v2/user", userRoutes);
app.use("/api/v2/product", productRoutes);

// Error Handling Middleware
app.use(ErrorHandler);

module.exports = app;