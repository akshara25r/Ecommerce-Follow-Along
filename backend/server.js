const app = require("./app");
const connectDatabase = require("./db/Database");
// const cors = require('cors');
// app.use(cors({ origin: 'http://localhost:5173' }));

// Handling uncaught Exception when setting up backend server
process.on("uncaughtException", (err) => {
  console.log(`Error: ${err.message}`);
  console.log("shutting down the server for handling uncaught exception");
});

// config
if (process.env.DB_URL  !== "PRODUCTION") {
  require("dotenv").config({
    path: "config/.env",
  });
}

// connect db
connectDatabase();

// create server
const server = app.listen(process.env.PORT, () => {
  console.log(
    `Server is running on http://localhost:${process.env.PORT}`
  );
});


  // unhandled promise rejection(explain error handling when setting up server as you code)
  process.on("unhandledRejection", (err) => {
    console.error(`Unhandled Rejection: ${err.message}`);
    console.log("Shutting down the server due to unhandled promise rejection.");
    
    server.close(() => {
      process.exit(1); // Exit with failure code
    });
  });