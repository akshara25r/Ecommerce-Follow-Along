# Ecommerce-Follow-Along

Project Description

The Ecommerce Follow Along project is designed to help developers build a full-stack e-commerce web application using the MERN stack (MongoDB, Express, React, and Node.js). This project follows a hands-on approach, where you will learn and implement key concepts such as user authentication, product management, and order handling through RESTful APIs. By the end of the project, you will have built a functioning e-commerce platform with core features, using JavaScript across both the client and server side.

The MERN stack allows for a seamless and efficient development process, providing a unified language (JavaScript) for the entire stack, making it easier for developers to build, scale, and maintain web applications.

**Milestone 1: **

Project Overview
In this milestone, we introduced the foundations of building a full-stack e-commerce application using the MERN stack. Key topics covered include:

1. Overview of the MERN Stack
The MERN stack is a popular set of technologies used for building modern, scalable, and fast web applications. The stack consists of:
MongoDB (database)
Express.js (backend framework)
React.js (frontend library)
Node.js (JavaScript runtime)
The key advantage of MERN is its JavaScript-only approach, where both the front-end and back-end are built using JavaScript, making development easier and more efficient.
2. REST API Structure and Endpoints
We explored REST APIs (Representational State Transfer) and their role in allowing communication between the client and server.
Key API endpoints were introduced to handle:
User Authentication: Register and log in users with secure authentication.
Product Management: Add, update, and retrieve product data.
Order Handling: Manage customer orders from creation to checkout.
These APIs interact with the database, responding with data in JSON format.
3. Basics of Database Schema Design
In MongoDB, schema design involves defining the structure of data stored in the database, including relationships between different collections such as users, products, and orders.
The schema plays a critical role in ensuring data consistency and making it easier to query.
4. Role of Authentication in Web Applications
Authentication verifies the identity of a user before granting access to certain features or data.
In this project, we focused on building secure authentication mechanisms, allowing users to register, log in, and manage their orders.
We implemented techniques like JWT (JSON Web Tokens) to securely handle user sessions.
Features Implemented
User Authentication:

Sign up and login features using JWT for secure sessions.
Product Management:

Add, update, and view products within the e-commerce platform.
Order Management:

Create, update, and view customer orders.

**Milestone 2: Project Setup and Login Page**


In this milestone, we focused on setting up the initial front-end structure and implementing the login page for the application. Key achievements include:

Front-End Framework:
Set up the React framework with Vite for a fast and modern development experience.
Folder Structure:
Organized the src folder to include separate directories for components, pages, and assets to improve scalability and maintainability.
Login Page Implementation:
Developed a basic login page (Login.jsx) that includes a user interface for email and password input.
Incorporated validation logic to ensure proper user input.
Routing:
Implemented React Router for navigation and created routes for the login and signup pages.
Styling:
Added basic styling using CSS (App.css) to ensure a clean and user-friendly design.
Git Integration:
Added the new files to version control and committed progress to the GitHub repository.
This milestone lays the groundwork for creating the front-end interface and interaction logic for the application.


# Milestone 3: Project Setup for Backend

In this milestone, the foundational backend structure for the e-commerce application was successfully established. Key achievements include:

Backend Folder Structure:
Organized the project into clearly defined folders (config, controller, db, middleware, model, and utility) to ensure scalability and maintainability.
Database Integration:
Set up a connection to MongoDB using Mongoose, enabling seamless interaction with the database.
Environment Configuration
Implemented a .env file to securely manage sensitive data such as database credentials, ensuring better security practices.
Middleware Implementation
Created essential middleware for authentication, error handling, and asynchronous error management to streamline request processing and ensure robust error handling.
Utility Functions
-Added reusable utility components like a custom error handler to improve consistency and simplify debugging.

Git Integration
Configured version control with Git and included a .gitignore file to exclude sensitive files and unnecessary folders like node_modules.
This milestone sets up a solid backend foundation for further development, including API implementation, user authentication, and business logic handling. It ensures that the project is structured, secure, and ready for future expansion.


# Milestone 4: Creating User Model and Controller

In this milestone, the focus was on implementing the user model and controller for managing user data and operations in the backend. Key achievements include:

User Model:
Created a User schema using Mongoose to define the structure for storing user information in the MongoDB database.
Fields include essential user details such as name, email, password, and timestamps.
Added validation for required fields and unique constraints for the email field.
Password Hashing:
Implemented password hashing using bcrypt to securely store user passwords in the database.
User Controller:
Developed a user controller to handle user-related backend operations such as registration and login.
Added methods for creating new users and retrieving user details.
API Endpoints:
Set up API routes for user-related operations, including:
/api/users/register: Endpoint to register a new user.
/api/users/login: Endpoint to authenticate a user.
Error Handling:
Added error handling for scenarios such as duplicate email registration and invalid login credentials.
Git Integration:
Committed progress to version control, ensuring proper documentation of changes and updates.
This milestone provides the necessary backend infrastructure to manage user data, supporting future features like user authentication and authorization.

# Milestone 5: Creating the Signup Page

In this milestone, we focused on developing the signup page to enable users to create an account within the application. Key achievements include:
Signup Page Implementation:
Developed the Signup.jsx component with a user-friendly interface for account registration.
Included form fields for user details such as name, email, and password.
Form Validation:
Added client-side validation logic to ensure proper input formatting and error messages for invalid entries.
Integration with Routing:
Configured navigation to and from the signup page using React Router for seamless user flow.
Styling:
Enhanced the design of the signup page to align with the application's overall styling for a consistent user experience.
Code Organization:
Refactored the code into reusable components where possible to promote cleaner and more maintainable code.
This milestone enhances the user experience by allowing new users to register, paving the way for further integration with back-end user authentication systems.