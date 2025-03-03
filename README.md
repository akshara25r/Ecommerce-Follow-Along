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

# Milestone 6: creating the backend endpoint for the Signup page to store all user data securely
Create a secure backend endpoint for user signup, encrypting passwords and storing user data safely.

Goals:
-Encrypt passwords before saving. -Securely store user details in the database.

Why Encrypt Passwords?
-Protect Data: Keeps passwords safe if breached. -Privacy: Prevents password visibility. -Compliance: Meets GDPR, PCI-DSS standards. -Security: Thwarts password theft.

Steps:

# Milestone 7: Creating the Login Endpoint
In this milestone, we focused on implementing a secure and efficient login endpoint for user authentication. Key achievements include:

1. Login Endpoint Creation:
Developed an API endpoint (/api/users/login) to handle user login requests.
Configured the endpoint to accept user credentials, such as email/username and password.
2. User Retrieval:
Implemented logic to retrieve the corresponding user from the MongoDB database based on the provided email or username.
3. Password Validation:
Utilized bcrypt to compare the hashed password entered by the user with the stored hashed password in the database.
Ensured that only valid credentials allow user authentication while providing appropriate error messages for invalid inputs.
4. Error Handling:
Added robust error handling to return informative responses for scenarios such as:
Non-existent users.
Incorrect passwords.
5. Security Enhancements:
Ensured that sensitive user data, such as passwords, remains protected during authentication. 
Followed industry best practices to prevent common vulnerabilities, such as brute force attacks.
This milestone provides the foundation for user authentication, paving the way for implementing session management and token-based authentication in future milestones. 

# Milestone 8: Designing the Homepage and Card Component
In this milestone, we focused on creating a visually appealing and functional homepage layout with reusable components for showcasing products. Key achievements include:

1. Card Component:
Designed a reusable card component for displaying product details.
Configured props to dynamically render product information such as:
Product Name
Product Image
Product Price
2. Homepage Layout:
Set up a clean and responsive homepage layout for displaying multiple product cards.
Utilized grid layout and flexbox to ensure a visually consistent and user-friendly design.
3. Component Reusability:
Ensured the card component is modular and adaptable for use across different pages of the application.
4. Code Submission:
Pushed the updated code to the GitHub repository.

# Milestone 9: Creating the Product Form
In this milestone, we focused on building a form that allows users to add products, including support for multiple product images. Key achievements include:

1. Product Form Implementation:
Designed and developed a form to capture essential product details, such as:
Product Name
Description
Price
Category
Multiple Product Images (file upload support)
2. Image Upload Handling:
Implemented functionality to allow multiple product images to be uploaded.
Ensured proper validation for image formats and file sizes.
3. Data Management:
Configured state management to handle form inputs efficiently.
Validated user inputs before submission to ensure accurate product data.

# Milestone 10: Creating the Product Schema and API Endpoint
In this milestone, we focused on defining the structure of product data and creating an API endpoint to store product details in MongoDB.

1. Product Schema Definition:
Defined a structured product schema using Mongoose to store product data in MongoDB.
Ensured each field has proper validation to maintain data integrity:
Name: Required, string
Description: Required, string
Price: Required, number, with validation for non-negative values
Image URL(s): Required, array of strings for multiple image storage
Category: Required, string
CreatedAt: Automatically generated timestamp
2. Endpoint Creation:
Developed a POST endpoint (/api/products) to accept product details from the frontend.
Implemented validation to ensure only correctly formatted data is stored in the database.
Saved product information to MongoDB using Mongoose models.
3. Data Validation & Integrity:
Enforced strict validation to prevent invalid or incomplete product entries.
Returned appropriate error messages for missing or incorrect data inputs.

# Milestone 11: Fetching and Displaying Product Data
In this milestone, we focused on retrieving product data from the backend and dynamically displaying it in the frontend. Key achievements include:

1. Backend: Creating an API Endpoint to Fetch All Products
Developed a GET endpoint (/api/products) in the backend to send all product data to the frontend.
Implemented MongoDB queries using Mongoose to retrieve all stored products.
Ensured error handling to manage potential issues in fetching data.
2. Frontend: Fetching Data from API
Created an API call function using fetch or axios in React to retrieve product data from the backend.
Managed the fetched data using React useState and useEffect hooks to ensure dynamic updates.
3. Displaying Products Dynamically
Passed the fetched product data to a ProductCard component.
Used the product details (name, image, price, etc.) as props to display them dynamically.
Applied responsive CSS styling to create a visually appealing product grid layout.

# Milestone 12: Filtering Products by User Email and Displaying Data
In this milestone, we focused on filtering products based on the user's email and sending only relevant product data to the frontend. Key achievements include:

1. Backend: Creating a Filtered API Endpoint
Developed a GET endpoint (/api/products/:email) to return products associated with a specific user email.
Used Mongoose to query the database and fetch only the products uploaded by the provided email.
Implemented error handling to manage scenarios where no products match the email.
2. Frontend: Fetching Filtered Data from API
Created a function in React to fetch only products uploaded by the logged-in user.
Used Axios or Fetch API to make requests to the backend with the logged-in user's email.
Managed product data using useState and useEffect hooks.
3. Displaying Filtered Products Dynamically
Passed the fetched filtered product data to a ProductCard component.
Rendered product details such as name, image, price, and description dynamically.
Ensured a clean and structured UI using CSS and responsive layout techniques.

# Milestone 13: Updating Product Data and Form Auto-Fill
In this milestone, we focused on implementing update functionality for product data, allowing users to modify existing product information through an editable form. Key achievements include:

Backend: Creating an Update Endpoint
Developed a PUT endpoint to receive and update existing product data in MongoDB.
Used Mongoose to find the product by its ID and update its fields.
Ensured data validation to maintain data integrity and prevent errors during updates.
Handled potential errors, such as cases where the product is not found.
Frontend: Form Auto-Fill and Edit Functionality
Added an Edit button to each product card.
Clicking the Edit button opens a form pre-filled with the existing product details.
Users can modify the form fields and save changes to update the product.
Used React state and useEffect to manage form data and populate it with the product’s current details.
UI and UX Enhancements
Ensured a responsive layout for the edit form, providing a user-friendly experience.
Added error messages for invalid data and success notifications on successful updates.
Future Enhancements & Experimentation
Admin-Only Access: Restrict update functionality to authorized users, such as shop owners or admins.
Real-Time Updates: Implement real-time data updates on the product listing page.
Optimized Form Design: Enhance the form with file uploads for updating product images and improved field validation.

# Milestone 14: Deleting Product Data from MongoDB
In this milestone, we focused on implementing delete functionality for product data, allowing users to remove existing product records from the database. Key achievements include:

Backend: Creating a Delete Endpoint
Developed a DELETE endpoint to remove product data from MongoDB using the product ID.
Used Mongoose to find and delete the product by its ID.
Implemented error handling to manage scenarios where the product ID does not exist.

Frontend: Delete Button and Request Handling
Added a Delete button to each product card.
Clicking the Delete button sends a request to the delete endpoint with the product ID.
Implemented a confirmation dialog to ensure users intend to delete the product.
Updated the product list dynamically to remove the deleted product without refreshing the page.

UI and UX Enhancements
Provided feedback on successful or failed delete operations.
Enhanced the user experience with a clean and responsive UI for managing product deletions.

# Milestone 15: Creating a Responsive Navbar
In this milestone, we focused on building a reusable and responsive Nav component that enhances navigation across multiple pages of the e-commerce application. Key achievements include:

Frontend: Creating the Nav Component
Designed a new Nav component with navigation links to all key pages:
Home
My Products
Add Product
Cart
Implemented smooth navigation between these pages using React Router.
Responsive Design
Used CSS Flexbox and media queries to ensure the Navbar is fully responsive on all screen sizes (mobile, tablet, desktop).
Added a hamburger menu for smaller screens to toggle the navigation links.


# Milestone 16: Product Info Page with Quantity Selection and Add to Cart
In this milestone, we focused on creating a dedicated Product Info Page to display detailed information for each product and allow users to select quantity and add the product to their cart.

Frontend: Product Info Page
Designed a new Product Info Page that shows all relevant product details such as:
Product Name
Product Description
Product Price
Product Images
Added a quantity selector that allows users to choose how many units they want to add to their cart.
Implemented an Add to Cart button to add the selected product and quantity to the user's cart.
React Router Integration
Used React Router to navigate to the Product Info Page when a product card is clicked on the homepage or product listing page.
Passed the product ID through the URL to fetch and display product details on the new page.
State Management and API Integration
Fetched product details from the backend using the product ID.
Managed the selected quantity using React state.
Implemented a function to handle adding the product to the cart, updating the cart state in the application.

# Milestone 17: Adding Products to Cart
In this milestone, we focused on implementing the functionality to add products to the cart. Key achievements include

Frontend: Adding Products to Cart
Designed a new Cart component that displays the products added to the cart, along with their
Implemented a function to handle adding products to the cart, updating the cart state in the application.
Used React state to manage the cart items and their quantities.
Backend: API Integration
Created a new API endpoint to handle adding products to the cart.
Implemented server-side logic to update the cart state in the database.
State Management and API Integration
Fetched the updated cart state from the backend after adding a product.
Managed the cart state using React state.

# Milestone 18: Creating an end point for cart page
In this milestone, we implemented a backend endpoint to fetch all the products inside a user's cart. This functionality is essential for displaying the cart contents on the cart page.

Backend: API Integration
Created a new API endpoint to fetch all products in a user's cart.
Implemented server-side logic to retrieve the cart contents from the database.
Frontend: Cart Page
Designed a new Cart Page component that displays the products in the user's cart.
Used React Router to navigate to the Cart Page.
State Management and API Integration
Fetched the cart contents from the backend using the API endpoint. The final product will have the following features:
A user can view all products on the homepage.
A user can view product details on a dedicated product info page.
A user can add products to their cart.
A user can view their cart contents on the cart page.

# Milestone 19: Shopping Cart UI with API Endpoint for Updating Product Quantity
In this milestone, we focused on implementing the shopping cart UI and API endpoint for updating product quantity.

Frontend: Shopping Cart UI
Designed a new Cart component that displays the products in the user's cart, along with their quantities
Implemented a function to handle updating the quantity of a product in the cart
Used React state to manage the cart items and their quantities
Backend: API Endpoint for Updating Product Quantity
Created a new API endpoint to update the quantity of a product in the cart
Implemented server-side logic to update the cart state in the database
State Management and API Integration
Fetched the updated cart state from the backend after updating a product quantity The final product will have the following features:
A user can view all products on the homepage
A user can view product details on a dedicated product info page
A user can add products to their cart
A user can view their cart contents on the cart page
A user can update the quantity of products in their cart