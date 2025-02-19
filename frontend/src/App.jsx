/* eslint-disable no-unused-vars */

import './App.css';
import React from 'react';
import {Login,Signup,Home, CreateProduct, MyProducts, Cart, ProductDetails} from "./Routes/Routes"
import { BrowserRouter, Routes, Route } from "react-router-dom";
function App() {
  return (
    <BrowserRouter>
    <Routes>
    <Route path='/' element={<Home/>}/>
    <Route path='/login' element={<Login/>}/>
    <Route path='/create-user' element={<Signup/>}/>
    <Route path='/create-product' element={<CreateProduct/>}/>  
    {/* For edit product by id */}
    <Route path="/create-product/:id" element={<CreateProduct />} />
    <Route path="/my-products" element={<MyProducts/>} />
    <Route path="/cart" element={<Cart/>} />
    <Route path="/product/:id" element={<ProductDetails />} />
    </Routes>
    </BrowserRouter>
  );
}

export default App;
