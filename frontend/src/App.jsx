/* eslint-disable no-unused-vars */

import './App.css';
import React from 'react';
import {Login,Signup,Home, CreateProduct, MyProducts} from "./Routes/Routes"
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
    </Routes>
    </BrowserRouter>
  );
}

export default App;
