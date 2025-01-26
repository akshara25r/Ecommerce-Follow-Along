/* eslint-disable no-unused-vars */

import './App.css';
import React from 'react';
import {Login} from "./Routes/Routes"
import { BrowserRouter, Routes, Route } from "react-router-dom";
function App() {
  return (
    <BrowserRouter>
    <Routes>
    <Route path='/login' element={<Login/>}/>
    </Routes>
    </BrowserRouter>
  );
}

export default App;
