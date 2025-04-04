
/* eslint-disable no-unused-vars */


import React from "react";
import ReactDOM from "react-dom";
import { createRoot } from 'react-dom/client'
import { Provider } from "react-redux";
import  store  from "./store/store";
import App from "./App.jsx";

createRoot(document.getElementById('root')).render(
  <Provider store={store}>
  <App />
</Provider>,
)

