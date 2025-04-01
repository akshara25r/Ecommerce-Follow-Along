import { configureStore, createSlice } from "@reduxjs/toolkit";

// Create a slice for user state
const userSlice = createSlice({
  name: "user",
  initialState: { email: "" }, // Initial state with empty email
  reducers: {
    setEmail: (state, action) => {
      state.email = action.payload; // Updates email in the state
    }
  }
});

// Export action to update email
export const { setEmail } = userSlice.actions;

// Create store and pass userSlice as a reducer
export const store = configureStore({
  reducer: { user: userSlice.reducer }
});
