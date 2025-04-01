import { setEmail } from "./store";

// Action creator to set user email
export const setUserEmail = (email) => (dispatch) => {
  dispatch(setEmail(email));
};
