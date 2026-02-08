// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { getMessaging } from "firebase-admin/messaging";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyC2M1uA3Pp0zHsTCx6w14c_DX1sYfjodg0",
  authDomain: "expensetracker-2759d.firebaseapp.com",
  projectId: "expensetracker-2759d",
  storageBucket: "expensetracker-2759d.firebasestorage.app",
  messagingSenderId: "874326601085",
  appId: "1:874326601085:web:357c2be9efd52ea4bfb014",
  measurementId: "G-CLSK6WETHM"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const messaging = getMessaging(app)