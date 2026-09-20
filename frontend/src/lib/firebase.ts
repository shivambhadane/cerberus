import { initializeApp } from "firebase/app";
import {
  getAuth,
  GoogleAuthProvider,
  GithubAuthProvider,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signOut as fbSignOut,
  updateProfile,
  onAuthStateChanged,
} from "firebase/auth";
import type { User as FirebaseUser } from "firebase/auth";

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyA6rcwS4w5IJ3nuSUm00YAMW5EFpuiOZkk",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "cerberus-a2be4.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "cerberus-a2be4",
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "cerberus-a2be4.firebasestorage.app",
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "491958432804",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:491958432804:web:fd606f2072415bda0b94b1",
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || "G-TBE3RXLM47",
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();
export const githubProvider = new GithubAuthProvider();
githubProvider.addScope("read:user");
githubProvider.addScope("user:email");

// Initialize analytics safely if supported in current browser environment
if (typeof window !== "undefined") {
  import("firebase/analytics")
    .then(({ getAnalytics, isSupported }) => isSupported().then((ok) => ok && getAnalytics(app)))
    .catch(() => undefined);
}

export async function getCurrentIdToken(forceRefresh = false): Promise<string | null> {
  const user = auth.currentUser;
  if (!user) return null;
  return user.getIdToken(forceRefresh);
}

export function formatFirebaseError(error: unknown): string {
  if (!error || typeof error !== "object") {
    return "An unexpected error occurred. Please try again.";
  }
  const code = "code" in error ? String((error as { code: unknown }).code) : "";
  switch (code) {
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found":
      return "Incorrect email or password.";
    case "auth/email-already-in-use":
      return "An account with this email already exists. Please sign in.";
    case "auth/weak-password":
      return "Password is too weak. Please use at least 6 characters.";
    case "auth/invalid-email":
      return "Please enter a valid email address.";
    case "auth/user-disabled":
      return "This account has been disabled. Contact support.";
    case "auth/popup-closed-by-user":
      return "Sign in was cancelled before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by your browser. Please allow popups for this site.";
    case "auth/account-exists-with-different-credential":
      return "An account already exists with this email using a different sign-in method. Please sign in with that method.";
    case "auth/credential-already-in-use":
      return "This credential is already linked to another account.";
    case "auth/unauthorized-domain":
      return "This domain is not authorized in Firebase Auth. Add it under Firebase Console > Authentication > Settings.";
    case "auth/operation-not-allowed":
      return "This sign-in provider is not enabled in your Firebase Console. Please enable it under Authentication > Sign-in method.";
    case "auth/too-many-requests":
      return "Too many failed attempts. Please try again later.";
    case "auth/network-request-failed":
      return "Network connection error. Check your internet connection.";
    default:
      return "message" in error && typeof (error as { message: unknown }).message === "string"
        ? (error as { message: string }).message
        : "Failed to authenticate. Please try again.";
  }
}

export {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  fbSignOut,
  updateProfile,
  onAuthStateChanged,
};
export type { FirebaseUser };
