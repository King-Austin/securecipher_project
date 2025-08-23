// Onboarding.jsx
import React from "react";
import { useNavigate } from "react-router-dom";

export default function Onboarding() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-gray-900 via-black to-gray-800 text-white">
      {/* Header / Navbar */}
      <header className="flex items-center justify-between px-6 py-4 bg-black/40 backdrop-blur-md">
        <h1 className="text-2xl font-bold tracking-wide">SecureCipherBank</h1>
        <div className="flex space-x-4">
          <button onClick={() => navigate('/login')} className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 transition font-medium">
            Login
          </button>
          <button onClick={() => navigate('/register')} className="px-4 py-2 rounded-lg bg-gray-700 hover:bg-gray-600 transition font-medium">
            Register
          </button>
        </div>
      </header>

      {/* Hero / Intro Section */}
      <main className="flex flex-1 flex-col items-center justify-center text-center px-6">
        <h2 className="text-4xl md:text-5xl font-bold mb-4">
          Welcome to <span className="text-indigo-400">SecureCipher App</span>
        </h2>
        <p className="max-w-xl text-lg text-gray-300 mb-8">
          Your transactions deserve security. <br />
          Onboard as a <span className="font-semibold">SecureCipherBankingUser</span> today —
          not just an account, but a trusted digital gateway.
        </p>
          <button onClick={() => navigate('/register')} className="px-8 py-3 text-lg rounded-2xl bg-indigo-600 hover:bg-indigo-700 transition font-semibold shadow-md">
          Get Started
        </button>
      </main>

      {/* Footer */}
      <footer className="bg-black/50 py-4 text-center text-gray-400 text-sm">
        © {new Date().getFullYear()} SecureCipherBank — Nigeria.
      </footer>
    </div>
  );
}
