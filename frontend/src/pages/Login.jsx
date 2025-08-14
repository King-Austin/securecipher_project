import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, AlertCircle, Mail, Loader2 } from 'lucide-react';
import * as SecureKeyManager from '../utils/SecureKeyManager';

export default function Login({ isAuthenticated, userProfile, onAuthChange }) {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [authChecked, setAuthChecked] = useState(false); // Ensure auth check completes before rendering
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard');
    }
    setAuthChecked(true); // Mark auth check as complete
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();
      if (!keyData) {
        throw new Error('No encryption keys found');
      }

      const { encrypted, salt, iv } = keyData;
      await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);

      // Set login status
      localStorage.setItem('isLoggedIn', 'true');

      // Call the parent callback to update authentication state immediately
      if (onAuthChange) {
        onAuthChange();
      }

      // Add a small delay to ensure state updates, then navigate
      setTimeout(() => {
        navigate('/dashboard');
      }, 100);

    } catch (error) {
      console.error('Login error:', error);
      setError('Invalid PIN. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  if (!authChecked) return null; // Wait for auth check to complete

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
          {/* Case 1: No user profile found */}
          {!userProfile && (
            <div className="text-center">
              <AlertCircle className="mx-auto h-12 w-12 text-red-500" />
              <h2 className="mt-2 text-xl font-semibold text-gray-900">
                No Account Found
              </h2>
              <p className="mt-2 text-sm text-gray-600">
                Sorry, we can't find a registered account on this device. Kindly register.
              </p>
              <button
                onClick={() => navigate('/register')}
                className="mt-4 w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                Register Now
              </button>
            </div>
          )}

          {/* Case 2: User profile exists */}
          {userProfile && (
            <>
              <div className="text-center mb-6">
                <Shield className="mx-auto h-12 w-12 text-green-600" />
                <h2 className="mt-2 text-xl font-semibold text-gray-900">
                  Welcome Back
                </h2>
                <div className="mt-4 p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-center text-sm text-gray-600">
                    <Mail className="h-4 w-4 mr-2" />
                    <span className="font-medium">{userProfile.email}</span>
                  </div>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-6 mt-6">
                <div>
                  <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                    Enter your PIN to continue
                  </label>
                  <div className="mt-1">
                    <input
                      id="pin"
                      name="pin"
                      type="password"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      maxLength={6}
                      required
                      value={pin}
                      onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))}
                      className={`appearance-none block w-full px-3 py-2 border ${
                        error ? 'border-red-300' : 'border-gray-300'
                      } rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                      placeholder="••••••"
                    />
                  </div>
                  {error && (
                    <p className="mt-2 text-sm text-red-600" role="alert">
                      <AlertCircle className="inline h-4 w-4 mr-1" />
                      {error}
                    </p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={isLoading || pin.length !== 6}
                  className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {isLoading ? (
                    <span className="flex items-center">
                      <Loader2 className="animate-spin h-4 w-4 mr-2" />
                      Verifying...
                    </span>
                  ) : (
                    'Login'
                  )}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}