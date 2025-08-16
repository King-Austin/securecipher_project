import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, AlertCircle, Mail, Loader2 } from 'lucide-react';
import * as SecureKeyManager from '../utils/SecureKeyManager';

export default function Login() {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [userProfile, setUserProfile] = useState(null);
  const navigate = useNavigate();

  // On mount — check if already logged in
  useEffect(() => {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    const profile = localStorage.getItem('userProfile');
    if (isLoggedIn && profile) {
      navigate('/dashboard', { replace: true });
      return;
    }
    if (profile) {
      setUserProfile(JSON.parse(profile));
    }
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();
      if (!keyData) throw new Error('No encryption keys found');

      const { encrypted, salt, iv } = keyData;

      // Attempt decryption with provided PIN
      await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);

      // Save login state
      localStorage.setItem('isLoggedIn', 'true');

      // Redirect after a short delay to avoid race conditions
      window.location.reload();
    } catch (err) {
      console.error('Login error:', err);
      setError('Invalid PIN. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">

          {/* If no user profile exists */}
          {!userProfile && (
            <div className="text-center">
              <AlertCircle className="mx-auto h-12 w-12 text-red-500" />
              <h2 className="mt-2 text-xl font-semibold text-gray-900">No Account Found</h2>
              <p className="mt-2 text-sm text-gray-600">
                We can’t find a registered account on this device. Please register.
              </p>
              <button
                onClick={() => navigate('/register')}
                className="mt-4 w-full py-2 px-4 bg-green-600 text-white text-sm font-medium rounded-md hover:bg-green-700 focus:outline-none"
              >
                Register Now
              </button>
            </div>
          )}

          {/* If user profile exists */}
          {userProfile && (
            <>
              <div className="text-center mb-6">
                <Shield className="mx-auto h-12 w-12 text-green-600" />
                <h2 className="mt-2 text-xl font-semibold text-gray-900">Welcome Back</h2>
                <div className="mt-4 p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-center text-sm text-gray-600">
                    <Mail className="h-4 w-4 mr-2" />
                    <span className="font-medium">{userProfile.email}</span>
                  </div>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                    Enter your PIN
                  </label>
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
                    className={`mt-1 block w-full px-3 py-2 border ${
                      error ? 'border-red-300' : 'border-gray-300'
                    } rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
                    placeholder="••••••"
                  />
                  {error && (
                    <p className="mt-2 text-sm text-red-600 flex items-center">
                      <AlertCircle className="h-4 w-4 mr-1" />
                      {error}
                    </p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={isLoading || pin.length !== 6}
                  className="w-full py-2 px-4 bg-green-600 text-white text-sm font-medium rounded-md hover:bg-green-700 focus:outline-none disabled:bg-gray-400"
                >
                  {isLoading ? (
                    <span className="flex items-center justify-center">
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
