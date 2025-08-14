import { useState } from 'react';
import { Shield, AlertCircle, Loader2 } from 'lucide-react';

export default function PinUnlockModal({ open, onUnlock, onClose, verifying }) {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [isSuccess, setIsSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await onUnlock(pin);
      setPin('');
      setIsSuccess(true);
      
      // Set localStorage with delay
      localStorage.setItem('isLoggedIn', 'true');
      
      // Wait for 1.5 seconds before redirecting
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 1500);
      
    } catch (err) {
      setError(err?.message || 'Invalid PIN. Please try again.');
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-lg p-8 max-w-sm w-full mx-4">
        {isSuccess ? (
          // Success State
          <div className="text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Shield className="h-8 w-8 text-green-600" />
            </div>
            <h2 className="text-xl font-bold text-gray-800 mb-2">Authentication Successful</h2>
            <p className="text-sm text-gray-600">Redirecting to dashboard...</p>
            <Loader2 className="h-6 w-6 mx-auto mt-4 animate-spin text-green-600" />
          </div>
        ) : (
          // PIN Entry State
          <>
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Shield className="h-8 w-8 text-green-600" />
              </div>
              <h2 className="text-xl font-bold text-gray-800">SecureCipher</h2>
              <p className="text-sm text-gray-600 mt-1">Enter your security PIN to access</p>
            </div>
            <form onSubmit={handleSubmit} className="space-y-4">
              <input
                type="password"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                autoFocus
                required
                value={pin}
                onChange={e => setPin(e.target.value.replace(/[^0-9]/g, ''))}
                className="block w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-center text-lg font-mono"
                placeholder="••••••"
                disabled={verifying}
              />
              {error && (
                <div className="flex items-center justify-center text-sm text-red-600">
                  <AlertCircle className="h-4 w-4 mr-1" />
                  {error}
                </div>
              )}
              <button
                type="submit"
                disabled={verifying || pin.length !== 6}
                className="w-full py-3 px-4 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 disabled:bg-gray-400 transition-colors"
              >
                {verifying ? (
                  <span className="flex items-center justify-center">
                    <Loader2 className="animate-spin h-4 w-4 mr-2" />
                    Verifying...
                  </span>
                ) : (
                  'Unlock'
                )}
              </button>
              <button
                type="button"
                onClick={onClose}
                className="w-full mt-2 py-2 px-4 bg-gray-200 text-gray-700 rounded-lg font-medium hover:bg-gray-300 transition-colors"
              >
                Cancel
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}