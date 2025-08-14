import { useState, useEffect } from 'react';
import { X, Eye, EyeOff } from 'lucide-react';

export default function PinModal({ isOpen, onClose, onSubmit, isLoading = false }) {
  const [pin, setPin] = useState('');
  const [showPin, setShowPin] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (error) {
      console.error('Error in PinModal:', error);
    }
  }, [error]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    try {
      if (!pin.trim()) {
        throw new Error('PIN is required');
      }

      onSubmit(pin);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleClose = () => {
    setPin('');
    setError('');
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md mx-4">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold text-gray-800">
            Enter PIN to Refresh Data
          </h3>
          <button
            onClick={handleClose}
            disabled={isLoading}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label htmlFor="pin" className="block text-sm font-medium text-gray-700 mb-2">
              Security PIN
            </label>
            <div className="relative">
              <input
                type={showPin ? 'text' : 'password'}
                id="pin"
                inputMode='numeric'
                maxLength={6}
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                disabled={isLoading}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your PIN"
                autoComplete="off"
              />
              <button
                type="button"
                onClick={() => setShowPin(!showPin)}
                disabled={isLoading}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showPin ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {error && (
              <p className="mt-1 text-sm text-red-600">{error}</p>
            )}
          </div>

          <div className="flex space-x-3">
            <button
              type="button"
              onClick={handleClose}
              disabled={isLoading}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:border-transparent transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || !pin.trim()}
              className="flex-1 px-4 py-2 bg-green-700 text-white rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  <span className="ml-2">Refreshing...</span>
                </div>
              ) : (
                'Refresh Data'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
