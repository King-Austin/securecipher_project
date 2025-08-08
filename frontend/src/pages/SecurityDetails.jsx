import { useState, useEffect } from 'react';
import { Shield, Copy, Check, Info, AlertCircle } from 'lucide-react';
import * as SecureKeyManager from '../utils/SecureKeyManager';
import { useNavigate } from 'react-router-dom';

export default function SecurityDetails() {
  const navigate = useNavigate();
  const [publicKeyPem, setPublicKeyPem] = useState('');
  const [copied, setCopied] = useState(false);
  const [showFullKey, setShowFullKey] = useState(false);
  const [keyCreatedAt, setKeyCreatedAt] = useState('');
  const [deviceInfo, setDeviceInfo] = useState('');
  const [showPinModal, setShowPinModal] = useState(true);
  const [pin, setPin] = useState('');
  const [pinError, setPinError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    setDeviceInfo(`${navigator.platform}, ${navigator.userAgent}`);
  }, []);

  const handlePinSubmit = async (e) => {
    e.preventDefault();
    setIsVerifying(true);
    setPinError('');
    try {
      const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();
      if (!keyData) {
        navigate('/register', { replace: true });
        return;
      }
      if (keyData.createdAt) setKeyCreatedAt(new Date(keyData.createdAt).toLocaleString());
      const { encrypted, salt, iv } = keyData;
      const keyPair = await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);
      const publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(keyPair.publicKey);
      setPublicKeyPem(publicKeyPem);
      setShowPinModal(false);
    } catch {
      setPinError('Invalid PIN. Please try again.');
    } finally {
      setIsVerifying(false);
    }
  };

  const formattedKey = (pem) => {
    if (!pem) return '';
    const clean = pem.replace(/-----.*-----|\n/g, '');
    return showFullKey ? clean : `${clean.slice(0, 20)}...${clean.slice(-20)}`;
  };

  const copyPublicKey = () => {
    navigator.clipboard.writeText(publicKeyPem);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div>
      {/* PIN Modal */}
      {showPinModal && (
        <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg p-8 max-w-sm w-full">
            <h2 className="text-xl font-bold mb-4 text-gray-800 flex items-center">
              <Shield className="h-6 w-6 text-green-600 mr-2" />
              Enter Security PIN
            </h2>
            <form onSubmit={handlePinSubmit} className="space-y-4">
              <input
                type="password"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                autoFocus
                required
                value={pin}
                onChange={e => setPin(e.target.value.replace(/[^0-9]/g, ''))}
                className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500"
                placeholder="Enter your 6-digit PIN"
                disabled={isVerifying}
              />
              {pinError && (
                <div className="flex items-center text-sm text-red-600">
                  <AlertCircle className="h-5 w-5 mr-1" />
                  {pinError}
                </div>
              )}
              <button
                type="submit"
                disabled={isVerifying || pin.length !== 6}
                className="w-full py-2 px-4 bg-green-600 text-white rounded-md font-medium hover:bg-green-700 disabled:bg-gray-400"
              >
                {isVerifying ? 'Verifying...' : 'Unlock'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Security Details (only visible after PIN unlock) */}
      {!showPinModal && (
        <>
          <h1 className="text-2xl font-semibold text-gray-800 mb-6">Security Center</h1>
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <div className="flex items-center mb-4">
              <Shield className="h-6 w-6 text-green-600 mr-2" />
              <h2 className="text-lg font-medium text-gray-800">Your Public Key</h2>
            </div>
            <p className="text-gray-600 mb-4">
              This is your public verification key. It is used to verify your transactions but cannot be used to access your funds.
            </p>
            <div className="bg-gray-50 p-3 rounded-md flex items-center justify-between mb-4">
              <code className="text-xs text-gray-700 font-mono break-all" aria-live="polite">
                {formattedKey(publicKeyPem) || 'Loading...'}
              </code>
              <div className="flex items-center">
                <button
                  onClick={copyPublicKey}
                  className="ml-2 p-1 rounded-md hover:bg-gray-200 focus:outline-none"
                  aria-label="Copy public key"
                >
                  {copied ? <Check className="h-5 w-5 text-green-600" /> : <Copy className="h-5 w-5 text-gray-600" />}
                </button>
                {publicKeyPem && (
                  <button
                    onClick={() => setShowFullKey((v) => !v)}
                    className="ml-2 text-xs text-green-700 underline"
                    aria-label={showFullKey ? "Hide full key" : "Show full key"}
                  >
                    {showFullKey ? "Hide" : "Show Full"}
                  </button>
                )}
              </div>
            </div>
            {keyCreatedAt && (
              <div className="flex items-center text-xs text-gray-500 mb-2">
                <Info className="h-4 w-4 mr-1" />
                Key created: {keyCreatedAt}
              </div>
            )}
            {deviceInfo && (
              <div className="flex items-center text-xs text-gray-500 mb-2">
                <Info className="h-4 w-4 mr-1" />
                Device: {deviceInfo}
              </div>
            )}
          </div>
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6 mb-4">
            <h3 className="text-lg font-medium text-yellow-800 mb-2">Security Notice</h3>
            <ul className="text-sm text-yellow-700 space-y-2">
              <li>Never share your PIN with anyone.</li>
              <li>Your private key is encrypted with your PIN and stored only on this device.</li>
              <li>If you get a new device, you'll need to set up a new key pair.</li>
              <li>Backup your recovery phrase if provided. Keep it safe and offline.</li>
              <li>Always log out on shared devices.</li>
            </ul>
          </div>
          {publicKeyPem === 'Public key unavailable' && (
            <div className="mt-4 text-center">
              <button
                onClick={() => navigate('/register')}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                Go to Registration
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
