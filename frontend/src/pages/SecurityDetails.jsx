import { useState, useEffect } from 'react';
import {
  Shield, Copy, Check, Info, AlertCircle, User, CreditCard, Calendar,
  Phone, Key, Lock, Eye, EyeOff, Activity, MapPin
} from 'lucide-react';
import * as SecureKeyManager from '../utils/SecureKeyManager';
import { useNavigate } from 'react-router-dom';

export default function SecurityDetails() {
  const navigate = useNavigate();

  const [userProfile, setUserProfile] = useState(null);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [publicKeyPem, setPublicKeyPem] = useState('');
  const [copied, setCopied] = useState(false);
  const [showFullKey, setShowFullKey] = useState(false);
  const [keyCreatedAt, setKeyCreatedAt] = useState('');
  const [showPinModal, setShowPinModal] = useState(true);
  const [pin, setPin] = useState('');
  const [pinError, setPinError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [showSensitiveData, setShowSensitiveData] = useState(false);
  const [userTransactions, setUserTransactions] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);

  useEffect(() => {
    // Load user profile from localStorage
    try {
      const savedProfile = localStorage.getItem('userProfile');
      if (savedProfile) {
        const profile = JSON.parse(savedProfile);
        setUserProfile(profile || null);
        if (profile?.public_key) setPublicKeyPem(profile.public_key);
      }
    } catch {
      // ignore parsing errors
    }

    // Load transaction history from localStorage (last 5)
    try {
      const savedTx = localStorage.getItem('userTransactions');
      if (savedTx) {
        const tx = JSON.parse(savedTx);
        if (Array.isArray(tx)) setUserTransactions(tx.slice(0, 5));
      }
    } catch {
      // ignore
    }

    // Demo security events
    const now = Date.now();
    setSecurityEvents([
      {
        id: 1,
        event: 'Login Success',
        timestamp: new Date(now).toISOString(),
        location: 'Current Device',
        status: 'success',
      },
      {
        id: 2,
        event: 'PIN Verification',
        timestamp: new Date(now - 5 * 60 * 1000).toISOString(),
        location: 'Current Device',
        status: 'success',
      },
      {
        id: 3,
        event: 'Key Access',
        timestamp: new Date(now - 60 * 60 * 1000).toISOString(),
        location: 'Current Device',
        status: 'success',
      },
    ]);

    // Optional: if you want to skip PIN modal when no encrypted key is stored,
    // but a public key exists locally, uncomment below:
    /*
    (async () => {
      try {
        const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();
        if (!keyData && localStorage.getItem('userProfile')) {
          setShowPinModal(false);
        }
      } catch {}
    })();
    */
  }, []);

  const handlePinSubmit = async (e) => {
    e.preventDefault();
    setIsVerifying(true);
    setPinError('');

    try {
      // Check if encrypted key data exists (device-bound private key)
      const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();

      if (!keyData) {
        // No encrypted private key stored: allow access with public key if present
        if (userProfile?.public_key) {
          setPublicKeyPem(userProfile.public_key);
          setShowPinModal(false);
          return;
        }
        // No profile at all → send to register
        navigate('/register', { replace: true });
        return;
      }

      // Keep createdAt as ISO for consistent formatting
      if (keyData.createdAt) setKeyCreatedAt(keyData.createdAt);

      // Attempt to decrypt with PIN (this is your verification)
      const { encrypted, salt, iv } = keyData;
      await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);

      // If decryption succeeds, PIN is correct
      if (userProfile?.public_key) setPublicKeyPem(userProfile.public_key);
      setShowPinModal(false);
    } catch (error) {
      console.log('PIN verification failed:', error?.message || error);
      setPinError('Invalid PIN. Please try again.');
    } finally {
      setIsVerifying(false);
    }
  };
// ... existing code ...

function getBrowserName() {
    const ua = navigator.userAgent;
    if (ua.includes('Chrome') && !ua.includes('Edg')) return 'Chrome';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Safari') && !ua.includes('Chrome')) return 'Safari';
    if (ua.includes('Edg')) return 'Edge';
    if (ua.includes('MSIE') || ua.includes('Trident')) return 'Internet Explorer';
    return 'Unknown Browser';
}

async function getUserIP() {
    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        return data.ip || 'Unable to retrieve';
    } catch (error) {
        return 'Unable to retrieve';
    }
}

// ... existing code ...
  const formattedKey = (pem) => {
    if (!pem) return '';
    const clean = pem.replace(/-----.*-----|\n/g, '');
    return showFullKey ? clean : `${clean.slice(0, 20)}...${clean.slice(-20)}`;
  };

  const copyPublicKey = async () => {
    try {
      await navigator.clipboard.writeText(publicKeyPem || '');
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = publicKeyPem || '';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } finally {
        document.body.removeChild(textarea);
      }
    }
  };

  const formatDate = (dateLike) => {
    if (!dateLike) return '—';
    const d = typeof dateLike === 'string' ? new Date(dateLike) : dateLike;
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const maskSensitiveData = (data, visible = false) => {
    if (!data) return 'Not provided';
    return visible ? data : '••••••••••';
    // If you’d rather show last 2 digits:
    // return visible ? data : `${'•'.repeat(Math.max(0, String(data).length - 2))}${String(data).slice(-2)}`
  };

  if (!userProfile) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-500">Loading security details...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* PIN Modal */}
      {showPinModal && (
        <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg p-8 max-w-sm w-full mx-4">
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Shield className="h-8 w-8 text-green-600" />
              </div>
              <h2 className="text-xl font-bold text-gray-800">SecureCipher</h2>
              <p className="text-sm text-gray-600 mt-1">Enter your security PIN to access</p>
            </div>
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
                className="block w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-center text-lg font-mono"
                placeholder="••••••"
                disabled={isVerifying}
              />
              {pinError && (
                <div className="flex items-center justify-center text-sm text-red-600">
                  <AlertCircle className="h-4 w-4 mr-1" />
                  {pinError}
                </div>
              )}
              <button
                type="submit"
                disabled={isVerifying || pin.length !== 6}
                className="w-full py-3 px-4 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 disabled:bg-gray-400 transition-colors"
              >
                {isVerifying ? 'Verifying...' : 'Unlock Security Center'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Security Details */}
      {!showPinModal && (
        <>
          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center mb-2">
              <Shield className="h-8 w-8 text-green-600 mr-3" />
              <h1 className="text-3xl font-bold text-gray-800">Security Center</h1>
            </div>
            <p className="text-gray-600">Manage your account security and encryption keys</p>
          </div>

          {/* Account Overview */}
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-800 flex items-center">
                <User className="h-5 w-5 text-green-600 mr-2" />
                Account Information
              </h2>
              <button
                onClick={() => setShowSensitiveData(!showSensitiveData)}
                className="flex items-center text-sm text-green-600 hover:text-green-700"
              >
                {showSensitiveData ? <EyeOff className="h-4 w-4 mr-1" /> : <Eye className="h-4 w-4 mr-1" />}
                {showSensitiveData ? 'Hide' : 'Show'} Details
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="flex items-center">
                  <User className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Name:</span>
                  <span className="font-medium">
                    {(userProfile.first_name || '')} {(userProfile.last_name || '')}
                  </span>
                </div>
                <div className="flex items-center">
                  <CreditCard className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Account:</span>
                  <span className="font-medium">{userProfile.account_number || '—'}</span>
                </div>
                <div className="flex items-center">
                  <Phone className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Phone:</span>
                  <span className="font-medium">{maskSensitiveData(userProfile.phone_number, showSensitiveData)}</span>
                </div>
              </div>
              <div className="space-y-3">
                <div className="flex items-center">
                  <Calendar className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Joined:</span>
                  <span className="font-medium">{formatDate(userProfile.created_at)}</span>
                </div>
                <div className="flex items-center">
                  <Shield className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Status:</span>
                  <span
                    className={`px-2 py-1 rounded-full text-xs font-medium ${
                      userProfile.status === 'ACTIVE'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    {userProfile.status || 'UNKNOWN'}
                  </span>
                </div>
                <div className="flex items-center">
                  <Check className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Verified:</span>
                  <span
                    className={`px-2 py-1 rounded-full text-xs font-medium ${
                      userProfile.is_verified ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                    }`}
                  >
                    {userProfile.is_verified ? 'Verified' : 'Pending'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Cryptographic Keys */}
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <div className="flex items-center mb-4">
              <Key className="h-5 w-5 text-green-600 mr-2" />
              <h2 className="text-lg font-semibold text-gray-800">Cryptographic Keys</h2>
            </div>
            <p className="text-gray-600 mb-4">
              Your public key is used to verify transactions and ensure secure communication with SecureCipher servers.
            </p>

            <div className="bg-gray-50 border rounded-lg p-4 mb-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-700">Public Key</span>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={copyPublicKey}
                    className="flex items-center px-2 py-1 text-xs bg-white border border-gray-300 rounded hover:bg-gray-50 transition-colors"
                    aria-label="Copy public key"
                  >
                    {copied ? (
                      <Check className="h-3 w-3 text-green-600 mr-1" />
                    ) : (
                      <Copy className="h-3 w-3 text-gray-500 mr-1" />
                    )}
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                  {publicKeyPem && (
                    <button
                      onClick={() => setShowFullKey(!showFullKey)}
                      className="text-xs text-green-600 hover:text-green-700 underline"
                    >
                      {showFullKey ? 'Hide' : 'Show Full'}
                    </button>
                  )}
                </div>
              </div>
              <code className="text-xs text-gray-700 font-mono break-all block bg-white p-2 rounded border">
                {formattedKey(publicKeyPem) || 'Loading...'}
              </code>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div className="flex items-center text-gray-600">
                <Info className="h-4 w-4 mr-2" />
                <span>Key Type: ECDSA P-384</span>
              </div>
              <div className="flex items-center text-gray-600">
                <Calendar className="h-4 w-4 mr-2" />
                <span>
                  Created: {keyCreatedAt ? formatDate(keyCreatedAt) : formatDate(userProfile.created_at)}
                </span>
              </div>
              <div className="flex items-center text-gray-600">
                <Shield className="h-4 w-4 mr-2" />
                <span>Status: Active & Verified</span>
              </div>
              <div className="flex items-center text-gray-600">
                <Lock className="h-4 w-4 mr-2" />
                <span>Private Key: Encrypted Locally</span>
              </div>
            </div>
          </div>

          {/* Security Settings */}
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <div className="flex items-center mb-4">
              <Lock className="h-5 w-5 text-green-600 mr-2" />
              <h2 className="text-lg font-semibold text-gray-800">Security Settings</h2>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h3 className="font-medium text-gray-800">Two-Factor Authentication</h3>
                  <p className="text-sm text-gray-600">PIN-based authentication for sensitive operations</p>
                </div>
                <span className="px-3 py-1 bg-green-100 text-green-800 text-sm font-medium rounded-full">Enabled</span>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h3 className="font-medium text-gray-800">End-to-End Encryption</h3>
                  <p className="text-sm text-gray-600">All transactions are cryptographically signed</p>
                </div>
                <span className="px-3 py-1 bg-green-100 text-green-800 text-sm font-medium rounded-full">Active</span>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h3 className="font-medium text-gray-800">Device Binding</h3>
                  <p className="text-sm text-gray-600">Keys are securely stored on this device only</p>
                </div>
                <span className="px-3 py-1 bg-green-100 text-green-800 text-sm font-medium rounded-full">Secured</span>
              </div>
            </div>
          </div>

          {/* Device Information */}
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <div className="flex items-center mb-4">
              <Info className="h-5 w-5 text-green-600 mr-2" />
              <h2 className="text-lg font-semibold text-gray-800">Device Information</h2>
            </div>

            <div className="bg-gray-50 p-4 rounded-lg">
              <div className="text-sm text-gray-600 space-y-2">
                <div><strong>Platform:</strong> {navigator.platform || '—'}</div>
                <div><strong>Browser:</strong> {getBrowserName()}</div>
                <div><strong>User Agent:</strong> {navigator.userAgent || '—'}</div>
                <div><strong>Last Access:</strong> {new Date().toLocaleString()}</div>
              </div>
            </div>
          </div>



          {/* Recent Security Activity */}
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <div className="flex items-center mb-4">
              <Activity className="h-5 w-5 text-green-600 mr-2" />
              <h2 className="text-lg font-semibold text-gray-800">Recent Security Activity</h2>
            </div>

            <div className="space-y-3">
              {securityEvents.map((event) => (
                <div key={event.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    <div
                      className={`w-2 h-2 rounded-full mr-3 ${
                        event.status === 'success' ? 'bg-green-500' : 'bg-red-500'
                      }`}
                    />
                    <div>
                      <p className="text-sm font-medium text-gray-800">{event.event}</p>
                      <p className="text-xs text-gray-600 flex items-center">
                        <MapPin className="h-3 w-3 mr-1" />
                        {event.location}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-600">{formatDate(event.timestamp)}</p>
                    <span
                      className={`text-xs font-medium ${
                        event.status === 'success' ? 'text-green-700' : 'text-red-700'
                      }`}
                    >
                      {event.status}
                    </span>
                  </div>
                </div>
              ))}
              {securityEvents.length === 0 && (
                <p className="text-sm text-gray-500">No recent security events.</p>
              )}
            </div>
          </div>


        </>
      )}
    </div>
  );

}
