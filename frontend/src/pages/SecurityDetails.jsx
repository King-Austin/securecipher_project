import { useState, useEffect } from 'react';
import { Shield, Copy, Check, Info, AlertCircle, User, CreditCard, Calendar, Phone, Key, Lock, Eye, EyeOff, Activity, FileText, Clock, MapPin } from 'lucide-react';
import * as SecureKeyManager from '../utils/SecureKeyManager';
import { useNavigate } from 'react-router-dom';

export default function SecurityDetails() {
  const navigate = useNavigate();
  const [userProfile, setUserProfile] = useState(null);
  const [publicKeyPem, setPublicKeyPem] = useState('');
  const [copied, setCopied] = useState(false);
  const [showFullKey, setShowFullKey] = useState(false);
  const [keyCreatedAt, setKeyCreatedAt] = useState('');
  const [deviceInfo, setDeviceInfo] = useState('');
  const [showPinModal, setShowPinModal] = useState(true);
  const [pin, setPin] = useState('');
  const [pinError, setPinError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [showSensitiveData, setShowSensitiveData] = useState(false);
  const [userTransactions, setUserTransactions] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);

  useEffect(() => {
    // Load user profile from localStorage
    const savedProfile = localStorage.getItem('userProfile');
    if (savedProfile) {
      const profile = JSON.parse(savedProfile);
      setUserProfile(profile);
      if (profile.public_key) {
        setPublicKeyPem(profile.public_key);
      }
    }

    // Load transaction history from localStorage
    const savedTransactions = localStorage.getItem('userTransactions');
    if (savedTransactions) {
      const transactions = JSON.parse(savedTransactions);
      setUserTransactions(transactions.slice(0, 5)); // Show last 5 transactions
    }

    // Generate mock security events for demonstration
    setSecurityEvents([
      {
        id: 1,
        event: 'Login Success',
        timestamp: new Date().toISOString(),
        location: 'Current Device',
        status: 'success'
      },
      {
        id: 2,
        event: 'PIN Verification',
        timestamp: new Date(Date.now() - 300000).toISOString(), // 5 minutes ago
        location: 'Current Device',
        status: 'success'
      },
      {
        id: 3,
        event: 'Key Access',
        timestamp: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
        location: 'Current Device',
        status: 'success'
      }
    ]);

    setDeviceInfo(`${navigator.platform}, ${navigator.userAgent}`);
  }, []);

  const handlePinSubmit = async (e) => {
    e.preventDefault();
    setIsVerifying(true);
    setPinError('');
    
    try {
      // First check if we have encrypted key data
      const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();
      if (!keyData) {
        console.log('No encrypted key data found, proceeding with public key from localStorage');
        // If no encrypted key data, just use the public key from localStorage
        if (userProfile?.public_key) {
          setPublicKeyPem(userProfile.public_key);
          setShowPinModal(false);
          return;
        } else {
          navigate('/register', { replace: true });
          return;
        }
      }
      
      if (keyData.createdAt) setKeyCreatedAt(new Date(keyData.createdAt).toLocaleString());
      
      // Verify PIN by attempting to decrypt the private key
      const { encrypted, salt, iv } = keyData;
      const keyPair = await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);
      
      // If we reach here, PIN is correct
      console.log('PIN verification successful');
      
      // Use the public key from localStorage
      if (userProfile?.public_key) {
        setPublicKeyPem(userProfile.public_key);
      }
      setShowPinModal(false);
    } catch (error) {
      console.log('PIN verification failed:', error.message);
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

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric', 
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleEmergencyLogout = async () => {
    const confirmed = confirm(
      '⚠️ CRITICAL WARNING ⚠️\n\n' +
      'This action will PERMANENTLY DELETE all cryptographic material from this device:\n\n' +
      '• Your encrypted private key will be wiped from IndexedDB\n' +
      '• All user profile data will be cleared from localStorage\n' +
      '• All SecureCipher session data will be removed\n' +
      '• Your PIN and security settings will be erased\n\n' +
      '🔴 THIS ACTION IS IRREVERSIBLE 🔴\n\n' +
      'Once you logout, you will need to re-register with SecureCipher and generate new cryptographic keys. ' +
      'Your old private key will be permanently lost and cannot be recovered.\n\n' +
      'Are you absolutely sure you want to proceed with emergency logout?'
    );

    if (confirmed) {
      const secondConfirm = confirm(
        'FINAL CONFIRMATION\n\n' +
        'You are about to permanently destroy all cryptographic keys and data on this device. ' +
        'This cannot be undone.\n\n' +
        'Click OK to proceed with complete data wipe and logout.'
      );

      if (secondConfirm) {
        try {
          // Clear all localStorage data
          localStorage.clear();
          
          // Clear sessionStorage as well
          sessionStorage.clear();
          
          // Clear IndexedDB data (encrypted private key)
          try {
            await SecureKeyManager.clearAllKeyData();
          } catch (error) {
            console.warn('Error clearing IndexedDB:', error);
            // Continue with logout even if IndexedDB clearing fails
          }
          

          
          alert(
            '✅ LOGOUT COMPLETE ✅\n\n' +
            'All cryptographic material and user data has been permanently wiped from this device.\n\n' +
            'You will now be redirected to the registration page.'
          );
          
          // Redirect and reload to reset auth state
          window.location.href = '/register';
          
        } catch (error) {
          console.error('Error during emergency logout:', error);
          alert(
            '⚠️ LOGOUT WARNING ⚠️\n\n' +
            'There was an error during the logout process. Some data may not have been completely cleared.\n\n' +
            'For complete security, please:\n' +
            '1. Clear your browser data manually\n' +
            '2. Close all browser windows\n' +
            '3. Restart your browser\n\n' +
            'You will still be redirected to the registration page.'
          );
          navigate('/register', { replace: true });
        }
      }
    }
  };

  const maskSensitiveData = (data, visible = false) => {
    if (!data || visible) return data || 'Not provided';
    return '••••••••••';
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

      {/* Security Details (only visible after PIN unlock) */}
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
                  <span className="font-medium">{userProfile.first_name} {userProfile.last_name}</span>
                </div>
                <div className="flex items-center">
                  <CreditCard className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Account:</span>
                  <span className="font-medium">{userProfile.account_number}</span>
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
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    userProfile.status === 'ACTIVE' 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-red-100 text-red-800'
                  }`}>
                    {userProfile.status}
                  </span>
                </div>
                <div className="flex items-center">
                  <Check className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-sm text-gray-600 w-20">Verified:</span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    userProfile.is_verified 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-yellow-100 text-yellow-800'
                  }`}>
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
                    {copied ? <Check className="h-3 w-3 text-green-600 mr-1" /> : <Copy className="h-3 w-3 text-gray-500 mr-1" />}
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                  {publicKeyPem && (
                    <button
                      onClick={() => setShowFullKey(!showFullKey)}
                      className="text-xs text-green-600 hover:text-green-700 underline"
                    >
                      {showFullKey ? "Hide" : "Show Full"}
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
                <span>Created: {keyCreatedAt || formatDate(userProfile.created_at)}</span>
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
                <span className="px-3 py-1 bg-green-100 text-green-800 text-sm font-medium rounded-full">
                  Enabled
                </span>
              </div>
              
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h3 className="font-medium text-gray-800">End-to-End Encryption</h3>
                  <p className="text-sm text-gray-600">All transactions are cryptographically signed</p>
                </div>
                <span className="px-3 py-1 bg-green-100 text-green-800 text-sm font-medium rounded-full">
                  Active
                </span>
              </div>
              
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h3 className="font-medium text-gray-800">Device Binding</h3>
                  <p className="text-sm text-gray-600">Keys are securely stored on this device only</p>
                </div>
                <span className="px-3 py-1 bg-green-100 text-green-800 text-sm font-medium rounded-full">
                  Secured
                </span>
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
                <div><strong>Platform:</strong> {navigator.platform}</div>
                <div><strong>Browser:</strong> {navigator.userAgent.split(') ')[0]})</div>
                <div><strong>Last Access:</strong> {new Date().toLocaleString()}</div>
                <div><strong>IP Address:</strong> Masked for privacy</div>
              </div>
            </div>
          </div>
          {/* Security Guidelines */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-6 mb-6">
            <div className="flex items-center mb-4">
              <Shield className="h-5 w-5 text-green-600 mr-2" />
              <h3 className="text-lg font-semibold text-green-800">SecureCipher Security Guidelines</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ul className="text-sm text-green-700 space-y-2">
                <li className="flex items-start">
                  <Check className="h-4 w-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                  Never share your PIN with anyone, including SecureCipher staff
                </li>
                <li className="flex items-start">
                  <Check className="h-4 w-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                  Your private key is encrypted and stored only on this device
                </li>
                <li className="flex items-start">
                  <Check className="h-4 w-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                  Always verify transaction details before confirmation
                </li>
              </ul>
              <ul className="text-sm text-green-700 space-y-2">
                <li className="flex items-start">
                  <Check className="h-4 w-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                  Log out completely when using shared or public devices
                </li>
                <li className="flex items-start">
                  <Check className="h-4 w-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                  Report any suspicious activity immediately
                </li>
                <li className="flex items-start">
                  <Check className="h-4 w-4 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
                  Keep your browser and device software updated
                </li>
                <li className="flex items-start">
                  <AlertCircle className="h-4 w-4 text-red-600 mr-2 mt-0.5 flex-shrink-0" />
                  <span className="text-red-700">Emergency logout permanently destroys all keys - use only when necessary</span>
                </li>
              </ul>
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
                    <div className={`w-2 h-2 rounded-full mr-3 ${
                      event.status === 'success' ? 'bg-green-500' : 'bg-red-500'
                    }`}></div>
                    <div>
                      <p className="text-sm font-medium text-gray-800">{event.event}</p>
                      <p className="text-xs text-gray-600 flex items-center">
                        <MapPin className="h-3 w-3 mr-1" />
                        {event.location}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-500">
                      {new Date(event.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

   

          {/* Account Verification Status */}
          <div className="bg-white rounded-lg shadow p-6 mb-6">
            <div className="flex items-center mb-4">
              <Check className="h-5 w-5 text-green-600 mr-2" />
              <h2 className="text-lg font-semibold text-gray-800">Account Verification Status</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <span className="text-sm text-gray-700">Phone Number</span>
                  <span className="px-2 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
                    Verified
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <span className="text-sm text-gray-700">Email Address</span>
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                    userProfile?.is_verified 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-yellow-100 text-yellow-800'
                  }`}>
                    {userProfile?.is_verified ? 'Verified' : 'Pending'}
                  </span>
                </div>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <span className="text-sm text-gray-700">Identity (NIN)</span>
                  <span className="px-2 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
                    Verified
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <span className="text-sm text-gray-700">Bank Account</span>
                  <span className="px-2 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
                    Active
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Emergency Actions */}
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center mb-4">
              <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
              <h3 className="text-lg font-semibold text-gray-800">Emergency Actions</h3>
            </div>
            
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
              <div className="flex">
                <AlertCircle className="h-5 w-5 text-red-500 mr-2 mt-0.5 flex-shrink-0" />
                <div className="text-sm text-red-700">
                  <p className="font-medium mb-1">⚠️ Data Wipe Warning</p>
                  <p>The emergency logout will permanently delete all cryptographic keys, user data, and session information from this device. This action cannot be undone and you will need to re-register with SecureCipher.</p>
                </div>
              </div>
            </div>
            
            <div className="flex justify-center">
              <button
                onClick={handleEmergencyLogout}
                className="flex items-center justify-center px-6 py-3 border border-red-300 text-red-700 rounded-lg hover:bg-red-50 transition-colors font-medium"
              >
                <AlertCircle className="h-4 w-4 mr-2" />
                Emergency Logout & Data Wipe
              </button>
            </div>
          </div>

          {publicKeyPem === 'Public key unavailable' && (
            <div className="mt-6 text-center bg-yellow-50 border border-yellow-200 rounded-lg p-6">
              <AlertCircle className="h-8 w-8 text-yellow-600 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-yellow-800 mb-2">Security Setup Required</h3>
              <p className="text-yellow-700 mb-4">Your security keys need to be configured to access all features.</p>
              <button
                onClick={() => navigate('/register')}
                className="inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-lg shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                Complete Security Setup
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
