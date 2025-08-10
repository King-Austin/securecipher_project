import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { CreditCard, Eye, EyeOff, Copy, Check, Wallet, TrendingUp, Shield, Zap } from 'lucide-react';

export default function Cards() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState(null);
  const [showDetails, setShowDetails] = useState({});
  const [copied, setCopied] = useState('');

  useEffect(() => {
    const stored = localStorage.getItem('userProfile');
    if (stored) {
      setProfile(JSON.parse(stored));
    } else {
      navigate('/register', { replace: true });
    }
  }, [navigate]);

  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(''), 2000);
  };

  const toggleDetails = (cardId) => {
    setShowDetails(prev => ({ ...prev, [cardId]: !prev[cardId] }));
  };

  if (!profile) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <CreditCard className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-500">Loading your cards...</p>
        </div>
      </div>
    );
  }

  // Generate mock cards based on user data
  const accountNum = profile.account_number || '';
  const lastName = profile.last_name || 'USER';
  
  const generateCardNumber = (suffix) => {
    const base = '4532' + accountNum.slice(-6) + suffix;
    return base.padEnd(16, '0').slice(0, 16);
  };

  const formatCardNumber = (number) => {
    return number.replace(/(.{4})/g, '$1 ').trim();
  };

  const cards = [
    {
      id: 1,
      type: 'SecureCipher Premium',
      brand: 'MASTERCARD',
      number: generateCardNumber('02'),
      name: `${profile.first_name} ${lastName}`.toUpperCase(),
      expiry: '09/29',
      cvv: '316',
      balance: `₦${parseFloat(profile.balance || 0).toLocaleString()}`,
      limit: '₦5,000,000',
      gradient: 'bg-gradient-to-br from-emerald-500 via-teal-600 to-green-700',
      icon: <Shield className="h-6 w-6" />,
      status: 'Premium'
    }
  ];

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center mb-2">
          <CreditCard className="h-8 w-8 text-green-600 mr-3" />
          <h1 className="text-3xl font-bold text-gray-800">My Cards</h1>
        </div>
        <p className="text-gray-600">Manage your SecureCipher cards and view balances</p>
      </div>

      {/* Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-1 xl:grid-cols-1 gap-6 mb-8 max-w-lg mx-auto">
        {cards.map((card) => (
          <div key={card.id} className="group">
            {/* Card */}
            <div className={`${card.gradient} text-white rounded-2xl p-6 shadow-2xl transform transition-all duration-300 hover:scale-105 hover:shadow-3xl relative overflow-hidden`}>
              {/* Background Pattern */}
              <div className="absolute inset-0 opacity-10">
                <div className="absolute top-4 right-4 w-32 h-32 rounded-full bg-white"></div>
                <div className="absolute bottom-4 left-4 w-24 h-24 rounded-full bg-white"></div>
              </div>
              
              {/* Card Header */}
              <div className="relative z-10">
                <div className="flex justify-between items-start mb-6">
                  <div className="flex items-center space-x-2">
                    {card.icon}
                    <span className="text-sm font-medium opacity-90">{card.type}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-lg font-bold">{card.brand}</span>
                    <div className={`text-xs px-2 py-1 rounded-full mt-1 ${
                      card.status === 'Premium' ? 'bg-yellow-400 text-yellow-900' :
                      card.status === 'Digital' ? 'bg-blue-400 text-blue-900' :
                      'bg-green-400 text-green-900'
                    }`}>
                      {card.status}
                    </div>
                  </div>
                </div>

                {/* Card Number */}
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm opacity-75">Card Number</span>
                    <button
                      onClick={() => toggleDetails(card.id)}
                      className="text-white hover:text-gray-200 transition-colors"
                    >
                      {showDetails[card.id] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <div className="font-mono text-xl tracking-wider">
                    {showDetails[card.id] ? formatCardNumber(card.number) : '•••• •••• •••• ' + card.number.slice(-4)}
                  </div>
                </div>

                {/* Card Details */}
                <div className="flex justify-between items-end">
                  <div>
                    <p className="text-sm opacity-75 uppercase">Cardholder</p>
                    <p className="font-medium text-sm">{card.name}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm opacity-75 uppercase">Expires</p>
                    <p className="font-medium">{card.expiry}</p>
                  </div>
                  {showDetails[card.id] && (
                    <div className="text-right">
                      <p className="text-sm opacity-75 uppercase">CVV</p>
                      <div className="flex items-center space-x-2">
                        <p className="font-medium">{card.cvv}</p>
                        <button
                          onClick={() => copyToClipboard(card.cvv, `cvv-${card.id}`)}
                          className="text-white hover:text-gray-200 transition-colors"
                        >
                          {copied === `cvv-${card.id}` ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Card Info Panel */}
            <div className="bg-white rounded-lg shadow-lg p-4 mt-4 border border-gray-100">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-600">Available Balance</p>
                  <p className="text-lg font-bold text-green-600">{card.balance}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Credit Limit</p>
                  <p className="text-lg font-bold text-gray-800">{card.limit}</p>
                </div>
              </div>
              
              <div className="mt-4 space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Usage</span>
                  <span className="text-sm font-medium">42%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div className="bg-green-500 h-2 rounded-full" style={{ width: '42%' }}></div>
                </div>
              </div>

              <div className="flex space-x-2 mt-4">
                <button
                  onClick={() => copyToClipboard(card.number, `card-${card.id}`)}
                  className="flex-1 bg-green-600 text-white py-2 px-3 rounded-lg text-sm font-medium hover:bg-green-700 transition-colors flex items-center justify-center space-x-1"
                >
                  {copied === `card-${card.id}` ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  <span>{copied === `card-${card.id}` ? 'Copied!' : 'Copy Number'}</span>
                </button>

              </div>
            </div>
          </div>
        ))}
      </div>


    </div>
  );
}
