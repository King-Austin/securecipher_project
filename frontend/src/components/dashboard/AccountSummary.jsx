import { Wallet, TrendingUp, EyeOff, Eye } from 'lucide-react';
import { useState, useEffect } from 'react';

export default function AccountSummary() {
  const [isBalanceHidden, setIsBalanceHidden] = useState(false);
  const [user, setUser] = useState({});

  // Load user data from localStorage
  useEffect(() => {
    const userData = localStorage.getItem('userProfile');
    if (userData) {
      const parsedUser = JSON.parse(userData);
      setUser(parsedUser);
      console.log('AccountSummary: Loaded user data:', parsedUser);
    }
  }, []);

  // Format number to Nigerian Naira
  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-NG', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(amount || 0);
  };

  const toggleBalanceVisibility = () => {
    setIsBalanceHidden(!isBalanceHidden);
  };

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className="bg-green-700 p-6">
        <div className="flex justify-between items-center mb-4">
          <div className="flex items-center">
            <Wallet className="h-6 w-6 text-white mr-2" />
            <h2 className="text-lg font-medium text-white">Account Balance</h2>
          </div>
          <button 
            onClick={toggleBalanceVisibility}
            className="text-white focus:outline-none"
            aria-label={isBalanceHidden ? "Show balance" : "Hide balance"}
          >
            {isBalanceHidden ? <Eye className="h-5 w-5" /> : <EyeOff className="h-5 w-5" />}
          </button>
        </div>
        
        <div className="mb-2">
          <div className="flex items-center">
            <p className="text-sm text-green-100">Available Balance</p>
          </div>
          <div className="flex items-baseline">
            <span className="text-2xl font-bold text-white mr-1">₦</span>
            <h3 className="text-3xl font-bold text-white">
              {isBalanceHidden ? '•••••••' : formatCurrency(user.balance)}
            </h3>
          </div>
        </div>
        
        <div className="flex items-center text-green-100">
          <TrendingUp className="h-4 w-4 mr-1" />
          <span className="text-xs">
            Account Status: {user.status === 'ACTIVE' ? 'Active & Verified' : user.status || 'Unknown'}
          </span>
        </div>
      </div>
      
      <div className="grid grid-cols-2 divide-x divide-gray-200 border-t border-gray-200">
        <div className="p-4">
          <p className="text-xs text-gray-500">Account Number</p>
          <p className="text-sm font-medium text-gray-800">{user.account_number || '...'}</p>
        </div>
        <div className="p-4">
          <p className="text-xs text-gray-500">Account Type</p>
          <p className="text-sm font-medium text-gray-800">{user.account_type || 'Savings'}</p>
        </div>
      </div>
      
      {/* Additional account info */}
      <div className="grid grid-cols-2 divide-x divide-gray-200 border-t border-gray-200">
        <div className="p-4">
          <p className="text-xs text-gray-500">Account Holder</p>
          <p className="text-sm font-medium text-gray-800">
            {user.first_name && user.last_name ? `${user.first_name} ${user.last_name}` : '...'}
          </p>
        </div>
        <div className="p-4">
          <p className="text-xs text-gray-500">Member Since</p>
          <p className="text-sm font-medium text-gray-800">
            {user.created_at ? new Date(user.created_at).toLocaleDateString('en-US', { 
              year: 'numeric', 
              month: 'short' 
            }) : '...'}
          </p>
        </div>
      </div>
    </div>
  );
}
