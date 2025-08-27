import { useState } from 'react';
import AccountSummary from '../components/dashboard/AccountSummary';
import QuickActions from '../components/dashboard/QuickActions';
import RecentTransactions from '../components/dashboard/RecentTransactions';
import PinModal from '../components/common/PinModal';
import { secureRequest } from '../services/secureApi';

export default function Dashboard() {
  const [showPinModal, setShowPinModal] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState('');

  // Get user from localStorage with fallback

  
  const user = JSON.parse(localStorage.getItem('userProfile') || '{}');
  const transactions = JSON.parse(localStorage.getItem('userTransactions') || '[]');

  const handleRefreshClick = () => {
    setRefreshError('');
    setShowPinModal(true);
  };

  const handlePinSubmit = async (pin) => {
    setIsRefreshing(true);
    setRefreshError('');

    try {
      console.log('[Dashboard] Refreshing data with PIN validation...');
      
      // Call the secure API with dashboard target
      const response = await secureRequest({
        target: 'refresh',
        payload: { user: user },
        pin: pin
      });

      console.log('[Dashboard] Refresh response:', response);

      // Update localStorage with fresh data
      if (response.user) {
        localStorage.setItem('userProfile', JSON.stringify(response.user));
        console.log('[Dashboard] User profile updated in localStorage');
      }

      if (response.transactions) {
        localStorage.setItem('userTransactions', JSON.stringify(response.transactions));
        console.log('[Dashboard] Transactions updated in localStorage');
      }

      // Close modal and refresh the page to show updated data
      setShowPinModal(false);
      window.location.reload();

    } catch (error) {
      console.error('[Dashboard] Refresh failed:', error);
      
      // Handle different types of errors
      if (error.message && error.message.includes('Invalid PIN')) {
        setRefreshError('Invalid PIN. Please try again.');
      } else if (error.message && error.message.includes('No cryptographic keys')) {
        setRefreshError('Authentication required. Please login again.');
      } else if (error.payload_errors || error.field_errors) {
        setRefreshError('Invalid request. Please try again.');
      } else {
        setRefreshError(error.message || 'Failed to refresh data. Please try again.');
      }
    } finally {
      setIsRefreshing(false);
    }
  };

  const handlePinModalClose = () => {
    setShowPinModal(false);
    setRefreshError('');
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold text-gray-800">Dashboard</h1>
      <p className="text-gray-600 mb-6">
        🎉 Welcome to SecureCipher, {user.first_name ? user.first_name : 'User'}!

      </p>

      {/* Display refresh error if any */}
      {refreshError && (
        <div className="mb-4 p-4 bg-red-100 border border-red-300 text-red-700 rounded-md">
          <p className="text-sm">{refreshError}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="md:col-span-2">
          <AccountSummary />
        </div>
        <div>
          <QuickActions onRefreshClick={handleRefreshClick} />
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RecentTransactions />
        </div>

      </div>
  

      {/* PIN Modal for refresh */}
      <PinModal
        isOpen={showPinModal}
        onClose={handlePinModalClose}
        onSubmit={handlePinSubmit}
        isLoading={isRefreshing}
      />
    </div>
    
  );
}
