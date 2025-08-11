import { useState, useEffect } from 'react';
import { AlertCircle, Check, Loader } from 'lucide-react';
import { secureRequest } from '../services/secureApi';
import * as SecureKeyManager from '../utils/SecureKeyManager';

export default function SendMoney() {
  const [step, setStep] = useState(1);
  const [transactionData, setTransactionData] = useState({
    to_account: '',
    amount: '',
    description: ''
  });
  const [storedPin, setStoredPin] = useState(''); // Store PIN from step 1
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [transactionResult, setTransactionResult] = useState(null);
  const [recipientInfo, setRecipientInfo] = useState(null);
  const [user, setUser] = useState({});
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Load user data from localStorage (set by Registration/Login)
  useEffect(() => {
    const userData = localStorage.getItem('userProfile');
    if (userData) {
      const parsedUser = JSON.parse(userData);
      setUser(parsedUser);
      setIsAuthenticated(true);
      console.log('SendMoney: Loaded user data:', parsedUser);
    }
  }, []);

  // Validate amount and PIN, then validate account
  const handleNextStep = async () => {
    const available = parseFloat(user.balance) || 0;
    const amount = parseFloat(transactionData.amount);
    const toAccount = transactionData.to_account;

    // Validation checks
    if (!toAccount || !transactionData.amount || !storedPin) {
      setError('Please fill in all required fields including PIN.');
      return;
    }
    if (storedPin.length !== 6) {
      setError('Please enter your 6-digit PIN.');
      return;
    }
    if (isNaN(amount) || amount <= 0) {
      setError('Amount must be greater than zero.');
      return;
    }
    if (!/^\d{10}$/.test(toAccount)) {
      setError('Invalid account number. Please enter a 10-digit account number.');
      return;
    }
    if (user && toAccount === user.account_number) {
      setError('You cannot send money to your own account.');
      return;
    }
    if (isNaN(available) || available <= 0) {
      setError('Insufficient account balance. Please check your account.');
      return;
    }
    if (amount > available) {
      setError(`Insufficient funds. Your available balance is ₦${available.toLocaleString()}.`);
      return;
    }

    try {
      setLoading(true);
      
      // Validate recipient account using secure request with PIN
      console.log('Validating recipient account...');
      const payload = { 
        account_number: transactionData.to_account,
      };
      const response = await secureRequest({
        target: 'validate_account',
        payload,
        pin: storedPin
      });
      
      // Check if response has an error (including 404 responses)
      if (response && response.error) {
        if (response.error === 'Account not found.' || response.error.includes('not found')) {
          setError('Account not found. Please check the account number and try again.');
        } else {
          setError(response.error);
        }
        return;
      }
      
      // Check for user field in successful response
      if (response && response.user) {
        setRecipientInfo(response.user);
        setError('');
        setStep(2);
        console.log('Account validation successful:', response.user);
      } else {
        setError('Unable to validate account. Please check the account number and try again.');
      }
    } catch (err) {
      console.error('Account validation error:', err);
      console.log('Error object structure:', err);
      let errorMessage = 'An error occurred while validating the account. Please try again.';
      
      // Handle different error types seamlessly
      if (err.status === 404 || err.error === 'Account not found.' || (err.error && err.error.includes('not found'))) {
        errorMessage = 'Account not found. Please check the account number and try again.';
      } else if (err.error) {
        errorMessage = err.error;
      } else if (err.message && err.message.includes('Invalid PIN')) {
        errorMessage = 'Invalid PIN. Please enter the correct PIN.';
      } else if (err.message && err.message.includes('404')) {
        errorMessage = 'Account not found. Please check the account number and try again.';
      } else if (err.message) {
        errorMessage = err.message;
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handlePrevStep = () => {
    if (step > 1) {
      setStep(step - 1);
      setError('');
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setTransactionData(prev => ({ ...prev, [name]: value }));
    setError('');
  };

  const handlePinChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 6) {
      setStoredPin(value);
      setError('');
    }
  };

  // Use stored PIN for final transaction
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (storedPin.length !== 6) {
      setError('Invalid PIN. Please go back and re-enter your PIN.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      if (!user || !user.account_number) {
        throw new Error('No account found. Please login again.');
      }

      // Final validation before sending
      const amount = parseFloat(transactionData.amount);
      const available = parseFloat(user.balance) || 0;
      
      if (isNaN(amount) || amount <= 0) {
        setError('Amount must be greater than zero.');
        setLoading(false);
        return;
      }
      if (amount > available) {
        setError(`Insufficient funds. Available balance: ₦${available.toLocaleString()}`);
        setLoading(false);
        return;
      }

      const payload = {
        source_account_number: user.account_number,
        destination_account_number: transactionData.to_account,
        amount: transactionData.amount,
        description: transactionData.description || 'Fund Transfer',
      };

      console.log('Transfer payload:', payload);

      // Use secureRequest with stored PIN
      const response = await secureRequest({
        target: 'transfer',
        payload,
        pin: storedPin
      });

      console.log('Transfer response:', response);

      if (response && response.success) {
        setTransactionResult(response);
        setSuccess(true);

        // Clear sensitive data after successful transaction
        setStoredPin('');

        // Update user data in localStorage if provided by server
        if (response.user) {
          localStorage.setItem('userProfile', JSON.stringify(response.user));
          setUser(response.user);
        }
        if (response.transactions) {
          localStorage.setItem('userTransactions', JSON.stringify(response.transactions));
        }
      } else {
        // Handle response errors
        if (response && response.error) {
          throw new Error(response.error);
        } else {
          throw new Error('Transaction failed. Please try again.');
        }
      }
    } catch (err) {
      console.error('Transfer Error:', err);
      console.log('Transfer error object structure:', err);
      
      let errorMessage = 'An unexpected error occurred. Please try again.';
      
      // Handle different error types seamlessly
      if (err.status === 404 || err.error === 'Account not found.' || (err.error && err.error.includes('not found'))) {
        errorMessage = 'Recipient account not found. Please check the account number.';
      } else if (err.error) {
        errorMessage = err.error;
      } else if (err.message && err.message.includes('Insufficient funds')) {
        errorMessage = err.message;
      } else if (err.message && err.message.includes('404')) {
        errorMessage = 'Recipient account not found. Please check the account number.';
      } else if (err.message && (err.message.includes('PIN') || err.message.includes('key'))) {
        errorMessage = 'Invalid PIN or authentication failed. Please try again.';
      } else if (err.message) {
        errorMessage = err.message;
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setStep(1);
    setTransactionData({ to_account: '', amount: '', description: '' });
    setStoredPin('');
    setError('');
    setSuccess(false);
    setTransactionResult(null);
    setRecipientInfo(null);
  };

  if (!isAuthenticated) {
    return (
      <div className="flex justify-center items-center h-64">
        <AlertCircle className="h-8 w-8 text-red-600" />
        <p className="ml-4 text-gray-600">You must be logged in to send money.</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader className="animate-spin h-8 w-8 text-indigo-600" />
        <p className="ml-4 text-gray-600">Processing transaction...</p>
      </div>
    );
  }

  if (success) {
    return (
      <div className="max-w-lg mx-auto p-8 bg-white shadow-lg rounded-lg text-center">
        <Check className="mx-auto h-16 w-16 text-green-500 bg-green-100 rounded-full p-2" />
        <h2 className="mt-4 text-2xl font-bold text-gray-800">Transfer Successful!</h2>
        <p className="mt-2 text-gray-600">
          You have successfully sent <strong>₦{parseFloat(transactionData.amount).toLocaleString()}</strong> to <strong>{recipientInfo?.first_name} {recipientInfo?.last_name}</strong> (Account: {transactionData.to_account}).
        </p>
        {transactionResult && (
          <div className="mt-6 space-y-4">
            <div className="text-left bg-gray-50 p-4 rounded-md">
              <p className="text-sm text-gray-500">Transaction Details:</p>
              <div className="mt-2 space-y-1 text-xs">
                <p><span className="text-gray-600">Amount:</span> <span className="font-semibold">₦{parseFloat(transactionData.amount).toLocaleString()}</span></p>
                <p><span className="text-gray-600">New Balance:</span> <span className="font-semibold text-green-600">₦{transactionResult.balance ? parseFloat(transactionResult.balance).toLocaleString() : 'Updated'}</span></p>
                <p><span className="text-gray-600">Status:</span> <span className="font-semibold text-green-600">Completed</span></p>
                {transactionResult.message && (
                  <p><span className="text-gray-600">Message:</span> <span className="text-green-600">{transactionResult.message}</span></p>
                )}
              </div>
            </div>
          </div>
        )}
        <button
          onClick={resetForm}
          className="mt-8 w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
        >
          Make Another Transfer
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto bg-white p-8 rounded-xl shadow-lg">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-800">Send Money</h1>
        {user && user.balance && (
          <div className="text-right">
            <p className="text-sm text-gray-500">Available Balance</p>
            <p className="text-xl font-semibold text-green-600">
              ₦{parseFloat(user.balance).toLocaleString()}
            </p>
            <p className="text-xs text-gray-400">Account: {user.account_number}</p>
          </div>
        )}
      </div>

      {/* Stepper */}
      <div className="flex items-center mb-8">
        <div className={`flex-1 text-center ${step >= 1 ? 'text-green-600' : 'text-gray-400'}`}>
          <div className={`mx-auto h-8 w-8 rounded-full border-2 flex items-center justify-center ${step >= 1 ? 'border-green-600 bg-green-50' : 'border-gray-300 bg-white'}`}>1</div>
          <p className="text-xs mt-1">Enter Details</p>
        </div>
        <div className={`flex-1 h-px ${step > 1 ? 'bg-green-600' : 'bg-gray-300'}`}></div>
        <div className={`flex-1 text-center ${step >= 2 ? 'text-green-600' : 'text-gray-400'}`}>
          <div className={`mx-auto h-8 w-8 rounded-full border-2 flex items-center justify-center ${step >= 2 ? 'border-green-600 bg-green-50' : 'border-gray-300 bg-white'}`}>2</div>
          <p className="text-xs mt-1">Confirm & Send</p>
        </div>
      </div>


      <form onSubmit={handleSubmit} className="space-y-6">
        {error && (
          <div className="flex items-center space-x-2 text-sm text-red-600 bg-red-50 p-3 rounded-md">
            <AlertCircle className="h-5 w-5" />
            <span>{error}</span>
          </div>
        )}

        {step === 1 && (
          <div>
            <h3 className="text-lg font-medium text-gray-700 mb-4">Recipient Details</h3>
            <div className="space-y-4">
              <div>
                <label htmlFor="to_account" className="block text-sm font-medium text-gray-700">
                  Recipient Account Number
                </label>
                <input
                  type="text"
                  name="to_account"
                  id="to_account"
                  value={transactionData.to_account}
                  onChange={handleChange}
                  maxLength="10"
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500"
                  placeholder="0123456789"
                />
              </div>
              <div>
                <label htmlFor="amount" className="block text-sm font-medium text-gray-700">
                  Amount (₦)
                </label>
                <input
                  type="number"
                  name="amount"
                  id="amount"
                  value={transactionData.amount}
                  onChange={handleChange}
                  min="1"
                  step="0.01"
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500"
                  placeholder="5000.00"
                />
                {user.balance && (
                  <p className="mt-1 text-xs text-gray-500">
                    Maximum: ₦{parseFloat(user.balance).toLocaleString()}
                  </p>
                )}
              </div>
              <div>
                <label htmlFor="description" className="block text-sm font-medium text-gray-700">
                  Description (Optional)
                </label>
                <input
                  type="text"
                  name="description"
                  id="description"
                  value={transactionData.description}
                  onChange={handleChange}
                  maxLength="100"
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500"
                  placeholder="e.g., For groceries, Birthday gift"
                />
              </div>
              <div>
                <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                  Enter your 6-digit PIN to validate account
                </label>
                <input
                  type="password"
                  name="pin"
                  id="pin"
                  maxLength="6"
                  value={storedPin}
                  onChange={handlePinChange}
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-green-500 focus:border-green-500 text-center tracking-[1em]"
                  placeholder="••••••"
                />
                <div className="mt-2 p-3 bg-blue-50 rounded text-blue-700 text-sm">
                  <p><strong>🔐 PIN Required for Account Validation</strong></p>
                  <p className="text-xs mt-1">Your PIN is needed to securely validate the recipient's account before proceeding.</p>
                </div>
              </div>
            </div>
            <div className="mt-6">
              <button
                type="button"
                onClick={handleNextStep}
                disabled={loading || !transactionData.to_account || !transactionData.amount || storedPin.length !== 6}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader className="animate-spin h-5 w-5" /> : 'Validate Account & Continue'}
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div>
            <h3 className="text-lg font-medium text-gray-700 mb-4">Confirm Transaction</h3>
            <div className="bg-gray-50 p-4 rounded-lg space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-600">Sending to:</span>
                <span className="font-medium text-gray-800">{transactionData.to_account}</span>
              </div>
              {recipientInfo && (
                <div className="flex justify-between">
                  <span className="text-gray-600">Recipient Name:</span>
                  <span className="font-medium text-green-700">{recipientInfo.first_name} {recipientInfo.last_name}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-gray-600">Amount:</span>
                <span className="font-bold text-xl text-green-600">₦{parseFloat(transactionData.amount).toLocaleString()}</span>
              </div>
              {transactionData.description && (
                <div className="flex justify-between">
                  <span className="text-gray-600">Description:</span>
                  <span className="font-medium text-gray-800">{transactionData.description}</span>
                </div>
              )}
              <div className="border-t pt-3 mt-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Your balance after transfer:</span>
                  <span className="font-medium text-gray-800">₦{(parseFloat(user.balance || 0) - parseFloat(transactionData.amount || 0)).toLocaleString()}</span>
                </div>
              </div>
            </div>
            <div className="mt-6">
              <div className="p-3 bg-green-50 rounded text-green-700 text-sm mb-4">
                <p><strong>🔐 Ready to Send</strong></p>
                <p className="text-xs mt-1">Your PIN has been verified. Click "Confirm & Send Money" to complete the transfer.</p>
              </div>
            </div>
            <div className="mt-6 flex items-center justify-between space-x-4">
              <button
                type="button"
                onClick={handlePrevStep}
                className="w-full bg-gray-200 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader className="animate-spin h-5 w-5" /> : 'Confirm'}
              </button>
            </div>
          </div>
        )}
      </form>
    </div>
  );
}