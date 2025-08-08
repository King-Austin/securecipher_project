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
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [transactionResult, setTransactionResult] = useState(null);
  const [recipientInfo, setRecipientInfo] = useState(null);
  const [accounts, setAccounts] = useState([]);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Load user accounts from local storage (set by Registration/Login)
  useEffect(() => {
    const userAccounts = localStorage.getItem('userAccounts');
    if (userAccounts) {
      setAccounts(JSON.parse(userAccounts));
      setIsAuthenticated(true);
    }
  }, []);

  // Validate amount before proceeding to next step
  const handleNextStep = async () => {
    const account = accounts?.[0];
    const available = account ? parseFloat(account.available_balance) : 0;
    const amount = parseFloat(transactionData.amount);
    const toAccount = transactionData.to_account;

    // Validation checks
    if (!toAccount || !transactionData.amount) {
      setError('Please fill in all required fields.');
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
    if (account && toAccount === account.account_number) {
      setError('You cannot send money to your own account.');
      return;
    }
    if (isNaN(available) || available <= 0) {
      setError('Invalid account balance.');
      return;
    }
    if (amount > available) {
      setError(`Insufficient funds. Your available balance is ₦${available.toLocaleString()}.`);
      return;
    }

    // Fetch recipient info securely
    try {
      const payload = { account_number: transactionData.to_account };
      const response = await secureRequest({
        target: 'validate_account',
        payload,
        pin // PIN is not strictly needed for validation, but can be required by backend
      });
      if (response && response.user) {
        setRecipientInfo(response.user);
        setError('');
        setStep(2);
      } else {
        setError('Recipient account not found.');
      }
    } catch (err) {
      setError('Failed to validate recipient account.');
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
      setPin(value);
      setError('');
    }
  };

  // Use SecureKeyManager to verify PIN before transaction
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (pin.length !== 6) {
      setError('Please enter your 6-digit PIN.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const account = accounts && accounts[0];
      if (!account) throw new Error('No account found.');

      // Final validation before sending
      const amount = parseFloat(transactionData.amount);
      if (isNaN(amount) || amount <= 0) {
        setError('Amount must be greater than zero.');
        setLoading(false);
        return;
      }
      if (amount > parseFloat(account.available_balance)) {
        setError('Insufficient funds.');
        setLoading(false);
        return;
      }

      // Verify PIN and unlock key before sending
      const keyData = await SecureKeyManager.fetchEncryptedPrivateKey();
      if (!keyData) throw new Error('No encrypted key found. Please login again.');
      await SecureKeyManager.decryptPrivateKey(keyData.encrypted, pin, keyData.salt, keyData.iv);

      const payload = {
        from_account: account.account_number,
        to_account: transactionData.to_account,
        amount: transactionData.amount,
        description: transactionData.description || 'Fund Transfer',
      };

      // Use secureRequest for transaction
      const response = await secureRequest({
        target: 'transfer',
        payload,
        pin
      });

      if (response.success) {
        setTransactionResult(response);
        setSuccess(true);

        // Update user data and accounts in localStorage if provided by server
        if (response.user) {
          localStorage.setItem('userProfile', JSON.stringify(response.user));
        }
        if (response.accounts) {
          localStorage.setItem('userAccounts', JSON.stringify(response.accounts));
          setAccounts(response.accounts); // update local state for immediate UI update
        }
        if (response.transactions) {
          localStorage.setItem('userTransactions', JSON.stringify(response.transactions));
        }
      } else {
        throw new Error(response.error || 'Transaction failed. Please try again.');
      }
    } catch (err) {
      console.error('Transfer Error:', err);
      const errorMessage = err.response?.data?.error || err.message || 'An unexpected error occurred.';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setStep(1);
    setTransactionData({ to_account: '', amount: '', description: '' });
    setPin('');
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
          You have successfully sent <strong>₦{parseFloat(transactionData.amount).toLocaleString()}</strong> to account <strong>{transactionData.to_account}</strong>.
        </p>
        <div className="mt-6 text-left bg-gray-50 p-4 rounded-md">
          <p className="text-sm text-gray-500">Transaction ID:</p>
          <p className="font-mono text-xs text-gray-800 break-all">{transactionResult?.debit_transaction_id}</p>
        </div>
        <button
          onClick={resetForm}
          className="mt-8 w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
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
        {accounts && accounts[0] && (
          <div className="text-right">
            <p className="text-sm text-gray-500">Available Balance</p>
            <p className="text-xl font-semibold text-indigo-600">
              ₦{parseFloat(accounts[0].available_balance).toLocaleString()}
            </p>
          </div>
        )}
      </div>

      {/* Stepper */}
      <div className="flex items-center mb-8">
        <div className={`flex-1 text-center ${step >= 1 ? 'text-indigo-600' : 'text-gray-400'}`}>
          <div className="mx-auto h-8 w-8 rounded-full border-2 flex items-center justify-center bg-white">1</div>
          <p className="text-xs mt-1">Details</p>
        </div>
        <div className={`flex-1 h-px ${step > 1 ? 'bg-indigo-600' : 'bg-gray-300'}`}></div>
        <div className={`flex-1 text-center ${step >= 2 ? 'text-indigo-600' : 'text-gray-400'}`}>
          <div className="mx-auto h-8 w-8 rounded-full border-2 flex items-center justify-center bg-white">2</div>
          <p className="text-xs mt-1">Confirm</p>
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
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
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
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  placeholder="5000.00"
                />
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
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                  placeholder="e.g., For groceries"
                />
              </div>
            </div>
            <div className="mt-6">
              <button
                type="button"
                onClick={handleNextStep}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                Continue
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
                <span className="font-bold text-xl text-indigo-600">₦{parseFloat(transactionData.amount).toLocaleString()}</span>
              </div>
              {transactionData.description && (
                <div className="flex justify-between">
                  <span className="text-gray-600">Description:</span>
                  <span className="font-medium text-gray-800">{transactionData.description}</span>
                </div>
              )}
            </div>
            <div className="mt-6">
              <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                Enter your 6-digit PIN to authorize
              </label>
              <input
                type="password"
                name="pin"
                id="pin"
                maxLength="6"
                value={pin}
                onChange={handlePinChange}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 text-center tracking-[1em]"
                placeholder="••••••"
              />
              <div className="mt-2 p-3 bg-green-50 rounded text-green-700 text-sm">
                <strong>What is your PIN used for?</strong>
                <ul className="list-disc ml-5 mt-1">
                  <li>Your PIN encrypts and protects your private key on this device.</li>
                  <li>It is required to authorize secure transactions and access your account.</li>
                  <li>Never share your PIN with anyone. It cannot be recovered if forgotten.</li>
                </ul>
              </div>
            </div>
            <div className="mt-6 flex items-center justify-between space-x-4">
              <button
                type="button"
                onClick={handlePrevStep}
                className="w-full bg-gray-200 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-300"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading || pin.length !== 6}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50"
              >
                {loading ? <Loader className="animate-spin h-5 w-5" /> : 'Confirm & Send'}
              </button>
            </div>
          </div>
        )}
      </form>
    </div>
  );
}