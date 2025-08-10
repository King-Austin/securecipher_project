import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ClipboardList, ArrowUpRight, ArrowDownLeft, Calendar, Filter, Search, Download } from 'lucide-react';

export default function Transactions() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [filteredTransactions, setFilteredTransactions] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all');

  useEffect(() => {
    const storedProfile = localStorage.getItem('userProfile');
    const storedTransactions = localStorage.getItem('userTransactions');
    
    if (storedProfile) {
      setProfile(JSON.parse(storedProfile));
    } else {
      navigate('/register', { replace: true });
    }

    if (storedTransactions) {
      const txns = JSON.parse(storedTransactions);
      setTransactions(txns);
      setFilteredTransactions(txns);
    }
  }, [navigate]);

  useEffect(() => {
    let filtered = transactions;

    // Filter by type
    if (filterType !== 'all') {
      filtered = filtered.filter(txn => txn.transaction_type.toLowerCase() === filterType.toLowerCase());
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(txn => 
        txn.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        txn.recipient_account?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        txn.amount.toString().includes(searchTerm)
      );
    }

    setFilteredTransactions(filtered);
  }, [transactions, searchTerm, filterType]);

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const formatAmount = (amount, type) => {
    const formattedAmount = `₦${parseFloat(amount).toLocaleString()}`;
    return type.toLowerCase() === 'credit' ? `+${formattedAmount}` : `-${formattedAmount}`;
  };

  if (!profile) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <ClipboardList className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-500">Loading transactions...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center mb-2">
          <ClipboardList className="h-8 w-8 text-green-600 mr-3" />
          <h1 className="text-3xl font-bold text-gray-800">Transaction History</h1>
        </div>
        <p className="text-gray-600">View and manage your transaction history</p>
      </div>

      {/* Filters and Search */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
            <input
              type="text"
              placeholder="Search transactions..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
            />
          </div>

          {/* Filter by Type */}
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
            >
              <option value="all">All Transactions</option>
              <option value="credit">Money Received (Credit)</option>
              <option value="debit">Money Sent (Debit)</option>
            </select>
          </div>

          {/* Export Button */}
          <button className="flex items-center justify-center space-x-2 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 transition-colors">
            <Download className="h-4 w-4" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Transaction List */}
      <div className="bg-white rounded-lg shadow">
        <div className="p-6 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800">
            {filteredTransactions.length} Transaction{filteredTransactions.length !== 1 ? 's' : ''}
          </h3>
        </div>

        {filteredTransactions.length === 0 ? (
          <div className="p-8 text-center">
            <ClipboardList className="h-12 w-12 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">No transactions found</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {filteredTransactions.map((transaction, index) => (
              <div key={index} className="p-6 hover:bg-gray-50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                      transaction.transaction_type.toLowerCase() === 'credit' 
                        ? 'bg-green-100 text-green-600' 
                        : 'bg-red-100 text-red-600'
                    }`}>
                      {transaction.transaction_type.toLowerCase() === 'credit' ? (
                        <ArrowDownLeft className="h-5 w-5" />
                      ) : (
                        <ArrowUpRight className="h-5 w-5" />
                      )}
                    </div>
                    
                    <div>
                      <h4 className="font-medium text-gray-800">
                        {transaction.transaction_type.toLowerCase() === 'credit' ? 'Money Received' : 'Money Sent'}
                      </h4>
                      <p className="text-sm text-gray-600">
                        {transaction.description || 'No description'}
                      </p>
                      <div className="flex items-center text-xs text-gray-500 mt-1">
                        <Calendar className="h-3 w-3 mr-1" />
                        {formatDate(transaction.created_at)}
                      </div>
                    </div>
                  </div>

                  <div className="text-right">
                    <p className={`text-lg font-semibold ${
                      transaction.transaction_type.toLowerCase() === 'credit' 
                        ? 'text-green-600' 
                        : 'text-red-600'
                    }`}>
                      {formatAmount(transaction.amount, transaction.transaction_type)}
                    </p>
                    <p className={`text-xs px-2 py-1 rounded-full ${
                      transaction.status === 'COMPLETED' 
                        ? 'bg-green-100 text-green-800' 
                        : transaction.status === 'PENDING'
                        ? 'bg-yellow-100 text-yellow-800'
                        : 'bg-red-100 text-red-800'
                    }`}>
                      {transaction.status}
                    </p>
                  </div>
                </div>

                {transaction.recipient_account && (
                  <div className="mt-3 pl-14">
                    <p className="text-sm text-gray-600">
                      {transaction.transaction_type.toLowerCase() === 'credit' ? 'From: ' : 'To: '}
                      <span className="font-medium">{transaction.recipient_account}</span>
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
