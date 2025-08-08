import { ArrowUpRight, ArrowDownLeft, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useState, useEffect } from 'react';

export default function RecentTransactions() {
  const [transactions, setTransactions] = useState([]);

  // Load transactions from localStorage
  useEffect(() => {
    const txnData = localStorage.getItem('userTransactions');
    if (txnData) setTransactions(JSON.parse(txnData));
  }, []);

  // Sort by date (newest first) and limit to 5
  const sortedTransactions = (transactions || [])
    .slice()
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5);

  // Format date from ISO string to "15 Jun 2025" format
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short',
      year: 'numeric'
    });
  };

  // Format amount with Naira symbol
  const formatAmount = (amount) => {
    return new Intl.NumberFormat('en-NG', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(amount);
  };

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className="flex items-center justify-between p-6 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-800">Recent Transactions</h2>
        <div className="flex items-center">
          <Link to="/transactions" className="text-green-600 hover:text-green-800 flex items-center">
            View All
            <ChevronRight className="h-4 w-4 ml-1" />
          </Link>
        </div>
      </div>
      <ul className="divide-y divide-gray-200">
        {sortedTransactions.length === 0 ? (
          <li className="p-6 text-gray-500 text-center">No transactions found.</li>
        ) : (
          sortedTransactions.map((txn) => (
            <li key={txn.id} className="flex items-center justify-between p-6">
              <div className="flex items-center">
                {txn.transaction_type === 'Credit' ? (
                  <ArrowDownLeft className="h-5 w-5 text-green-500 mr-3" />
                ) : (
                  <ArrowUpRight className="h-5 w-5 text-red-500 mr-3" />
                )}
                <div>
                  <p className="text-sm font-medium text-gray-800">{txn.description}</p>
                  <p className="text-xs text-gray-500">{formatDate(txn.created_at)}</p>
                </div>
              </div>
              <div className="text-right">
                <p className={`text-sm font-bold ${txn.transaction_type === 'Credit' ? 'text-green-600' : 'text-red-600'}`}>
                  {txn.transaction_type === 'Credit' ? '+' : '-'}₦{formatAmount(txn.amount)}
                </p>
                <p className="text-xs text-gray-400">{txn.status}</p>
              </div>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}
