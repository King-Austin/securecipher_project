import { ArrowUpRight, ArrowDownLeft, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useState, useEffect } from 'react';

export default function RecentTransactions() {
  const [transactions, setTransactions] = useState([]);

  // Load transactions from localStorage
  useEffect(() => {
    const txnData = localStorage.getItem('userTransactions');
    if (txnData) {
      const parsedTransactions = JSON.parse(txnData);
      setTransactions(parsedTransactions);
      console.log('RecentTransactions: Loaded transaction data:', parsedTransactions);
    }
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
    const numAmount = Math.abs(parseFloat(amount) || 0);
    return new Intl.NumberFormat('en-NG', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(numAmount);
  };

  // Determine transaction type and color
  const getTransactionInfo = (txn) => {
    const amount = parseFloat(txn.amount) || 0;
    const isCredit = amount > 0 || txn.transaction_type === 'CREDIT';
    
    return {
      isCredit,
      displayType: isCredit ? 'Credit' : 'Debit',
      colorClass: isCredit ? 'text-green-600' : 'text-red-600',
      iconColorClass: isCredit ? 'text-green-500' : 'text-red-500',
      prefix: isCredit ? '+' : '-'
    };
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
          <li className="p-6 text-gray-500 text-center">
            <p>No transactions found.</p>
            <p className="text-xs mt-1">Your transaction history will appear here.</p>
          </li>
        ) : (
          sortedTransactions.map((txn) => {
            const transactionInfo = getTransactionInfo(txn);
            
            return (
              <li key={txn.id} className="flex items-center justify-between p-6 hover:bg-gray-50 transition-colors">
                <div className="flex items-center">
                  {transactionInfo.isCredit ? (
                    <ArrowDownLeft className={`h-5 w-5 ${transactionInfo.iconColorClass} mr-3`} />
                  ) : (
                    <ArrowUpRight className={`h-5 w-5 ${transactionInfo.iconColorClass} mr-3`} />
                  )}
                  <div>
                    <p className="text-sm font-medium text-gray-800">
                      {txn.description || `${transactionInfo.displayType} Transaction`}
                    </p>
                    <p className="text-xs text-gray-500">{formatDate(txn.created_at)}</p>
                    {txn.reference_number && (
                      <p className="text-xs text-gray-400">Ref: {txn.reference_number}</p>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <p className={`text-sm font-bold ${transactionInfo.colorClass}`}>
                    {transactionInfo.prefix}₦{formatAmount(txn.amount)}
                  </p>
                  <p className="text-xs text-gray-400 capitalize">
                    {txn.status || 'Completed'}
                  </p>
                  {txn.balance_after && (
                    <p className="text-xs text-gray-400">
                      Bal: ₦{formatAmount(txn.balance_after)}
                    </p>
                  )}
                </div>
              </li>
            );
          })
        )}
      </ul>
    </div>
  );
}
