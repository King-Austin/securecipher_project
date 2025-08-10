import { PieChart, Home, ShoppingBag, Coffee, Car, Phone, Heart, MoreHorizontal } from 'lucide-react';
import { useState, useEffect } from 'react';

export default function SpendingInsights() {
  const [transactions, setTransactions] = useState([]);
  const [user, setUser] = useState({});
  const [timeRange, setTimeRange] = useState('30'); // 30 days default

  // Load data from localStorage
  useEffect(() => {
    const userData = localStorage.getItem('userProfile');
    const txnData = localStorage.getItem('userTransactions');
    
    if (userData) setUser(JSON.parse(userData));
    if (txnData) setTransactions(JSON.parse(txnData));
  }, []);

  // Category mapping for transactions
  const categoryMapping = {
    'transfer': { name: 'Transfers', icon: <MoreHorizontal className="h-4 w-4" />, color: 'bg-blue-500' },
    'food': { name: 'Food & Dining', icon: <Coffee className="h-4 w-4" />, color: 'bg-yellow-500' },
    'shopping': { name: 'Shopping', icon: <ShoppingBag className="h-4 w-4" />, color: 'bg-purple-500' },
    'transport': { name: 'Transportation', icon: <Car className="h-4 w-4" />, color: 'bg-green-500' },
    'bills': { name: 'Bills & Utilities', icon: <Phone className="h-4 w-4" />, color: 'bg-red-500' },
    'housing': { name: 'Housing', icon: <Home className="h-4 w-4" />, color: 'bg-indigo-500' },
    'healthcare': { name: 'Healthcare', icon: <Heart className="h-4 w-4" />, color: 'bg-pink-500' },
    'others': { name: 'Others', icon: <MoreHorizontal className="h-4 w-4" />, color: 'bg-gray-500' }
  };

  // Mock spending data based on account balance for demo purposes
  const generateSpendingData = () => {
    const balance = parseFloat(user.balance) || 50000;
    const spentAmount = Math.min(balance * 0.3, 15000); // 30% of balance or max 15k
    
    // If no real debit transactions, show demo spending categories
    const mockCategories = [
      { key: 'transfer', amount: spentAmount * 0.4 },
      { key: 'food', amount: spentAmount * 0.25 },
      { key: 'transport', amount: spentAmount * 0.15 },
      { key: 'bills', amount: spentAmount * 0.12 },
      { key: 'others', amount: spentAmount * 0.08 }
    ];

    return mockCategories;
  };

  // Process real transaction data for spending insights
  const processTransactionData = () => {
    // Filter debit transactions from last 30 days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - parseInt(timeRange));
    
    const debitTransactions = transactions.filter(txn => {
      const txnDate = new Date(txn.created_at);
      const amount = parseFloat(txn.amount) || 0;
      return amount < 0 && txnDate >= cutoffDate; // Negative amounts are debits
    });

    if (debitTransactions.length === 0) {
      return generateSpendingData();
    }

    // Group transactions by category (you could enhance this with description parsing)
    const categoryTotals = {};
    let totalSpent = 0;

    debitTransactions.forEach(txn => {
      const amount = Math.abs(parseFloat(txn.amount));
      const description = (txn.description || '').toLowerCase();
      
      let category = 'others';
      if (description.includes('transfer')) category = 'transfer';
      else if (description.includes('food') || description.includes('restaurant')) category = 'food';
      else if (description.includes('shop') || description.includes('store')) category = 'shopping';
      else if (description.includes('transport') || description.includes('uber')) category = 'transport';
      else if (description.includes('bill') || description.includes('utility')) category = 'bills';

      categoryTotals[category] = (categoryTotals[category] || 0) + amount;
      totalSpent += amount;
    });

    return Object.entries(categoryTotals).map(([key, amount]) => ({
      key,
      amount
    }));
  };

  const spendingData = processTransactionData();
  const totalSpent = spendingData.reduce((sum, item) => sum + item.amount, 0);

  // Convert to display format with percentages
  const categories = spendingData.map(item => {
    const categoryInfo = categoryMapping[item.key] || categoryMapping.others;
    const percentage = totalSpent > 0 ? Math.round((item.amount / totalSpent) * 100) : 0;
    
    return {
      ...categoryInfo,
      amount: item.amount,
      percentage
    };
  }).sort((a, b) => b.amount - a.amount); // Sort by amount descending

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <PieChart className="h-5 w-5 text-gray-700 mr-2" />
          <h2 className="text-lg font-medium text-gray-800">Spending Insights</h2>
        </div>
        <select 
          value={timeRange} 
          onChange={(e) => setTimeRange(e.target.value)}
          className="text-sm border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-green-500"
        >
          <option value="7">Last 7 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
        </select>
      </div>
      
      {totalSpent === 0 ? (
        <div className="text-center py-8">
          <PieChart className="h-12 w-12 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">No spending data available</p>
          <p className="text-gray-400 text-xs mt-1">
            Make some transactions to see your spending insights
          </p>
        </div>
      ) : (
        <>
          <div className="mb-4 text-center">
            <p className="text-2xl font-bold text-gray-800">₦{totalSpent.toLocaleString()}</p>
            <p className="text-sm text-gray-500">Total spent in last {timeRange} days</p>
          </div>
          
          <div className="space-y-4">
            {categories.map((category, index) => (
              <div key={index}>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center">
                    <div className="mr-2 text-gray-600">
                      {category.icon}
                    </div>
                    <span className="text-sm text-gray-700">{category.name}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-sm font-medium text-gray-800">₦{category.amount.toLocaleString()}</span>
                    <span className="text-xs text-gray-500 ml-2">{category.percentage}%</span>
                  </div>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className={`${category.color} h-2 rounded-full transition-all duration-300`} 
                    style={{ width: `${category.percentage}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
          
          {user.first_name && (
            <div className="mt-4 p-3 bg-green-50 rounded-lg">
              <p className="text-sm text-green-700">
                💡 <strong>{user.first_name}</strong>, you've spent {((totalSpent / (parseFloat(user.balance) + totalSpent)) * 100).toFixed(1)}% of your available funds this period.
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
