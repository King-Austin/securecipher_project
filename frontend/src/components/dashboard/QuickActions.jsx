import { Send, CreditCard, History, Shield, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function QuickActions({ onRefreshClick }) {
  const actions = [
    { 
      icon: <Send className="h-5 w-5" />, 
      label: 'Send Money', 
      color: 'bg-blue-100 text-blue-600', 
      link: '/send-money' 
    },
    { 
      icon: <CreditCard className="h-5 w-5" />, 
      label: 'Cards', 
      color: 'bg-purple-100 text-purple-600', 
      link: '/cards' 
    },
    { 
      icon: <History className="h-5 w-5" />, 
      label: 'Transactions', 
      color: 'bg-green-100 text-green-600', 
      link: '/transactions' 
    },
    { 
      icon: <Shield className="h-5 w-5" />, 
      label: 'Security', 
      color: 'bg-orange-100 text-orange-600', 
      link: '/security-details' 
    },
  ];

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-medium text-gray-800">Quick Actions</h2>
        <button
          onClick={onRefreshClick}
          className="flex items-center px-3 py-1 text-sm bg-blue-100 text-blue-600 rounded-md hover:bg-blue-200 transition-colors"
          title="Refresh dashboard data"
        >
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </button>
      </div>
      
      <div className="grid grid-cols-2 gap-3">
        {actions.map((action, index) => (
          <Link 
            key={index} 
            to={action.link}
            className="flex flex-col items-center justify-center p-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
          >
            <div className={`rounded-full p-2 ${action.color} mb-2`}>
              {action.icon}
            </div>
            <span className="text-sm text-gray-700">{action.label}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
