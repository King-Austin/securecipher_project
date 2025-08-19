import { Card } from '@/components/ui/card';
import { TransactionChart } from './TransactionChart';
import { PerformanceStats } from './PerformanceStats';
import { format } from 'date-fns';
import { useState, useEffect } from 'react';

const Dashboard = () => {
  const [dashboardData, setDashboardData] = useState<any>(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/admin/', {
          headers: { 'Content-Type': 'application/json' },
        });
        if (!response.ok) throw new Error('Failed to fetch dashboard data');
        const data = await response.json();
        setDashboardData(data);
        localStorage.setItem('dashboardData', JSON.stringify(data));
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
        const cached = localStorage.getItem('dashboardData');
        if (cached) setDashboardData(JSON.parse(cached));
      }
    };
    fetchDashboardData();
  }, []);

  // Extract active public key
  const activePublicKey = dashboardData?.middleware_keys?.find((k: any) => k.active);

  // Transaction metrics
  const totalTransactions = dashboardData?.transactions?.length || 0;
  const verifiedSignatures = dashboardData?.transactions?.filter((t: any) => t.status_code === 200).length || 0;
  const failedSignatures = totalTransactions - verifiedSignatures;
  const successRate = totalTransactions > 0 ? Math.round((verifiedSignatures / totalTransactions) * 100) : 0;
  const failureRate = totalTransactions > 0 ? Math.round((failedSignatures / totalTransactions) * 100) : 0;

  // Helper to shorten PEM key
  const shortenKey = (key: string) => {
    if (!key) return '';
    const trimmed = key.replace(/-----BEGIN (PUBLIC|PRIVATE) KEY-----/g, '')
                       .replace(/-----END (PUBLIC|PRIVATE) KEY-----/g, '')
                       .replace(/\s+/g, '');
    return `${trimmed.substring(0, 20)}...${trimmed.substring(trimmed.length - 10)}`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">Cryptographic activity overview</p>
      </div>

      {/* Key Status */}
      <Card className="p-6 border-l-4 border-primary shadow-lg bg-white">
        <h3 className="text-xl font-semibold mb-4 text-primary">Active Key Status</h3>
        {activePublicKey ? (
          <div className="space-y-4">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-gray-50 p-3 rounded-lg border border-gray-200">
              <span className="text-sm text-gray-500 font-medium">Public Key:</span>
              <code className="text-sm bg-gray-100 px-3 py-1 rounded break-all w-full md:w-auto mt-1 md:mt-0">
                {shortenKey(activePublicKey.public_key_pem)}
              </code>
            </div>
            <div className="flex justify-between items-center bg-gray-50 p-3 rounded-lg border border-gray-200">
              <span className="text-sm text-gray-500 font-medium">Next Rotation:</span>
              <span className="text-sm font-semibold text-gray-700">
                {activePublicKey.rotated_at
                  ? format(new Date(activePublicKey.rotated_at), 'MMM dd, yyyy')
                  : 'Next 30 days'}
              </span>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-400 italic">No active key found</p>
        )}
      </Card>

      {/* Transaction Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-4 shadow-md hover:shadow-lg transition-all duration-200">
          <h4 className="text-md font-semibold text-gray-700 mb-2">Total Transactions</h4>
          <p className="text-2xl font-bold text-primary">{totalTransactions}</p>
          <p className="text-sm text-gray-400 mt-1">Today</p>
        </Card>
        <Card className="p-4 shadow-md hover:shadow-lg transition-all duration-200">
          <h4 className="text-md font-semibold text-gray-700 mb-2">Verified Signatures</h4>
          <p className="text-2xl font-bold text-green-600">{verifiedSignatures}</p>
          <p className="text-sm text-gray-400 mt-1">{successRate}% success rate</p>
        </Card>
        <Card className="p-4 shadow-md hover:shadow-lg transition-all duration-200">
          <h4 className="text-md font-semibold text-gray-700 mb-2">Failed Verifications</h4>
          <p className="text-2xl font-bold text-red-600">{dashboardData?.nonces?.filter((n: any) => n.status_code !== 200).length || 0}</p>
          <p className="text-sm text-gray-400 mt-1">{failureRate}% failure rate</p>
        </Card>
      </div>

      {/* Charts and Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TransactionChart />
        <PerformanceStats />
      </div>

    </div>
  );
};

export default Dashboard;
