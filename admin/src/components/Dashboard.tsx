import { Card } from '@/components/ui/card';
import { TransactionChart } from './TransactionChart';
import { PerformanceStats } from './PerformanceStats';
import { format } from 'date-fns';
import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const { fetchDashboard } = useAuth();
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        const data = await fetchDashboard();
        setDashboardData(data || {});
      } catch (error) {
        console.error('Error loading dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadDashboard();
  }, [fetchDashboard]);

  if (loading) return <p className="text-center text-gray-500">Loading dashboard...</p>;

  // Active key
  const activeKey = dashboardData?.middleware_keys?.find((k: any) => k.active);

  // Transactions
  const transactions = dashboardData?.transactions || [];
  const totalTransactions = transactions.length;
  const verifiedSignatures = transactions.filter((t: any) => t.status_code === 200).length;
  const failedSignatures = totalTransactions - verifiedSignatures;
  const successRate = totalTransactions ? Math.round((verifiedSignatures / totalTransactions) * 100) : 0;
  const failureRate = totalTransactions ? Math.round((failedSignatures / totalTransactions) * 100) : 0;

  // Nonces
  const nonces = dashboardData?.nonces || [];
  const failedNonces = nonces.filter((n: any) => n.status_code !== 200).length;

  // Helper
  const shortenKey = (key: string) => {
    if (!key) return '';
    const clean = key.replace(/-----.* KEY-----/g, '').replace(/\s+/g, '');
    return `${clean.slice(0, 20)}...${clean.slice(-10)}`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">Cryptographic activity overview</p>
      </div>

      {/* Active Key */}
      <Card className="p-4">
        <h3 className="font-semibold mb-2">Active Key</h3>
        {activeKey ? (
          <>
            <p className="text-sm">Public Key: <code>{shortenKey(activeKey.public_key_pem)}</code></p>
            <p className="text-sm">Next Rotation: {activeKey.rotated_at ? format(new Date(activeKey.rotated_at), 'MMM dd, yyyy') : 'Unknown'}</p>
          </>
        ) : (
          <p className="text-gray-400 text-sm italic">No active key found</p>
        )}
      </Card>

      {/* Transactions */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-4">
          <h4 className="text-sm font-medium">Total Transactions</h4>
          <p className="text-2xl font-bold text-primary">{totalTransactions}</p>
        </Card>

        <Card className="p-4">
          <h4 className="text-sm font-medium">Verified Signatures</h4>
          <p className="text-2xl font-bold text-green-600">{verifiedSignatures}</p>
          <p className="text-xs text-gray-500">{successRate}% success</p>
        </Card>

        <Card className="p-4">
          <h4 className="text-sm font-medium">Failed Nonces</h4>
          <p className="text-2xl font-bold text-red-600">{failedNonces}</p>
          <p className="text-xs text-gray-500">{failureRate}% error</p>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TransactionChart />
        <PerformanceStats />
      </div>
    </div>
  );
};

export default Dashboard;
