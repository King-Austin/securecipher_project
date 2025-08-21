import { format } from 'date-fns';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { TransactionChart } from './TransactionChart';
import { PerformanceStats } from './PerformanceStats';
import { useAuth } from '../context/AuthContext';
import { Key, BarChart3, CheckCircle, Clock } from 'lucide-react';

const Dashboard = () => {
  const { dashboardData, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <p className="p-4 text-red-500">Please log in to view dashboard</p>;
  }

  if (!dashboardData) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  const activeKey = dashboardData.middleware_keys?.[0]; // First key is active
  const stats = dashboardData.stats || {};

  const StatCard = ({ title, value, subtitle, icon: Icon, color = 'text-primary' }: any) => (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground">{title}</p>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          <Icon className="h-8 w-8 text-muted-foreground opacity-60" />
        </div>
      </CardContent>
    </Card>
  );

  const shortenKey = (key: string) => {
    if (!key) return '';
    const clean = key.replace(/-----.* KEY-----/g, '').replace(/\s+/g, '');
    return `${clean.slice(0, 20)}...${clean.slice(-10)}`;
  };

  return (
    <div className="space-y-2 p-6">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">Cryptographic activity overview</p>
      </div>

      {/* Active Key Card */}
      <Card className="bg-gradient-to-r from-blue-50 to-indigo-50">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-lg font-semibold">Active Key</CardTitle>
          <Key className="h-5 w-5 text-blue-600" />
        </CardHeader>
        <CardContent>
          {activeKey ? (
            <div className="space-y-2">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Public Key</p>
                <code className="text-sm font-mono bg-blue-100 px-2 py-1 rounded">
                  {shortenKey(activeKey.public_key_pem)}
                </code>
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">Next Rotation</p>
                <p className="text-sm">
                  {format(
                    activeKey.rotated_at 
                      ? new Date(activeKey.rotated_at)
                      : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
                    'MMM dd, yyyy'
                  )}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-muted-foreground italic">No active key found</p>
          )}
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard
          title="Total Transactions"
          value={stats.total_transactions_24h || 0}
          icon={BarChart3}
          color="text-blue-600"
        />
        <StatCard
          title="Verified Signatures"
          value={stats.successful_transactions_24h || 0}
          subtitle={`${stats.success_rate_24h || 0}% success rate`}
          icon={CheckCircle}
          color="text-green-600"
        />
        <StatCard
          title="Failed Signatures"
          value={stats.failed_transactions_24h || 0}
          subtitle={`${100 - (stats.success_rate_24h || 0)}% failure rate`}
          icon={Clock}
          color="text-red-600"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TransactionChart />
        <PerformanceStats />
      </div>
    </div>
  );
};

export default Dashboard;