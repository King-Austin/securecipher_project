import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Clock, CheckCircle, XCircle, BarChart3 } from 'lucide-react';

interface Transaction {
  id: string;
  transaction_id: string;
  status_code: number;
  processing_time_ms: number;
  created_at: string;
}

export const PerformanceStats = () => {
  const [transactions, setTransactions] = useState<Transaction[]>([]);

  useEffect(() => {
    const storedData = localStorage.getItem('dashboardData');
    if (storedData) {
      const parsed = JSON.parse(storedData);
      setTransactions(parsed.transactions || []);
    }
  }, []);

  const last24HourTx = transactions.filter(tx => {
    const txTime = new Date(tx.created_at);
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return txTime >= twentyFourHoursAgo;
  });

  const avgProcessingTime = last24HourTx.length > 0
    ? last24HourTx.reduce((sum, tx) => sum + (tx.processing_time_ms || 0), 0) / last24HourTx.length / 1000
    : 0;

  const successCount = last24HourTx.filter(tx => tx.status_code === 200).length;
  const failedCount = last24HourTx.filter(tx => tx.status_code !== 200).length;
  const successRate = last24HourTx.length > 0 ? (successCount / last24HourTx.length) * 100 : 0;

  const StatItem = ({ label, value, icon: Icon, color = 'text-primary' }: any) => (
    <div className="flex items-center justify-between p-4 bg-muted/30 rounded-lg">
      <div className="flex items-center gap-3">
        <Icon className={`h-5 w-5 ${color}`} />
        <span className="text-sm font-medium">{label}</span>
      </div>
      <span className={`text-lg font-bold ${color}`}>{value}</span>
    </div>
  );

  return (
    <Card className="border-0 shadow-lg">
      <CardHeader className="bg-gradient-to-r from-purple-50 to-blue-50">
        <CardTitle className="flex items-center gap-2 text-xl">
          <BarChart3 className="h-5 w-5" />
          Performance Stats (24h)
        </CardTitle>
      </CardHeader>
      <CardContent className="p-6 space-y-4">
        <StatItem
          label="Avg Processing Time"
          value={`${avgProcessingTime.toFixed(2)}s`}
          icon={Clock}
          color="text-blue-600"
        />
        <StatItem
          label="Total Transactions"
          value={last24HourTx.length}
          icon={BarChart3}
          color="text-purple-600"
        />
        <StatItem
          label="Successful"
          value={successCount}
          icon={CheckCircle}
          color="text-green-600"
        />
        <StatItem
          label="Failed"
          value={failedCount}
          icon={XCircle}
          color="text-red-600"
        />
        <div className="pt-4 border-t">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Success Rate</span>
            <span className="font-semibold text-green-600">
              {successRate.toFixed(1)}%
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
