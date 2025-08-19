import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

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

  // Filter last 24 hours
  const last24HourTx = transactions.filter(tx => {
    const txTime = new Date(tx.created_at);
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return txTime >= twentyFourHoursAgo;
  });

  // Average processing time in seconds
  const avgProcessingTime =
    last24HourTx.length > 0
      ? last24HourTx.reduce((sum, tx) => sum + (tx.processing_time_ms || 0), 0) / last24HourTx.length / 1000
      : 0;

  // Success / Failed counts
  const successCount = last24HourTx.filter(tx => tx.status_code === 200).length;
  const failedCount = last24HourTx.filter(tx => tx.status_code !== 200).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Performance Stats (24h)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex justify-between items-center p-3 bg-muted/50 rounded">
            <span className="text-sm font-medium">Avg Processing Time</span>
            <span className="text-lg font-bold text-primary">{avgProcessingTime.toFixed(2)} s</span>
          </div>
          <div className="flex justify-between items-center p-3 bg-muted/50 rounded">
            <span className="text-sm font-medium">Total Transactions</span>
            <span className="text-lg font-bold text-primary">{last24HourTx.length}</span>
          </div>
          <div className="flex justify-between items-center p-3 bg-muted/50 rounded">
            <span className="text-sm font-medium">Success / Failed</span>
            <span className="text-lg font-bold text-primary">
              {successCount} / {failedCount}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
