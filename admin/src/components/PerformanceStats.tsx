import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Clock, CheckCircle, XCircle, BarChart3 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface Transaction {
  id: string;
  transaction_id: string;
  status_code: number;
  processing_time_ms: number;
  created_at: string;
}

export const PerformanceStats = () => {
  const { dashboardData } = useAuth();
  
  const transactions = dashboardData?.transactions || [];
  const stats = dashboardData?.stats || {};

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
          value={`${((stats.avg_processing_time_ms || 0) / 1000).toFixed(2)}s`}
          icon={Clock}
          color="text-blue-600"
        />
        <StatItem
          label="Total Transactions"
          value={stats.total_transactions_24h || 0}
          icon={BarChart3}
          color="text-purple-600"
        />
        <StatItem
          label="Successful"
          value={stats.successful_transactions_24h || 0}
          icon={CheckCircle}
          color="text-green-600"
        />
        <StatItem
          label="Failed"
          value={stats.failed_transactions_24h || 0}
          icon={XCircle}
          color="text-red-600"
        />
        <div className="pt-4 border-t">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Success Rate</span>
            <span className="font-semibold text-green-600">
              {(stats.success_rate_24h || 0).toFixed(1)}%
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};