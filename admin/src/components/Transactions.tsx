import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { format, subHours, startOfHour, startOfDay } from 'date-fns';
import { useAuth } from '../context/AuthContext';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

export const TransactionChart = () => {
  const { dashboardData } = useAuth();
  const [view, setView] = useState<'24h' | 'all'>('24h');

  const transactions = dashboardData?.transactions || [];

  // --- Last 24 hours, hourly ---
  const last24Hours = useMemo(() => {
    return Array.from({ length: 24 }, (_, i) => {
      const hour = startOfHour(subHours(new Date(), 23 - i));
      const count = transactions.filter(
        t => startOfHour(new Date(t.created_at)).getTime() === hour.getTime()
      ).length;
      return {
        label: format(hour, 'HH:00'),
        count,
      };
    });
  }, [transactions]);

  // --- All time, grouped by day ---
  const allTimeDaily = useMemo(() => {
    const grouped: Record<string, number> = {};
    transactions.forEach(t => {
      const day = format(startOfDay(new Date(t.created_at)), 'yyyy-MM-dd');
      grouped[day] = (grouped[day] || 0) + 1;
    });

    return Object.entries(grouped)
      .sort(([a], [b]) => new Date(a).getTime() - new Date(b).getTime())
      .map(([day, count]) => ({
        label: format(new Date(day), 'MMM d'),
        count,
      }));
  }, [transactions]);

  const dataSet = view === '24h' ? last24Hours : allTimeDaily;

  const chartData = {
    labels: dataSet.map(d => d.label),
    datasets: [
      {
        label: view === '24h' ? 'Transactions per Hour' : 'Transactions per Day',
        data: dataSet.map(d => d.count),
        backgroundColor: 'hsl(var(--primary))',
        borderColor: 'hsl(var(--primary))',
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: { position: 'top' as const },
      title: { display: false },
    },
    scales: {
      y: { beginAtZero: true, ticks: { stepSize: 1 } },
      x: { title: { display: true, text: view === '24h' ? 'Hour' : 'Day' } },
    },
  };

  return (
    <Card>
      <CardHeader className="flex justify-between items-center">
        <CardTitle>
          Transaction Volume ({view === '24h' ? 'Last 24 Hours' : 'All Time'})
        </CardTitle>
        <div className="space-x-2">
          <Button
            variant={view === '24h' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setView('24h')}
          >
            24h
          </Button>
          <Button
            variant={view === 'all' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setView('all')}
          >
            All Time
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <Bar data={chartData} options={options} />
      </CardContent>
    </Card>
  );
};
