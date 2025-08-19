import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { format, subHours, startOfHour } from 'date-fns';
import { useState, useEffect } from 'react';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

export const TransactionChart = () => {
  const [transactions, setTransactions] = useState<any[]>([]);

  useEffect(() => {
    const dashboardDataStr = localStorage.getItem('dashboardData');
    if (dashboardDataStr) {
      const dashboardData = JSON.parse(dashboardDataStr);
      setTransactions(dashboardData.transactions || []);
    }
  }, []);

  // Last 24 hours, hourly
  const last24Hours = Array.from({ length: 24 }, (_, i) => {
    const hour = startOfHour(subHours(new Date(), 23 - i));
    const count = transactions.filter(
      t => startOfHour(new Date(t.created_at)).getTime() === hour.getTime()
    ).length;
    return {
      hourLabel: format(hour, 'HH:00'),
      count,
    };
  });

  const chartData = {
    labels: last24Hours.map(d => d.hourLabel),
    datasets: [
      {
        label: 'Transactions per Hour',
        data: last24Hours.map(d => d.count),
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
      x: { title: { display: true, text: 'Hour' } },
    },
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Transaction Volume (Last 24 Hours)</CardTitle>
      </CardHeader>
      <CardContent>
        <Bar data={chartData} options={options} />
      </CardContent>
    </Card>
  );
};
