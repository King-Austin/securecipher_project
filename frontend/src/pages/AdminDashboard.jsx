import React, { useState, useEffect } from 'react';
import { Tabs, Tab, Box, Typography } from '@mui/material';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';
import { Bar } from 'react-chartjs-2';
import { User, Key, FileText, BarChart2 } from 'lucide-react';
import { Chart } from 'chart.js';

const mockUsers = [
  { id: 1, name: 'Alice', email: 'alice@example.com', registeredAt: '2025-01-01' },
  { id: 2, name: 'Bob', email: 'bob@example.com', registeredAt: '2025-02-15' },
];

const mockKeys = [
  { id: 1, label: 'Key1', privateKey: 'PrivateKey1', publicKey: 'PublicKey1', createdAt: '2025-03-01' },
  { id: 2, label: 'Key2', privateKey: 'PrivateKey2', publicKey: 'PublicKey2', createdAt: '2025-04-10' },
];

const mockTransactions = [
  { id: 1, transactionId: 'abc123', status: 'Success', timestamp: '2025-05-01', clientIp: '192.168.1.1', sessionKeyHash: 'hash1', payloadSize: 1024 },
  { id: 2, transactionId: 'def456', status: 'Failed', timestamp: '2025-05-02', clientIp: '192.168.1.2', sessionKeyHash: 'hash2', payloadSize: 2048 },
];

const AdminDashboard = () => {
  const [activeTab, setActiveTab] = useState(0);

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const renderUsers = () => (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Name</TableCell>
            <TableCell>Email</TableCell>
            <TableCell>Registered At</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {mockUsers.map((user) => (
            <TableRow key={user.id}>
              <TableCell>{user.id}</TableCell>
              <TableCell>{user.name}</TableCell>
              <TableCell>{user.email}</TableCell>
              <TableCell>{user.registeredAt}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderKeys = () => (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Label</TableCell>
            <TableCell>Private Key</TableCell>
            <TableCell>Public Key</TableCell>
            <TableCell>Created At</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {mockKeys.map((key) => (
            <TableRow key={key.id}>
              <TableCell>{key.id}</TableCell>
              <TableCell>{key.label}</TableCell>
              <TableCell>{key.privateKey}</TableCell>
              <TableCell>{key.publicKey}</TableCell>
              <TableCell>{key.createdAt}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderTransactions = () => (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Transaction ID</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Timestamp</TableCell>
            <TableCell>Client IP</TableCell>
            <TableCell>Session Key Hash</TableCell>
            <TableCell>Payload Size (bytes)</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {mockTransactions.map((transaction) => (
            <TableRow key={transaction.id}>
              <TableCell>{transaction.id}</TableCell>
              <TableCell>{transaction.transactionId}</TableCell>
              <TableCell>{transaction.status}</TableCell>
              <TableCell>{transaction.timestamp}</TableCell>
              <TableCell>{transaction.clientIp}</TableCell>
              <TableCell>{transaction.sessionKeyHash}</TableCell>
              <TableCell>{transaction.payloadSize}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderAnalytics = () => {
    const data = {
      labels: ['January', 'February', 'March', 'April', 'May'],
      datasets: [
        {
          label: 'Transactions',
          data: [10, 20, 15, 30, 25],
          backgroundColor: 'rgba(75, 192, 192, 0.6)',
        },
      ],
    };

    useEffect(() => {
      return () => {
        Chart.instances.forEach((instance) => {
          if (instance) {
            instance.destroy();
          }
        });
      };
    }, []);

    return <Bar data={data} />;
  };

  return (
    <Box sx={{ width: '100%', typography: 'body1' }}>
      <Typography variant="h4" gutterBottom>
        Admin Dashboard - Mr. Austin
      </Typography>
      <Tabs value={activeTab} onChange={handleTabChange} aria-label="Admin Dashboard Tabs">
        <Tab icon={<User />} label="Users" />
        <Tab icon={<Key />} label="Keys" />
        <Tab icon={<FileText />} label="Transactions" />
        <Tab icon={<BarChart2 />} label="Analytics" />
      </Tabs>
      <Box sx={{ mt: 3 }}>
        {activeTab === 0 && renderUsers()}
        {activeTab === 1 && renderKeys()}
        {activeTab === 2 && renderTransactions()}
        {activeTab === 3 && renderAnalytics()}
      </Box>
    </Box>
  );
};

export default AdminDashboard;
