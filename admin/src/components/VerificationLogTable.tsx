import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { mockData } from '../data/mockData';
import { format } from 'date-fns';

export const VerificationLogTable = () => {
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;
  
  const paginatedLogs = mockData.auditLogs.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );
  
  const totalPages = Math.ceil(mockData.auditLogs.length / itemsPerPage);
  
  const shortenKey = (key: string) => `${key.substring(0, 10)}...${key.substring(key.length - 6)}`;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Verification Logs</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left p-2">Timestamp</th>
                <th className="text-left p-2">Client Key</th>
                <th className="text-left p-2">Action</th>
                <th className="text-left p-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {paginatedLogs.map((log) => (
                <tr key={log.id} className="border-b">
                  <td className="p-2">{format(log.timestamp, 'MMM dd, HH:mm:ss')}</td>
                  <td className="p-2">
                    <code className="text-xs bg-muted px-1 py-0.5 rounded">
                      {shortenKey(log.clientPublicKey)}
                    </code>
                  </td>
                  <td className="p-2">{log.action}</td>
                  <td className="p-2">
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      log.status === 'success' 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-red-100 text-red-800'
                    }`}>
                      {log.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        <div className="flex items-center justify-between mt-4">
          <p className="text-sm text-muted-foreground">
            Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, mockData.auditLogs.length)} of {mockData.auditLogs.length} entries
          </p>
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="text-sm">{currentPage} of {totalPages}</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};