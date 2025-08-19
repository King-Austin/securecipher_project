import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ChevronLeft, ChevronRight, Search, Download, ChevronDown, ChevronUp } from 'lucide-react';
import { format } from 'date-fns';

interface AuditLog {
  id: string;
  transaction_id: string;
  event_type: string;
  actor: string;
  timestamp: string;
  prev_hash: string;
  record_hash: string;
  details?: Record<string, any>;
}

const Logs = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const itemsPerPage = 10;

  useEffect(() => {
    const storedLogs = localStorage.getItem('dashboardData');
    if (storedLogs) {
      const parsed = JSON.parse(storedLogs);
      if (Array.isArray(parsed.audit_logs)) {
        setLogs(parsed.audit_logs);
      }
    }
  }, []);

  const filteredLogs = logs.filter(log =>
    log.transaction_id.includes(searchTerm) ||
    log.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.actor.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const paginatedLogs = filteredLogs.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage);

  const toggleExpand = (id: string) => {
    setExpanded(prev => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Audit Logs</h1>
        <p className="text-muted-foreground">System audit and activity logs</p>
      </div>

      <Card>
        <CardHeader className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <CardTitle>Activity Log</CardTitle>
          <div className="flex flex-col sm:flex-row gap-4 flex-1">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8"
              />
            </div>
            <Button variant="outline" className="flex items-center gap-2">
              <Download className="h-4 w-4" />
              Export
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {paginatedLogs.map(log => (
              <div key={log.id} className="border rounded-lg shadow-sm p-4 hover:bg-muted/50 transition">
                <div className="flex justify-between items-start">
                  <div className="space-y-1">
                    <p className="text-sm text-muted-foreground">{format(new Date(log.timestamp), 'MMM dd, yyyy HH:mm:ss')}</p>
                    <p className="font-mono text-xs break-all">Transaction: {log.transaction_id}</p>
                    <p className="font-semibold">{log.event_type}</p>
                    <p className="text-sm">Actor: {log.actor}</p>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => toggleExpand(log.id)}>
                    {expanded[log.id] ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </Button>
                </div>
                {expanded[log.id] && (
                  <div className="mt-2 text-xs bg-muted/10 rounded p-2 font-mono space-y-1 overflow-x-auto">
                    <p>Prev Hash: <code>{log.prev_hash}</code></p>
                    <p>Record Hash: <code>{log.record_hash}</code></p>
                    {log.details && <pre>{JSON.stringify(log.details, null, 2)}</pre>}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <p className="text-sm text-muted-foreground">
              Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, filteredLogs.length)} of {filteredLogs.length} entries
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
    </div>
  );
};

export default Logs;
