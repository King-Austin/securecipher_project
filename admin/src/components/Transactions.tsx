// Transactions.tsx
import React, { useContext } from "react";
import { useAuth } from "../context/AuthContext";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function Transactions() {
  const { dashboardData } = useAuth();

  // Transactions come from AuthContext state
  const transactions = dashboardData?.transactions || [];

  return (
    <div className="p-6">
      <Card className="shadow-lg rounded-2xl">
        <CardHeader>
          <CardTitle className="text-xl font-bold">Transactions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto  scrollbar-track-gray-100">
            <Table className="min-w-full">
              <TableHeader>
                <TableRow>
                  <TableHead>Txn ID</TableHead>
                  <TableHead>Client IP</TableHead>
                  <TableHead>Created At</TableHead>
                  <TableHead>Processing Time (ms)</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Payload Size (bytes)</TableHead>
                  <TableHead>Session Key Hash</TableHead>
                  <TableHead>Client Sig Verified</TableHead>
                  <TableHead>Middleware Signature</TableHead>
                  <TableHead>Status Code</TableHead>
                  <TableHead>Response Size (bytes)</TableHead>
                  <TableHead>Decryption (ms)</TableHead>
                  <TableHead>Encryption (ms)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {transactions.length > 0 ? (
                  transactions.map((tx: any) => (
                    <TableRow key={tx.id}>
                      <TableCell>{tx.transaction_id}</TableCell>
                      <TableCell>{tx.client_ip}</TableCell>
                      <TableCell>{new Date(tx.created_at).toLocaleString()}</TableCell>
                      <TableCell>
                        {tx.processing_time_ms != null ? Number(tx.processing_time_ms).toFixed(2) : "N/A"}
                      </TableCell>
                      <TableCell>{tx.banking_route}</TableCell>
                      <TableCell>{tx.payload_size_bytes}</TableCell>
                      <TableCell className="truncate max-w-xs">{tx.session_key_hash}</TableCell>
                      <TableCell>{tx.client_signature_verified ? "✅" : "❌ No"}</TableCell>
                      <TableCell className="truncate max-w-xs">{tx.middleware_signature}</TableCell>
                      <TableCell>{tx.status_code}</TableCell>
                      <TableCell>{tx.response_size_bytes}</TableCell>
                      <TableCell>
                        {tx.decryption_time_ms != null ? Number(tx.decryption_time_ms).toFixed(2) : "N/A"}
                      </TableCell>
                      <TableCell>
                        {tx.encryption_time_ms != null ? Number(tx.encryption_time_ms).toFixed(2) : "N/A"}
                      </TableCell>

                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={13} className="text-center">
                      No transactions found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
