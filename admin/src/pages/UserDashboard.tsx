// src/pages/UserDashboard.tsx
import React, { useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ClipboardCopy } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "../context/AuthContext";  // ✅ use context

interface Stats {
  total_users: number;
  active_users: number;
  total_balance: number;
  total_transactions: number;
  total_credits: number;
  total_debits: number;
  completed_transactions: number;
  failed_transactions: number;
}

interface Transaction {
  id: string;
  transaction_type: "CREDIT" | "DEBIT";
  amount: string;
  description: string;
  status: string;
  reference_number: string;
  created_at: string;
  balance_before: string;
  balance_after: string;
  recipient_account_number: string;
  recipient_name: string;
  sender_account_number: string;
  sender_name: string;
}

interface UserProfile {
  user: {
    id: number;
    username: string;
    full_name: string;
    account_number: string;
    account_type: string;
    status: string;
    balance: number;
    created_at: string;
    is_verified: boolean;
    public_key: string;
  };
  recent_transactions: Transaction[];
}

interface DashboardResponse {
  stats: Stats;
  profiles: UserProfile[];
}

// === Utility: shorten long public keys ===
const shortenKey = (key: string, front: number = 10, back: number = 10) => {
  if (!key) return "";
  if (key.length <= front + back) return key;
  return `${key.slice(0, front)}...${key.slice(-back)}`;
};

const UserDashboard: React.FC = () => {
  const { fetchBankingDashboard, isAuthenticated } = useAuth();
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);



      // ✅ Fetch only via AuthContext
      if (isAuthenticated) {
        const dashboard = await fetchBankingDashboard();
        setData(dashboard);
      }
      setLoading(false);
    };

    loadData();
  }, [isAuthenticated, fetchBankingDashboard]);

  if (loading) return <p className="p-4">Loading dashboard...</p>;
  if (!data) return <p className="p-4 text-red-500">Failed to load data</p>;

  return (
    <div className="p-6 space-y-8">
      {/* === Global Stats === */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Object.entries(data.stats).map(([key, value]) => (
          <Card key={key} className="shadow-md">
            <CardContent className="p-4">
              <p className="text-sm text-muted-foreground capitalize">
                {key.replace(/_/g, " ")}
              </p>
              <p className="text-xl font-bold">{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* === User Profiles === */}
      <div className="space-y-6">
        {data.profiles.map((profile) => (
          <Card key={profile.user.id} className="shadow-md">
            <CardContent className="p-4 space-y-4">
              {/* User Info */}
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-semibold">{profile.user.full_name}</h2>
                  <p className="text-sm text-muted-foreground">
                    {profile.user.account_number} • {profile.user.account_type}
                  </p>

                  {/* Public Key with Copy Button */}
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-mono text-muted-foreground">
                      ECDSA Pub_key: {shortenKey(profile.user.public_key)}
                    </p>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={async () => {
                        try {
                          await navigator.clipboard.writeText(profile.user.public_key);
                          toast.success("Public key copied!");
                        } catch {
                          toast.error("Failed to copy key");
                        }
                      }}
                    >
                      <ClipboardCopy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                <div className="text-right">
                  <p className="text-xl font-bold">
                    ₦{profile.user.balance.toLocaleString()}
                  </p>
                  <Badge
                    variant={profile.user.status === "ACTIVE" ? "default" : "secondary"}
                  >
                    {profile.user.status}
                  </Badge>
                </div>
              </div>

              {/* Recent Transactions */}
              <div>
                <h3 className="font-medium mb-2">Recent Transactions</h3>
                <div className="space-y-2">
                  {profile.recent_transactions.length > 0 ? (
                    profile.recent_transactions.map((txn) => (
                      <div
                        key={txn.id}
                        className="flex items-center justify-between border p-2 rounded-md"
                      >
                        <div>
                          <p className="text-sm font-medium">
                            {txn.transaction_type} • ₦
                            {parseFloat(txn.amount).toLocaleString()}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {txn.description}
                          </p>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {new Date(txn.created_at).toLocaleString()}
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      No recent transactions
                    </p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default UserDashboard;
