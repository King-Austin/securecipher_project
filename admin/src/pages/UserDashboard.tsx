// src/pages/UserDashboard.tsx
import React, { useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ClipboardCopy, ChevronDown, ChevronUp } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "../context/AuthContext";
import { cn } from "@/lib/utils"; // helper for conditional classes

// === Interfaces ===
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
  const [expandedUser, setExpandedUser] = useState<number | null>(null);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      if (isAuthenticated) {
        const dashboard = await fetchBankingDashboard();
        setData(dashboard);
      }
      setLoading(false);
    };
    loadData();
  }, [isAuthenticated, fetchBankingDashboard]);

  if (loading) return <p className="p-4 text-sm">Loading dashboard...</p>;
  if (!data) return <p className="p-4 text-red-500 text-sm">Failed to load data</p>;

  return (
    <div className="p-6 space-y-8">
      {/* === Global Stats === */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Object.entries(data.stats).map(([key, value]) => (
          <Card key={key} className="shadow-md">
            <CardContent className="p-3">
              <p className="text-xs text-muted-foreground capitalize">
                {key.replace(/_/g, " ")}
              </p>
              <p className="text-lg font-bold">{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* === User Profiles === */}
      <div className="space-y-6">
        {data.profiles.map((profile) => {
          const isExpanded = expandedUser === profile.user.id;

          return (
            <Card key={profile.user.id} className="shadow-md">
              <CardContent className="p-4 space-y-4">
                {/* User Info */}
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-bold">{profile.user.full_name}</h2>
                    <p className="text-xs text-muted-foreground">
                      {profile.user.account_number} • {profile.user.account_type}
                    </p>

                    {/* Public Key with Copy Button */}
                    <div className="flex items-center gap-2 mt-1">
                      <p className="text-xs font-mono text-muted-foreground">
                        ECDSA_Pub Key: <span className="font-bold">{shortenKey(profile.user.public_key)}</span>
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-6 w-6 p-0"
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(profile.user.public_key);
                            toast.success("Public key copied!");
                          } catch {
                            toast.error("Failed to copy key");
                          }
                        }}
                      >
                        <ClipboardCopy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>

                  <div className="text-right">
                    <p className="text-sm font-bold">
                      ₦{profile.user.balance.toLocaleString()}
                    </p>
                    <Badge
                      variant={profile.user.status === "ACTIVE" ? "default" : "secondary"}
                      className="text-xs"
                    >
                      {profile.user.status}
                    </Badge>
                  </div>
                </div>

                {/* Dropdown Transactions */}
                <div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="flex items-center gap-2 text-xs"
                    onClick={() =>
                      setExpandedUser(isExpanded ? null : profile.user.id)
                    }
                  >
                    {isExpanded ? "Hide Transactions" : "Show Recent Transactions"}
                    {isExpanded ? (
                      <ChevronUp className="h-3 w-3" />
                    ) : (
                      <ChevronDown className="h-3 w-3" />
                    )}
                  </Button>

                  {isExpanded && (
                    <div className="mt-2 space-y-1 max-h-48 overflow-y-auto">
                      {profile.recent_transactions.length > 0 ? (
                        profile.recent_transactions.map((txn) => (
                          <div
                            key={txn.id}
                            className={cn(
                              "flex items-center justify-between border rounded-md p-2 text-xs",
                              txn.transaction_type === "CREDIT"
                                ? "bg-green-50"
                                : "bg-red-50"
                            )}
                          >
                            <div>
                              <p className="font-bold">
                                {txn.transaction_type} • ₦
                                {parseFloat(txn.amount).toLocaleString()}
                              </p>
                              <p className="text-[11px] text-muted-foreground">
                                {txn.sender_name} - {txn.recipient_name}
                              </p>
                            </div>
                            <div className="text-[11px] text-muted-foreground">
                              {new Date(txn.created_at).toLocaleString()}
                            </div>
                          </div>
                        ))
                      ) : (
                        <p className="text-xs text-muted-foreground">
                          No recent transactions
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
};

export default UserDashboard;
