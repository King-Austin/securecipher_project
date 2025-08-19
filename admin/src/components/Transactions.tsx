// Transactions.tsx (compact details view)
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ChevronLeft, ChevronRight, Search, RefreshCw, Copy, X, ChevronDown, ChevronUp } from "lucide-react";
import { format, parseISO } from "date-fns";
import { toast } from "sonner";

type Transaction = Record<string, any>;
const ITEMS_PER_PAGE_DEFAULT = 20;

const shorten = (s?: string, head = 14, tail = 6) => {
  if (!s) return "—";
  return s.length > head + tail ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
};

const formatTimestamp = (iso?: string) => {
  if (!iso) return "—";
  try {
    const d = parseISO(iso);
    if (isNaN(d.getTime())) return iso;
    return format(d, "MMM dd, yyyy HH:mm:ss");
  } catch {
    return iso;
  }
};

const computeStatus = (t: Transaction) => {
  const sig = t.client_signature_verified;
  const status = t.status_code;
  if (sig === true && (status === 200 || status === "200")) return "success";
  if (sig === false) return "failed";
  if (typeof status === "number" && status !== 200) return "failed";
  return "unknown";
};

export default function Transactions() {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(ITEMS_PER_PAGE_DEFAULT);
  const [loading, setLoading] = useState(false);

  // detail view state (compact)
  const [selectedTx, setSelectedTx] = useState<Transaction | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [expandedFields, setExpandedFields] = useState<Record<string, boolean>>({});
  const [showFullJson, setShowFullJson] = useState(false);

  const loadFromLocalStorage = useCallback(() => {
    setLoading(true);
    try {
      const raw = localStorage.getItem("dashboardData");
      if (!raw) {
        setTransactions([]);
        setLoading(false);
        return;
      }
      const parsed = JSON.parse(raw);
      const txs: Transaction[] = parsed.transactions || [];
      txs.sort((a: Transaction, b: Transaction) => {
        const at = a.created_at ? Date.parse(a.created_at) : 0;
        const bt = b.created_at ? Date.parse(b.created_at) : 0;
        return bt - at;
      });
      setTransactions(txs);
    } catch (err) {
      console.error("Failed to load dashboardData:", err);
      setTransactions([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadFromLocalStorage();
  }, [loadFromLocalStorage]);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === "dashboardData") {
        loadFromLocalStorage();
        toast("Local cache updated");
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [loadFromLocalStorage]);

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return transactions;
    return transactions.filter((t) => {
      const keyFields = [
        t.transaction_id,
        t.session_key_hash,
        t.client_ip,
        t.middleware_signature,
      ];
      if (keyFields.some((f) => f && String(f).toLowerCase().includes(q))) return true;
      return Object.values(t).some((v) => typeof v === "string" && v.toLowerCase().includes(q));
    });
  }, [searchTerm, transactions]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / itemsPerPage));
  useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(totalPages);
  }, [currentPage, totalPages]);

  const currentSlice = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filtered.slice(start, start + itemsPerPage);
  }, [filtered, currentPage, itemsPerPage]);

  const openDrawerWith = (tx: Transaction) => {
    setSelectedTx(tx);
    setDrawerOpen(true);
    setExpandedFields({});
    setShowFullJson(false);
  };
  const closeDrawer = () => {
    setDrawerOpen(false);
    setTimeout(() => setSelectedTx(null), 140);
  };

  const copyText = async (text?: string, label = "Copied") => {
    if (!text) {
      toast.error("Nothing to copy");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      toast.success(label);
    } catch (err) {
      console.error("Copy failed", err);
      toast.error("Copy failed");
    }
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && drawerOpen) closeDrawer();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

  const toggleField = (k: string) => {
    setExpandedFields((s) => ({ ...s, [k]: !s[k] }));
  };

  // compact field row renderer
  const FieldRow: React.FC<{ k: string; v: any }> = ({ k, v }) => {
    const isExpanded = !!expandedFields[k];
    const pretty = (typeof v === "object" && v !== null) ? JSON.stringify(v, null, 2) : String(v ?? "—");
    const display = (() => {
      if (v === null || typeof v === "undefined") return "—";
      if (typeof v === "string") {
        // try timestamp formatting
        if (/(created_at|timestamp|rotated_at|time)/i.test(k)) {
          try {
            const d = parseISO(v);
            if (!isNaN(d.getTime())) return format(d, "MMM dd, yyyy HH:mm:ss");
          } catch {}
        }
        return isExpanded ? v : (v.length > 80 ? `${v.slice(0, 80)}…` : v);
      }
      if (typeof v === "number" || typeof v === "boolean") return String(v);
      // object/array
      return isExpanded ? pretty : shorten(pretty.replace(/\s+/g, " "), 60, 12);
    })();

    return (
      <div className="flex items-start justify-between gap-3 py-2">
        <div className="flex-1 min-w-0">
          <div className="text-xs text-muted-foreground">{k}</div>
          <div className="mt-1 text-sm font-mono whitespace-pre-wrap overflow-hidden truncate">{display}</div>
        </div>

        <div className="flex-shrink-0 flex flex-col gap-2">
          <button
            className="text-muted-foreground hover:text-foreground p-1"
            onClick={() => copyText(typeof v === "object" ? pretty : String(v), `Copied ${k}`)}
            aria-label={`Copy ${k}`}
            title="Copy"
          >
            <Copy className="h-4 w-4" />
          </button>

          <button
            className="text-muted-foreground hover:text-foreground p-1"
            onClick={() => toggleField(k)}
            aria-label={isExpanded ? `Collapse ${k}` : `Expand ${k}`}
            title={isExpanded ? "Collapse" : "Expand"}
          >
            {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Transactions</h1>
        <p className="text-sm text-muted-foreground">Click a row to open a compact detail view (copy & expand fields).</p>
      </div>

      <Card>
        <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex items-center gap-3 w-full">
            <CardTitle className="!mb-0">Transaction Log</CardTitle>

            <div className="relative flex-1 max-w-lg">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search id / session key / client ip / signature..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-10 w-full"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={loadFromLocalStorage} disabled={loading}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </CardHeader>

        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left p-2">Timestamp</th>
                  <th className="text-left p-2">Transaction ID</th>
                  <th className="text-left p-2">Client IP</th>
                  <th className="text-left p-2">Session Key</th>
                  <th className="text-left p-2">Status</th>
                  <th className="text-right p-2">Processing</th>
                </tr>
              </thead>
              <tbody>
                {currentSlice.length === 0 ? (
                  <tr><td colSpan={6} className="p-4 text-center text-sm text-muted-foreground">{loading ? "Loading..." : "No transactions in local cache."}</td></tr>
                ) : (
                  currentSlice.map((tx, idx) => {
                    const status = computeStatus(tx);
                    const processing = typeof tx.processing_time_ms === "number" ? `${Math.round(tx.processing_time_ms)} ms` : "—";
                    return (
                      <tr
                        key={tx.id ?? `${tx.transaction_id ?? idx}-${idx}`}
                        className="border-b hover:bg-muted/50 cursor-pointer"
                        onClick={() => openDrawerWith(tx)}
                        title="Click to open detail view"
                      >
                        <td className="p-2">{formatTimestamp(tx.created_at)}</td>
                        <td className="p-2 break-all">{tx.transaction_id ?? "—"}</td>
                        <td className="p-2">{tx.client_ip ?? "—"}</td>
                        <td className="p-2">
                          <code className="text-xs bg-muted px-1 py-0.5 rounded">{shorten(tx.session_key_hash)}</code>
                        </td>
                        <td className="p-2">
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            status === "success" ? "bg-green-100 text-green-800" :
                            status === "failed" ? "bg-red-100 text-red-800" : "bg-yellow-100 text-yellow-800"
                          }`}>{status}</span>
                        </td>
                        <td className="p-2 text-right">{processing}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <p className="text-sm text-muted-foreground">
              Showing {(currentPage - 1) * itemsPerPage + (currentSlice.length ? 1 : 0)} to {Math.min(currentPage * itemsPerPage, filtered.length)} of {filtered.length} entries
            </p>

            <div className="flex items-center space-x-2">
              <Button variant="outline" size="sm" onClick={() => setCurrentPage((p) => Math.max(1, p - 1))} disabled={currentPage === 1}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm">{currentPage} of {totalPages}</span>
              <Button variant="outline" size="sm" onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Compact Detail Drawer */}
      {drawerOpen && selectedTx && (
        <>
          <div className="fixed inset-0 bg-black/40 z-40" onClick={closeDrawer} aria-hidden />
          <aside
            role="dialog"
            aria-label="Transaction details"
            className="fixed right-0 top-0 h-full w-full sm:w-[640px] bg-background z-50 shadow-2xl p-4 sm:p-6 overflow-auto"
          >
            <div className="flex items-start justify-between gap-3 mb-3">
              <div>
                <h2 className="text-lg font-semibold">Transaction details</h2>
                <p className="text-xs text-muted-foreground">Compact view — expand fields as needed</p>
              </div>

              <div className="flex items-center gap-2">
                <Button size="sm" variant="ghost" onClick={() => copyText(JSON.stringify(selectedTx, null, 2), "Full transaction JSON copied")}>
                  <Copy className="h-4 w-4" />
                </Button>
                <Button size="sm" variant="outline" onClick={closeDrawer}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3">
              {/* Top row summary - very compact */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-muted/10 p-2 rounded text-xs">
                  <div className="text-xxs text-muted-foreground">Transaction ID</div>
                  <div className="mt-1 text-sm break-all">{selectedTx.transaction_id ?? "—"}</div>
                </div>
                <div className="bg-muted/10 p-2 rounded text-xs">
                  <div className="text-xxs text-muted-foreground">Timestamp</div>
                  <div className="mt-1 text-sm">{formatTimestamp(selectedTx.created_at)}</div>
                </div>

                <div className="bg-muted/10 p-2 rounded text-xs">
                  <div className="text-xxs text-muted-foreground">Client IP</div>
                  <div className="mt-1 text-sm">{selectedTx.client_ip ?? "—"}</div>
                </div>
                <div className="bg-muted/10 p-2 rounded text-xs">
                  <div className="text-xxs text-muted-foreground">Status</div>
                  <div className="mt-1 text-sm">{selectedTx.status_code ?? "—"}</div>
                </div>
              </div>

              {/* Fields list (compact) */}
              <Card>
                <CardContent className="p-3">
                  <div className="space-y-2">
                    {Object.keys(selectedTx).map((k) => (
                      <FieldRow key={k} k={k} v={selectedTx[k]} />
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Full JSON toggle — hidden by default */}
              <div className="flex items-center justify-between">
                <div className="text-xs text-muted-foreground">Full JSON (hidden by default)</div>
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="ghost" onClick={() => setShowFullJson((s) => !s)}>
                    {showFullJson ? "Hide JSON" : "Show JSON"}
                  </Button>
                </div>
              </div>

              {showFullJson && (
                <Card>
                  <CardContent>
                    <pre className="text-xs bg-black/5 p-3 rounded overflow-auto" style={{ maxHeight: 360 }}>
                      {JSON.stringify(selectedTx, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              )}
            </div>
          </aside>
        </>
      )}
    </div>
  );
}
