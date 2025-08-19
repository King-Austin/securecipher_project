import { useEffect, useState, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Key, RotateCcw, ClipboardCopy, History } from "lucide-react";
import { format, parseISO } from "date-fns";
import { toast } from "sonner";

// Utilities
const cleanPemToSingleLine = (pem?: string) =>
  (pem || "")
    .replace(/-----BEGIN PUBLIC KEY-----/gi, "")
    .replace(/-----END PUBLIC KEY-----/gi, "")
    .replace(/\s+/g, "")
    .trim();

const shorten = (s?: string, head = 36, tail = 20) => {
  if (!s) return "—";
  return s.length > head + tail ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
};

// Types
type MiddlewareKey = {
  id: string;
  label?: string;
  public_key_pem?: string;
  active?: boolean;
  version?: number;
  created_at?: string;
  rotated_at?: string | null;
};

type KeyRotation = {
  id: string;
  old_key?: string;
  new_key?: string;
  reason?: string;
  rotated_at?: string;
};

const KeyManagement = () => {
  const { rotateKey } = useAuth(); // Get rotateKey from AuthContext
  const [keys, setKeys] = useState<MiddlewareKey[]>([]);
  const [rotations, setRotations] = useState<KeyRotation[]>([]);
  const [rotating, setRotating] = useState(false);
  const [rotateReason, setRotateReason] = useState("");
  const [activeRotateId, setActiveRotateId] = useState<string | null>(null);

  // Fetch data from localStorage
  const refreshFromLocalStorage = useCallback(() => {
    const raw = localStorage.getItem("dashboardData");
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw);
      const mk: MiddlewareKey[] = parsed.middleware_keys || [];
      const kr: KeyRotation[] = parsed.key_rotations || [];

      mk.sort((a, b) =>
        a.active === b.active ? (b.version ?? 0) - (a.version ?? 0) : a.active ? -1 : 1
      );

      kr.sort((a, b) => (b.rotated_at ? Date.parse(b.rotated_at) : 0) - (a.rotated_at ? Date.parse(a.rotated_at) : 0));

      setKeys(mk);
      setRotations(kr);
    } catch (err) {
      console.error(err);
      setKeys([]);
      setRotations([]);
    }
  }, []);

  useEffect(() => refreshFromLocalStorage(), [refreshFromLocalStorage]);

  const onCopy = async (pem?: string) => {
    try {
      const cleaned = cleanPemToSingleLine(pem);
      if (!cleaned) return toast.error("No key to copy");
      await navigator.clipboard.writeText(cleaned);
      toast.success("Public key copied");
    } catch {
      toast.error("Copy failed");
    }
  };

  const onRotate = async (keyId: string, reason: string) => {
    if (!reason.trim()) return toast.error("Rotation reason is required");
    if (rotating) return;
    setRotating(true);
    try {
      const dashboard = await rotateKey(reason); // Call centralized rotateKey from AuthContext
      if (!dashboard) throw new Error("Rotation failed or no dashboard data returned");

      // After rotation, refresh state from localStorage
      refreshFromLocalStorage();
      toast.success("Key rotated successfully");
    } catch (err) {
      console.error(err);
      toast.error("Rotation failed — see console");
    } finally {
      setRotating(false);
      setActiveRotateId(null);
      setRotateReason("");
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Key Management</h1>
        <p className="text-muted-foreground">Middleware public keys (SECP384R1)</p>
      </div>

      {/* Key Cards */}
      <div className="grid gap-4">
        {keys.map((k) => {
          const cleaned = cleanPemToSingleLine(k.public_key_pem);
          return (
            <Card key={k.id}>
              <CardHeader>
                <CardTitle className="flex items-center gap-3">
                  <Key className="h-5 w-5" />
                  <span className="flex-1">Version {k.version ?? "—"}</span>
                  {k.active ? (
                    <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">ACTIVE</span>
                  ) : (
                    <span className="bg-muted/20 text-muted-foreground text-xs px-2 py-1 rounded-full">inactive</span>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <code className="text-xs bg-muted p-2 rounded break-all flex-1">{shorten(cleaned)}</code>
                  <Button size="sm" variant="outline" onClick={() => onCopy(k.public_key_pem)}>
                    <ClipboardCopy className="h-4 w-4" /> Copy
                  </Button>
                </div>

                {k.active && (
                  <div className="pt-2 space-y-2">
                    {activeRotateId === k.id ? (
                      <div className="flex gap-2 items-center">
                        <input
                          type="text"
                          placeholder="Enter rotation reason"
                          value={rotateReason}
                          onChange={(e) => setRotateReason(e.target.value)}
                          className="flex-1 border rounded px-2 py-1 text-sm"
                        />
                        <Button size="sm" onClick={() => onRotate(k.id, rotateReason)} disabled={rotating || !rotateReason.trim()}>
                          <RotateCcw className="h-4 w-4" /> {rotating ? "Rotating…" : "Confirm"}
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setActiveRotateId(null)}>
                          Cancel
                        </Button>
                      </div>
                    ) : (
                      <Button size="sm" onClick={() => setActiveRotateId(k.id)}>
                        <RotateCcw className="h-4 w-4" /> Rotate Key
                      </Button>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Rotation History Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="h-5 w-5" />
            Rotation History
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {rotations.length === 0 ? (
            <p className="text-sm text-muted-foreground">No rotation history available.</p>
          ) : (
            rotations.map((r) => {
              const ts = r.rotated_at
                ? format(parseISO(r.rotated_at), "MMM dd, yyyy, HH:mm:ss")
                : "—";
              const detail = `${r.old_key ?? "unknown"} → ${r.new_key ?? "unknown"}${
                r.reason ? ` (${r.reason})` : ""
              }`;
              return (
                <div key={r.id} className="py-2 border-b last:border-0">
                  <div className="text-sm font-medium">{ts}</div>
                  <div className="text-xs text-muted-foreground mt-1">{detail}</div>
                </div>
              );
            })
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default KeyManagement;
