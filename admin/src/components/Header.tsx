import { Button } from '@/components/ui/button';
import { useAuth } from '../context/AuthContext';

export const Header = () => {
  const { user, logout } = useAuth();

  return (
    <header className="border-b bg-card px-6 py-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Crypto Admin Dashboard</h1>
        <div className="flex items-center gap-4">
          <span className="text-sm text-muted-foreground">{user?.email}</span>
          <Button variant="outline" size="sm" onClick={logout}>
            Logout
          </Button>
        </div>
      </div>
    </header>
  );
};