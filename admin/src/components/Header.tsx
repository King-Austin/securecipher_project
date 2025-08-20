import { Button } from '@/components/ui/button';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, Bell } from 'lucide-react';

export const Header = () => {
  const { user, logout } = useAuth();

  return (
    <header className="border-b bg-card px-4 py-3 md:px-6">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        {/* Left Section: Title */}
        <h1 className="text-lg md:text-xl flex items-center font-bold text-blue-800">
          SECURECIPHER
        </h1>

        {/* Right Section: Actions */}
        <div className="flex  justify-end gap-4">
          
          {/* Secure Status */}
          <div className="flex items-center gap-1 text-sm text-green-600">
            <ShieldCheck className="h-4 w-4" />
            <span>Secure</span>
          </div>



          {/* Logout Button */}
          <Button
            variant="destructive"
            size="sm"
            className="whitespace-nowrap px-4 py-2 font-bold rounded-lg shadow-md bg-red-600 text-white hover:bg-red-700 focus:ring-2 focus:ring-red-400"
            onClick={logout}
          >
            Logout
          </Button>
        </div>
      </div>
    </header>
  );
};
