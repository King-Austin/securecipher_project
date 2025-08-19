import { NavLink, useLocation } from 'react-router-dom';
import { LayoutDashboard, Key, List, BarChart3, Shield, Settings, FileText } from 'lucide-react';

const navigationItems = [
  { title: 'Dashboard', url: '/crypto-admin', icon: LayoutDashboard },
  { title: 'Key Management', url: '/crypto-admin/keys', icon: Key },
  { title: 'Transactions', url: '/crypto-admin/transactions', icon: List },
  { title: 'Logs', url: '/crypto-admin/logs', icon: FileText },
  { title: 'Security', url: '/crypto-admin/security', icon: Shield },
];

export const Sidebar = () => {
  const location = useLocation();
  const isActive = (path: string) => location.pathname === path;

  return (
    <aside className="w-64 bg-card border-r">
      <div className="p-6">
        <h2 className="text-lg font-semibold">SecureCipher</h2>
      </div>
      <nav className="px-4 space-y-2">
        {navigationItems.map((item) => (
          <NavLink
            key={item.title}
            to={item.url}
            end={item.url === '/crypto-admin'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                isActive 
                  ? 'bg-primary text-primary-foreground' 
                  : 'hover:bg-muted text-muted-foreground hover:text-foreground'
              }`
            }
          >
            <item.icon className="h-4 w-4" />
            {item.title}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
};