import { NavLink } from "react-router-dom";
import { 
  LayoutDashboard, 
  Key, 
  List, 
  Shield, 
  FileText, 
  User, 
  CreditCard, 
  Settings 
} from "lucide-react";

const middlewareNav = [
  { title: "Dashboard", url: "/dashboard", icon: LayoutDashboard },
  { title: "Key Management", url: "/dashboard/keys", icon: Key },
  { title: "Transactions", url: "/dashboard/transactions", icon: List },
  { title: "Logs", url: "/dashboard/logs", icon: FileText },
  { title: "Security", url: "/dashboard/security", icon: Shield },
];

const userNav = [
  { title: "User Profile", url: "/dashboard/user/profile", icon: User },
  { title: "Accounts", url: "/dashboard/user/accounts", icon: CreditCard },
  { title: "Settings", url: "/dashboard/user/settings", icon: Settings },
];

export const Sidebar = () => {
  return (
    <aside className="w-64 bg-card border-r min-h-screen">
      <nav className="px-4 py-8 space-y-6">
        {/* Middleware Section */}
        <div>
          <h2 className="px-3 mb-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Middleware
          </h2>
          <div className="space-y-1">
            {middlewareNav.map((item) => (
              <NavLink
                key={item.title}
                to={item.url}
                end={item.url === "/dashboard"}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                    isActive
                      ? "bg-primary text-primary-foreground"
                      : "hover:bg-muted text-muted-foreground hover:text-foreground"
                  }`
                }
              >
                <item.icon className="h-4 w-4" />
                {item.title}
              </NavLink>
            ))}
          </div>
        </div>

        {/* Banking/User Section */}
        <div>
          <h2 className="px-3 mb-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            BANK-USERS
          </h2>
          <div className="space-y-1">
            {userNav.map((item) => (
              <NavLink
                key={item.title}
                to={item.url}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                    isActive
                      ? "bg-primary text-primary-foreground"
                      : "hover:bg-muted text-muted-foreground hover:text-foreground"
                  }`
                }
              >
                <item.icon className="h-4 w-4" />
                {item.title}
              </NavLink>
            ))}
          </div>
        </div>
      </nav>
    </aside>
  );
};
