import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Settings as SettingsIcon, Save } from 'lucide-react';

const Settings = () => {
  return (
    <div className="space-y-6 max-w-5xl mx-auto px-4 py-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl md:text-3xl font-bold">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Configure system preferences and security policies
        </p>
      </div>

      {/* General Settings */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-lg">
            <SettingsIcon className="h-5 w-5" />
            General
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium">System Name</label>
              <Input defaultValue="SecureCipher Admin" />
            </div>
            <div>
              <label className="text-sm font-medium">Admin Email</label>
              <Input defaultValue="admin@securecypher.com" />
            </div>
          </div>

          <div>
            <label className="text-sm font-medium">Timezone</label>
            <Select defaultValue="utc">
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="utc">UTC</SelectItem>
                <SelectItem value="est">Eastern Time</SelectItem>
                <SelectItem value="pst">Pacific Time</SelectItem>
                <SelectItem value="cet">Central European Time</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Notifications */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-lg">Notifications</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {[
            {
              title: "Email Notifications",
              desc: "Receive alerts for important events",
              checked: true,
            },
            {
              title: "Failed Transaction Alerts",
              desc: "Warn if failure rate > 5%",
              checked: true,
            },
            {
              title: "Key Rotation Reminders",
              desc: "Notify 7 days before rotation",
              checked: true,
            },
          ].map((item, idx) => (
            <div key={idx} className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">{item.title}</p>
                <p className="text-xs text-muted-foreground">{item.desc}</p>
              </div>
              <Switch defaultChecked={item.checked} />
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Data Retention */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-lg">Data Retention</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-sm font-medium">Transactions (days)</label>
            <Input type="number" defaultValue="90" />
          </div>
          <div>
            <label className="text-sm font-medium">Audit Logs (days)</label>
            <Input type="number" defaultValue="365" />
          </div>
          <div>
            <label className="text-sm font-medium">Key History (days)</label>
            <Input type="number" defaultValue="730" />
          </div>
        </CardContent>
      </Card>

      {/* Maintenance */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-lg">System Maintenance</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Button variant="outline" className="w-full">
            Export Config
          </Button>
          <Button variant="outline" className="w-full">
            Import Config
          </Button>
          <Button variant="outline" className="w-full">
            Clear Cache
          </Button>
          <Button variant="destructive" className="w-full">
            Factory Reset
          </Button>
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button className="flex items-center gap-2">
          <Save className="h-4 w-4" />
          Save Settings
        </Button>
      </div>
    </div>
  );
};

export default Settings;
