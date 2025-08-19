import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Shield, AlertTriangle, CheckCircle, Lock } from 'lucide-react';

const Security = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security</h1>
        <p className="text-muted-foreground">Security settings and monitoring</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4">
            <div className="flex items-center justify-between p-3 bg-green-50 border border-green-200 rounded">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <span className="font-medium">SSL/TLS Certificate</span>
              </div>
              <span className="text-green-600 text-sm">Valid</span>
            </div>
            
            <div className="flex items-center justify-between p-3 bg-green-50 border border-green-200 rounded">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <span className="font-medium">Key Rotation</span>
              </div>
              <span className="text-green-600 text-sm">On Schedule</span>
            </div>
            

          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">

          
          <div className="flex items-center justify-between">
            <div>
              <label className="font-medium">Automatic Key Rotation</label>
              <p className="text-sm text-muted-foreground">Rotate keys every 30 days</p>
            </div>
            <Switch defaultChecked />
          </div>
          

          
          <div className="flex items-center justify-between">
            <div>
              <label className="font-medium">Audit Logging</label>
              <p className="text-sm text-muted-foreground">Log all security events</p>
            </div>
            <Switch defaultChecked />
          </div>
        </CardContent>
      </Card>


    </div>
  );
};

export default Security;