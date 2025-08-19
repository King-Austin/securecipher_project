import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Shield, Lock, Key } from 'lucide-react';

const Index = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center max-w-2xl mx-auto p-8">
        <div className="flex justify-center mb-6">
          <div className="p-4 bg-primary/10 rounded-full">
            <Shield className="h-16 w-16 text-primary" />
          </div>
        </div>
        <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
          SecureCipher
        </h1>
        <p className="text-xl text-muted-foreground mb-8">
          Advanced cryptographic security platform with comprehensive transaction monitoring and key management.
        </p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
          <Link to="/crypto-admin">
            <Button size="lg" className="flex items-center gap-2">
              <Lock className="h-5 w-5" />
              Access Admin Dashboard
            </Button>
          </Link>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Key className="h-4 w-4" />
            Secure cryptographic operations
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
