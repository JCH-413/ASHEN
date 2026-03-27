import { Link } from "react-router-dom";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";

const SignUp = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-accent-dark p-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div className="h-16 w-16 rounded-2xl bg-primary flex items-center justify-center mb-4">
            <Shield className="h-8 w-8 text-primary-foreground" />
          </div>
          <h1 className="text-2xl font-bold text-primary-foreground tracking-wider">ASHEN</h1>
          <p className="text-sm text-sidebar-foreground/60 mt-1">
            Account Registration
          </p>
        </div>

        <div className="bg-card rounded-xl p-8 shadow-2xl space-y-5 text-center">
          <p className="text-sm text-muted-foreground">
            New analyst accounts are created by an administrator from the
            <strong> User Management </strong> panel.
          </p>
          <p className="text-sm text-muted-foreground">
            Contact your administrator if you need access.
          </p>

          <Link to="/login">
            <Button variant="outline" className="w-full mt-4">
              Back to Sign In
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default SignUp;
