import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { PublicHeader } from "@/components/public-header";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
import Products from "@/pages/products";
import Contact from "@/pages/contact";
import Login from "@/pages/login";
import Register from "@/pages/register";
import Dashboard from "@/pages/dashboard/dashboard";
import PlaceOrder from "@/pages/dashboard/place-order";
import Orders from "@/pages/dashboard/orders";
import Invoices from "@/pages/dashboard/invoices";
import Profile from "@/pages/dashboard/profile";
import InstructorDocs from "@/pages/instructor-docs";

function PublicRouter() {
  return (
    <div className="min-h-screen">
      <PublicHeader />
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/products" component={Products} />
        <Route path="/contact" component={Contact} />
        <Route path="/login" component={Login} />
        <Route path="/register" component={Register} />
        <Route path="/instructor" component={InstructorDocs} />
        <Route component={NotFound} />
      </Switch>
    </div>
  );
}

function DashboardRouter() {
  const style = {
    "--sidebar-width": "20rem",
    "--sidebar-width-icon": "4rem",
  };

  return (
    <SidebarProvider style={style as React.CSSProperties}>
      <div className="flex h-screen w-full">
        <AppSidebar />
        <div className="flex flex-col flex-1">
          <header className="flex items-center justify-between p-4 border-b border-border">
            <SidebarTrigger data-testid="button-sidebar-toggle" />
            <div className="flex items-center gap-4">
              <span className="text-sm text-muted-foreground">Customer Portal</span>
            </div>
          </header>
          <main className="flex-1 overflow-auto p-8">
            <Switch>
              <Route path="/dashboard" component={Dashboard} />
              <Route path="/dashboard/order" component={PlaceOrder} />
              <Route path="/dashboard/orders" component={Orders} />
              <Route path="/dashboard/invoices" component={Invoices} />
              <Route path="/dashboard/profile" component={Profile} />
              <Route component={NotFound} />
            </Switch>
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}

function Router() {
  return (
    <Switch>
      <Route path="/dashboard" nest>
        <DashboardRouter />
      </Route>
      <Route>
        <PublicRouter />
      </Route>
    </Switch>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Router />
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}
