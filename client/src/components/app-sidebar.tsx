import { Home, ShoppingCart, Package, FileText, User, LogOut, Menu } from "lucide-react";
import { Link, useLocation } from "wouter";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
} from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

const menuItems = [
  {
    title: "Dashboard",
    url: "/dashboard",
    icon: Home,
  },
  {
    title: "Place Order",
    url: "/dashboard/order",
    icon: ShoppingCart,
  },
  {
    title: "My Orders",
    url: "/dashboard/orders",
    icon: Package,
  },
  {
    title: "Invoices",
    url: "/dashboard/invoices",
    icon: FileText,
  },
  {
    title: "My Profile",
    url: "/dashboard/profile",
    icon: User,
  },
];

export function AppSidebar() {
  const [location, setLocation] = useLocation();
  const { toast } = useToast();

  const logoutMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest("POST", "/api/logout", {});
    },
    onSuccess: () => {
      toast({
        title: "Logged Out",
        description: "You have been successfully logged out",
      });
      setLocation("/");
    },
  });

  return (
    <Sidebar>
      <SidebarHeader className="p-6 border-b border-sidebar-border">
        <Link href="/dashboard" className="flex items-center gap-2" data-testid="link-sidebar-logo">
          <div className="w-8 h-8 rounded-md bg-primary flex items-center justify-center">
            <span className="text-primary-foreground font-semibold text-sm">MFF</span>
          </div>
          <div>
            <h2 className="font-semibold text-sidebar-foreground">Manchester Fresh</h2>
            <p className="text-xs text-muted-foreground">Customer Portal</p>
          </div>
        </Link>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Menu</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {menuItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton 
                    asChild 
                    isActive={location === item.url}
                    data-testid={`link-sidebar-${item.title.toLowerCase().replace(/\s+/g, '-')}`}
                  >
                    <Link href={item.url}>
                      <item.icon className="w-4 h-4" />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="p-4 border-t border-sidebar-border">
        <Button
          variant="ghost"
          className="w-full justify-start"
          onClick={() => logoutMutation.mutate()}
          disabled={logoutMutation.isPending}
          data-testid="button-sidebar-logout"
        >
          <LogOut className="w-4 h-4 mr-2" />
          {logoutMutation.isPending ? "Logging out..." : "Logout"}
        </Button>
      </SidebarFooter>
    </Sidebar>
  );
}
