import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Package, ShoppingCart, FileText, TrendingUp } from "lucide-react";
import { Link } from "wouter";
import { type Order, type User } from "@shared/schema";
import { Skeleton } from "@/components/ui/skeleton";

export default function Dashboard() {
  const { data: user, isLoading: userLoading } = useQuery<User>({
    queryKey: ["/api/user"],
  });

  const { data: orders, isLoading: ordersLoading } = useQuery<Order[]>({
    queryKey: ["/api/orders"],
  });

  const recentOrders = orders?.slice(0, 5) || [];
  const pendingOrders = orders?.filter(o => o.status === "pending").length || 0;
  const totalOrders = orders?.length || 0;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-semibold text-foreground mb-2">
          {userLoading ? (
            <Skeleton className="h-9 w-64" />
          ) : (
            `Welcome back, ${user?.companyName || user?.username || "Customer"}`
          )}
        </h1>
        <p className="text-muted-foreground">
          Manage your orders and account from your dashboard
        </p>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card data-testid="card-stat-total-orders">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Orders</CardTitle>
            <Package className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {ordersLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-semibold">{totalOrders}</div>
            )}
          </CardContent>
        </Card>

        <Card data-testid="card-stat-pending">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Orders</CardTitle>
            <ShoppingCart className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {ordersLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-semibold">{pendingOrders}</div>
            )}
          </CardContent>
        </Card>

        <Card data-testid="card-stat-this-month">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">This Month</CardTitle>
            <TrendingUp className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {ordersLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-semibold">
                {orders?.filter(o => {
                  const orderDate = new Date(o.createdAt);
                  const now = new Date();
                  return orderDate.getMonth() === now.getMonth() && 
                         orderDate.getFullYear() === now.getFullYear();
                }).length || 0}
              </div>
            )}
          </CardContent>
        </Card>

        <Card data-testid="card-stat-invoices">
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Invoices</CardTitle>
            <FileText className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {ordersLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-semibold">
                {orders?.filter(o => o.status === "delivered").length || 0}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Recent Orders</CardTitle>
            <CardDescription>Your latest orders and their status</CardDescription>
          </CardHeader>
          <CardContent>
            {ordersLoading ? (
              <div className="space-y-4">
                {[...Array(3)].map((_, i) => (
                  <Skeleton key={i} className="h-16 w-full" />
                ))}
              </div>
            ) : recentOrders.length > 0 ? (
              <div className="space-y-4">
                {recentOrders.map((order) => (
                  <div 
                    key={order.id} 
                    className="flex items-center justify-between p-4 border border-border rounded-md hover-elevate"
                    data-testid={`order-item-${order.id}`}
                  >
                    <div className="flex-1">
                      <p className="font-medium text-foreground">Order #{order.orderNumber}</p>
                      <p className="text-sm text-muted-foreground">
                        {new Date(order.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-4">
                      <p className="font-semibold text-foreground">
                        £{Number(order.totalAmount).toFixed(2)}
                      </p>
                      <Badge 
                        variant={
                          order.status === "delivered" ? "default" :
                          order.status === "confirmed" ? "secondary" :
                          order.status === "cancelled" ? "destructive" :
                          "outline"
                        }
                        data-testid={`badge-status-${order.id}`}
                      >
                        {order.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground text-center py-8">
                No orders yet. Start by placing your first order!
              </p>
            )}
            {!ordersLoading && recentOrders.length > 0 && (
              <div className="mt-6">
                <Link href="/dashboard/orders">
                  <Button variant="outline" className="w-full" data-testid="button-view-all-orders">
                    View All Orders
                  </Button>
                </Link>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Manage your account and orders</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Link href="/dashboard/order">
              <Button className="w-full justify-start" data-testid="button-quick-new-order">
                <ShoppingCart className="w-4 h-4 mr-2" />
                Place New Order
              </Button>
            </Link>
            <Link href="/dashboard/orders">
              <Button variant="outline" className="w-full justify-start" data-testid="button-quick-track-orders">
                <Package className="w-4 h-4 mr-2" />
                Track Orders
              </Button>
            </Link>
            <Link href="/dashboard/invoices">
              <Button variant="outline" className="w-full justify-start" data-testid="button-quick-view-invoices">
                <FileText className="w-4 h-4 mr-2" />
                View Invoices
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
