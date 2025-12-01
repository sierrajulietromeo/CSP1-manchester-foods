import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { type Order, type User } from "@shared/schema";
import { useState } from "react";
import { Loader2, Search, Package } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type EnrichedOrder = Order & {
  customerName?: string;
  customerContact?: string;
};

export default function Orders() {
  const [searchTerm, setSearchTerm] = useState("");

  const { data: currentUser, isLoading: isLoadingUser } = useQuery<User>({
    queryKey: ["/api/user"],
  });

  const { data: orders, isLoading: isLoadingOrders } = useQuery<EnrichedOrder[]>({
    queryKey: ["/api/orders"],
  });

  const isAdmin = currentUser?.role === "admin";
  const isLoading = isLoadingUser || isLoadingOrders;

  const filteredOrders = orders?.filter(order => {
    const searchLower = searchTerm.toLowerCase();
    return (
      order.orderNumber.toLowerCase().includes(searchLower) ||
      order.status.toLowerCase().includes(searchLower) ||
      (order.customerName && order.customerName.toLowerCase().includes(searchLower))
    );
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-semibold text-foreground mb-2">
          {isAdmin ? "All Orders" : "My Orders"}
        </h1>
        <p className="text-muted-foreground">
          {isAdmin ? "View and manage all customer orders" : "View and track all your orders"}
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <CardTitle>
                {isAdmin ? "All Customer Orders" : "Order History"}
              </CardTitle>
              <CardDescription>
                {isAdmin ? "Manage orders from all customers" : "All your orders in one place"}
              </CardDescription>
            </div>
            <div className="w-full md:w-64">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  type="search"
                  placeholder="Search orders..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                  data-testid="input-search-orders"
                />
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : filteredOrders && filteredOrders.length > 0 ? (
            <div className="rounded-md border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Order #</TableHead>
                    {isAdmin && <TableHead>Customer</TableHead>}
                    <TableHead>Date</TableHead>
                    <TableHead>Delivery Date</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Total</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredOrders.map((order) => (
                    <TableRow key={order.id} data-testid={`row-order-${order.id}`}>
                      <TableCell className="font-medium">
                        {order.orderNumber}
                        {order.notes && (
                          <div
                            className="text-xs text-muted-foreground mt-1"
                            dangerouslySetInnerHTML={{ __html: order.notes }}
                          />
                        )}
                      </TableCell>
                      {isAdmin && (
                        <TableCell>
                          <div>
                            <div className="font-medium">{order.customerName}</div>
                            {order.customerContact && (
                              <div className="text-xs text-muted-foreground">
                                {order.customerContact}
                              </div>
                            )}
                          </div>
                        </TableCell>
                      )}
                      <TableCell>
                        {new Date(order.createdAt).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        {order.deliveryDate || "TBD"}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            order.status === "delivered" ? "default" :
                              order.status === "confirmed" ? "secondary" :
                                order.status === "cancelled" ? "destructive" :
                                  "outline"
                          }
                          data-testid={`badge-order-status-${order.id}`}
                        >
                          {order.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right font-semibold">
                        £{Number(order.totalAmount).toFixed(2)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-center py-12">
              <Package className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg font-medium text-foreground mb-2">No orders found</p>
              <p className="text-muted-foreground">
                {searchTerm ? "Try adjusting your search" : "You haven't placed any orders yet"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
