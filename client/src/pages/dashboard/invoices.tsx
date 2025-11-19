import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { type Order } from "@shared/schema";
import { Loader2, Download, FileText } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function Invoices() {
  const { data: orders, isLoading } = useQuery<Order[]>({
    queryKey: ["/api/orders"],
  });

  const deliveredOrders = orders?.filter(order => order.status === "delivered") || [];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-semibold text-foreground mb-2">Invoices</h1>
        <p className="text-muted-foreground">
          View and download your invoices
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Available Invoices</CardTitle>
          <CardDescription>Invoices for delivered orders</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : deliveredOrders.length > 0 ? (
            <div className="rounded-md border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Invoice #</TableHead>
                    <TableHead>Order Date</TableHead>
                    <TableHead>Delivered</TableHead>
                    <TableHead className="text-right">Amount</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {deliveredOrders.map((order) => (
                    <TableRow key={order.id} data-testid={`row-invoice-${order.id}`}>
                      <TableCell className="font-medium">
                        INV-{order.orderNumber}
                      </TableCell>
                      <TableCell>
                        {new Date(order.createdAt).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        {order.deliveryDate || new Date(order.createdAt).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-right font-semibold">
                        £{Number(order.totalAmount).toFixed(2)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button 
                          size="sm" 
                          variant="outline"
                          data-testid={`button-download-invoice-${order.id}`}
                        >
                          <Download className="w-4 h-4 mr-1" />
                          Download
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg font-medium text-foreground mb-2">No invoices available</p>
              <p className="text-muted-foreground">
                Invoices will appear here once your orders are delivered
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
