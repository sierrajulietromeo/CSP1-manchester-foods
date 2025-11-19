import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { type Product } from "@shared/schema";
import { useState } from "react";
import { Loader2, ShoppingCart, Minus, Plus } from "lucide-react";
import { useLocation } from "wouter";

export default function PlaceOrder() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [cart, setCart] = useState<Record<string, number>>({});
  const [deliveryAddress, setDeliveryAddress] = useState("");
  const [deliveryDate, setDeliveryDate] = useState("");
  const [notes, setNotes] = useState("");

  const { data: products, isLoading } = useQuery<Product[]>({
    queryKey: ["/api/products"],
  });

  const updateQuantity = (productId: string, change: number) => {
    setCart(prev => {
      const current = prev[productId] || 0;
      const newQuantity = Math.max(0, current + change);
      if (newQuantity === 0) {
        const { [productId]: _, ...rest } = prev;
        return rest;
      }
      return { ...prev, [productId]: newQuantity };
    });
  };

  const cartItems = Object.entries(cart).map(([productId, quantity]) => {
    const product = products?.find(p => p.id === productId);
    return product ? { product, quantity } : null;
  }).filter(Boolean) as { product: Product; quantity: number }[];

  const totalAmount = cartItems.reduce((sum, item) => {
    return sum + (Number(item.product.pricePerUnit) * item.quantity);
  }, 0);

  const placeOrderMutation = useMutation({
    mutationFn: async () => {
      const orderItems = cartItems.map(item => ({
        productId: item.product.id,
        productName: item.product.name,
        quantity: item.quantity,
        pricePerUnit: item.product.pricePerUnit,
        subtotal: (Number(item.product.pricePerUnit) * item.quantity).toFixed(2),
      }));

      return await apiRequest("POST", "/api/orders", {
        items: orderItems,
        totalAmount: totalAmount.toFixed(2),
        deliveryAddress,
        deliveryDate,
        notes,
      });
    },
    onSuccess: () => {
      toast({
        title: "Order Placed",
        description: "Your order has been submitted successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/orders"] });
      setLocation("/dashboard/orders");
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to place order. Please try again.",
        variant: "destructive",
      });
    },
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-semibold text-foreground mb-2">Place New Order</h1>
        <p className="text-muted-foreground">
          Select products and quantities for your order
        </p>
      </div>

      <div className="grid lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Available Products</CardTitle>
              <CardDescription>Add items to your order</CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-8 h-8 animate-spin text-primary" />
                </div>
              ) : (
                <div className="space-y-4">
                  {products?.map((product) => (
                    <div 
                      key={product.id} 
                      className="flex items-center gap-4 p-4 border border-border rounded-md"
                      data-testid={`product-row-${product.id}`}
                    >
                      {product.imageUrl && (
                        <img
                          src={product.imageUrl}
                          alt={product.name}
                          className="w-16 h-16 object-cover rounded-md"
                        />
                      )}
                      <div className="flex-1">
                        <h3 className="font-medium text-foreground">{product.name}</h3>
                        <p className="text-sm text-muted-foreground">{product.description}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="secondary" className="text-xs">
                            {product.category}
                          </Badge>
                          <span className="text-sm font-semibold text-primary">
                            £{Number(product.pricePerUnit).toFixed(2)} / {product.unit}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          size="icon"
                          variant="outline"
                          onClick={() => updateQuantity(product.id, -1)}
                          disabled={!cart[product.id]}
                          data-testid={`button-decrease-${product.id}`}
                        >
                          <Minus className="w-4 h-4" />
                        </Button>
                        <span className="w-12 text-center font-medium" data-testid={`quantity-${product.id}`}>
                          {cart[product.id] || 0}
                        </span>
                        <Button
                          size="icon"
                          variant="outline"
                          onClick={() => updateQuantity(product.id, 1)}
                          data-testid={`button-increase-${product.id}`}
                        >
                          <Plus className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Order Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {cartItems.length === 0 ? (
                <p className="text-muted-foreground text-sm text-center py-4">
                  Your cart is empty
                </p>
              ) : (
                <>
                  <div className="space-y-2">
                    {cartItems.map(item => (
                      <div key={item.product.id} className="flex justify-between text-sm">
                        <span className="text-muted-foreground">
                          {item.product.name} x {item.quantity}
                        </span>
                        <span className="font-medium">
                          £{(Number(item.product.pricePerUnit) * item.quantity).toFixed(2)}
                        </span>
                      </div>
                    ))}
                  </div>
                  <div className="pt-4 border-t border-border">
                    <div className="flex justify-between text-lg font-semibold">
                      <span>Total</span>
                      <span className="text-primary" data-testid="text-order-total">
                        £{totalAmount.toFixed(2)}
                      </span>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Delivery Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium text-foreground mb-2 block">
                  Delivery Address
                </label>
                <Input
                  value={deliveryAddress}
                  onChange={(e) => setDeliveryAddress(e.target.value)}
                  placeholder="Enter delivery address"
                  data-testid="input-delivery-address"
                />
              </div>
              <div>
                <label className="text-sm font-medium text-foreground mb-2 block">
                  Preferred Delivery Date
                </label>
                <Input
                  type="date"
                  value={deliveryDate}
                  onChange={(e) => setDeliveryDate(e.target.value)}
                  data-testid="input-delivery-date"
                />
              </div>
              <div>
                <label className="text-sm font-medium text-foreground mb-2 block">
                  Order Notes
                </label>
                <Textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Any special instructions?"
                  rows={3}
                  data-testid="textarea-order-notes"
                />
              </div>
              <Button
                className="w-full"
                onClick={() => placeOrderMutation.mutate()}
                disabled={cartItems.length === 0 || placeOrderMutation.isPending}
                data-testid="button-place-order"
              >
                <ShoppingCart className="w-4 h-4 mr-2" />
                {placeOrderMutation.isPending ? "Placing Order..." : "Place Order"}
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
