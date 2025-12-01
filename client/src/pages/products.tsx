import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Loader2, Search } from "lucide-react";
import { type Product } from "@shared/schema";
import { useState } from "react";
import { Link } from "wouter";

export default function Products() {
  const [searchTerm, setSearchTerm] = useState("");

  const { data: products, isLoading } = useQuery<Product[]>({
    queryKey: [searchTerm ? `/api/products?search=${encodeURIComponent(searchTerm)}` : "/api/products"],
  });

  // Use server-side results directly
  const filteredProducts = products;

  return (
    <div className="min-h-screen py-12 bg-background">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-12">
          <h1 className="text-4xl font-semibold mb-4 text-foreground">Our Products</h1>
          <p className="text-lg text-muted-foreground mb-8">
            Fresh fruits, vegetables and produce delivered daily to your business
          </p>

          <div className="max-w-md">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                type="search"
                placeholder="Search products..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
                data-testid="input-search-products"
              />
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : (
          <>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredProducts?.map((product) => (
                <Card key={product.id} className="hover-elevate" data-testid={`card-product-${product.id}`}>
                  {product.imageUrl && (
                    <div className="aspect-[4/3] overflow-hidden rounded-t-md">
                      <img
                        src={product.imageUrl}
                        alt={product.name}
                        className="w-full h-full object-cover"
                      />
                    </div>
                  )}
                  <CardHeader>
                    <div className="flex items-start justify-between gap-2">
                      <CardTitle className="text-lg">{product.name}</CardTitle>
                      <Badge variant="secondary" data-testid={`badge-category-${product.id}`}>
                        {product.category}
                      </Badge>
                    </div>
                    {product.description && (
                      <CardDescription>{product.description}</CardDescription>
                    )}
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-baseline justify-between">
                      <div>
                        <span className="text-2xl font-semibold text-primary">
                          £{Number(product.pricePerUnit).toFixed(2)}
                        </span>
                        <span className="text-sm text-muted-foreground ml-1">
                          / {product.unit}
                        </span>
                      </div>
                      {product.stock > 0 ? (
                        <Badge variant="outline" className="text-xs">
                          In Stock
                        </Badge>
                      ) : (
                        <Badge variant="destructive" className="text-xs">
                          Out of Stock
                        </Badge>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {filteredProducts?.length === 0 && (
              <div className="text-center py-20">
                <p className="text-lg text-muted-foreground">No products found matching your search.</p>
              </div>
            )}
          </>
        )}

        <div className="mt-12 text-center">
          <Card className="max-w-2xl mx-auto">
            <CardHeader>
              <CardTitle>Ready to Order?</CardTitle>
              <CardDescription>
                Log in to your account to place orders and manage your deliveries
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-4 justify-center">
                <Link href="/login">
                  <Button data-testid="button-login-products">
                    Customer Login
                  </Button>
                </Link>
                <Link href="/register">
                  <Button variant="outline" data-testid="button-register-products">
                    Open Account
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
