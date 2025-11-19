import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Truck, Clock, MapPin, Shield, Phone, Mail } from "lucide-react";
import heroImage from "@assets/generated_images/Manchester_delivery_van_hero_image_c7265f6d.png";
import warehouseImage from "@assets/generated_images/Warehouse_distribution_center_about_section_b6c71bf3.png";

export default function Home() {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative h-[80vh] flex items-center justify-center overflow-hidden">
        <div 
          className="absolute inset-0 bg-cover bg-center"
          style={{ backgroundImage: `url(${heroImage})` }}
        >
          <div className="absolute inset-0 bg-gradient-to-r from-black/70 to-black/50" />
        </div>
        
        <div className="relative z-10 max-w-4xl mx-auto text-center px-6">
          <h1 className="text-5xl md:text-6xl font-semibold text-white mb-6">
            Fresh Produce Delivered Daily to Manchester Businesses
          </h1>
          <p className="text-xl text-white/90 mb-8 max-w-2xl mx-auto">
            Quality fruits, vegetables and fresh ingredients for restaurants, bars and shops across Greater Manchester
          </p>
          <div className="flex flex-wrap gap-4 justify-center">
            <Link href="/login">
              <Button 
                size="lg" 
                variant="default"
                className="bg-primary/90 backdrop-blur-sm border border-primary-border hover-elevate active-elevate-2"
                data-testid="button-login-hero"
              >
                Customer Login
              </Button>
            </Link>
            <Link href="/register">
              <Button 
                size="lg" 
                variant="outline"
                className="bg-background/10 backdrop-blur-sm text-white border-white/30 hover-elevate active-elevate-2"
                data-testid="button-register-hero"
              >
                Open Account
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 md:py-20 bg-background">
        <div className="max-w-7xl mx-auto px-6">
          <h2 className="text-3xl font-semibold text-center mb-12 text-foreground">Why Choose Manchester Fresh Foods?</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card data-testid="card-feature-delivery">
              <CardHeader>
                <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mb-4">
                  <Truck className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-lg">Daily Deliveries</CardTitle>
              </CardHeader>
              <CardContent>
                <CardDescription>
                  Fresh produce delivered every morning before 8am across Greater Manchester
                </CardDescription>
              </CardContent>
            </Card>

            <Card data-testid="card-feature-quality">
              <CardHeader>
                <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mb-4">
                  <Shield className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-lg">Quality Guaranteed</CardTitle>
              </CardHeader>
              <CardContent>
                <CardDescription>
                  Sourced from trusted suppliers, inspected for freshness and quality daily
                </CardDescription>
              </CardContent>
            </Card>

            <Card data-testid="card-feature-coverage">
              <CardHeader>
                <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mb-4">
                  <MapPin className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-lg">Wide Coverage</CardTitle>
              </CardHeader>
              <CardContent>
                <CardDescription>
                  Serving restaurants, bars and shops across Manchester, Salford, and Trafford
                </CardDescription>
              </CardContent>
            </Card>

            <Card data-testid="card-feature-ordering">
              <CardHeader>
                <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mb-4">
                  <Clock className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-lg">Easy Ordering</CardTitle>
              </CardHeader>
              <CardContent>
                <CardDescription>
                  Order online 24/7, flexible scheduling, and account management portal
                </CardDescription>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* About Section */}
      <section className="py-16 md:py-20 bg-muted/30">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl font-semibold mb-6 text-foreground">About Manchester Fresh Foods</h2>
              <div className="space-y-4 text-base text-foreground">
                <p>
                  Established in 2015, Manchester Fresh Foods has been serving the hospitality and retail sectors across Greater Manchester with premium quality fresh produce.
                </p>
                <p>
                  Our warehouse and distribution centre in Trafford Park operates 7 days a week, ensuring restaurants, bars, cafes and independent retailers receive the freshest fruits, vegetables and ingredients.
                </p>
                <p>
                  We pride ourselves on reliable service, competitive pricing, and building long-term relationships with our customers across the region.
                </p>
              </div>
              <div className="mt-8">
                <Link href="/products">
                  <Button size="lg" data-testid="button-view-products">
                    View Our Products
                  </Button>
                </Link>
              </div>
            </div>
            <div className="rounded-md overflow-hidden">
              <img 
                src={warehouseImage} 
                alt="Manchester Fresh Foods warehouse and distribution centre"
                className="w-full h-auto"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Contact Section */}
      <section className="py-16 md:py-20 bg-background">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-3xl mx-auto text-center">
            <h2 className="text-3xl font-semibold mb-6 text-foreground">Get In Touch</h2>
            <p className="text-base text-muted-foreground mb-8">
              Ready to start ordering? Contact us to set up your business account today.
            </p>
            <div className="grid md:grid-cols-2 gap-6 mb-8">
              <Card data-testid="card-contact-phone">
                <CardHeader>
                  <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mx-auto mb-4">
                    <Phone className="w-6 h-6 text-primary" />
                  </div>
                  <CardTitle className="text-lg">Call Us</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-foreground font-medium">0161 234 5678</p>
                  <p className="text-sm text-muted-foreground mt-2">Mon-Fri 7am-6pm</p>
                </CardContent>
              </Card>

              <Card data-testid="card-contact-email">
                <CardHeader>
                  <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mx-auto mb-4">
                    <Mail className="w-6 h-6 text-primary" />
                  </div>
                  <CardTitle className="text-lg">Email Us</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-foreground font-medium">orders@manchesterfresh.co.uk</p>
                  <p className="text-sm text-muted-foreground mt-2">24-hour response time</p>
                </CardContent>
              </Card>
            </div>
            <Link href="/contact">
              <Button size="lg" variant="outline" data-testid="button-contact-form">
                Send Us a Message
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-muted/50 border-t border-border py-6">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center space-y-2">
            <p className="text-sm text-muted-foreground">
              © 2025 Manchester Fresh Foods. All rights reserved.
            </p>
            <p className="text-xs text-muted-foreground/80 italic">
              ⚠️ This is a fictional educational application created for cybersecurity training purposes.
              Not a real business.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
