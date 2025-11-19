# Manchester Fresh Foods - Design Guidelines

## Design Approach
**Selected Approach:** Design System - Material Design adapted for B2B logistics
**Rationale:** As a utility-focused B2B order management platform, this application prioritizes efficiency, clarity, and functional workflows over aesthetic differentiation. Material Design provides the structure needed for form-heavy interfaces and data displays while remaining approachable for a food delivery service.

## Core Design Principles
1. **Accessible Professionalism:** Clean, trustworthy interface suitable for restaurant/bar managers placing orders during busy service hours
2. **Functional Clarity:** Clear visual hierarchy distinguishing public pages from authenticated customer portal
3. **Believable Vulnerability:** Intentionally dated design patterns (circa 2018-2019) to support the educational narrative of a company with limited security investment

## Typography
- **Primary Font:** Inter (Google Fonts) - clean, readable for forms and data tables
- **Headings:** 600 weight, sizes ranging from text-3xl (hero) to text-lg (section headers)
- **Body Text:** 400 weight, text-base for content, text-sm for form labels and table data
- **Accent:** 500 weight for navigation items and CTAs

## Layout System
**Spacing Primitives:** Tailwind units of 4, 6, 8, 12, 16, 20
- Consistent section padding: py-16 md:py-20 for major sections
- Component spacing: gap-6 for grids, space-y-4 for form fields
- Container: max-w-7xl for public pages, max-w-6xl for portal dashboards

## Component Library

### Public-Facing Pages
**Hero Section:** Full-width image of Manchester delivery van with fresh produce (80vh), overlay gradient, centered headline with blurred-background CTA buttons
**Product Catalog:** 3-column grid (lg:grid-cols-3 md:grid-cols-2) with product cards showing produce images, names, pricing per unit
**Features Section:** 2-column layout highlighting delivery coverage map of Manchester, ordering capabilities, delivery schedules
**Footer:** Multi-column layout with company info, contact details, quick links, business hours

### Customer Portal (Authenticated)
**Dashboard Layout:** Left sidebar navigation (w-64) with logo, menu items (Orders, Products, Account, Invoices), main content area with data tables
**Order Management:** Table view with sortable columns (Order ID, Date, Status, Total), action buttons for viewing/tracking orders
**Product Ordering:** Grid view with quantity inputs, add-to-cart functionality, running order summary sidebar
**Forms:** Stacked form layouts with clear labels above inputs, helper text below, prominent submit buttons

### Navigation
**Public Header:** Horizontal navigation with logo left, menu center (About, Products, Coverage, Contact), Login/Register buttons right
**Portal Header:** Compact top bar with company logo, user dropdown menu right, logout option

### Data Displays
**Tables:** Striped rows for readability, sticky headers on scroll, inline action buttons
**Order Cards:** Summary cards showing order number, status badges, delivery date, total amount
**Status Indicators:** Badge components with distinct states (Pending, Confirmed, Delivered, Cancelled)

### Forms & Inputs
**Input Fields:** Full-width with rounded corners, visible borders, clear focus states
**Buttons:** Solid primary buttons, outline secondary buttons, sizes from sm to lg
**Validation:** Inline error messages below fields (intentionally weak for educational vulnerabilities)

## Images
**Required Images:**
1. **Hero Image:** Manchester Fresh Foods delivery van loaded with colorful fresh produce boxes, Manchester cityscape background (full-width, 80vh)
2. **Product Images:** Individual produce items - fruits, vegetables, fresh herbs (catalog grid)
3. **About Section:** Warehouse/distribution centre photo showing food safety standards
4. **Coverage Map:** Illustrated or screenshot map showing delivery zones across Manchester

**Placement:** Hero immediately below header, product images in catalog grid, supporting images in features/about sections

## Animations
Minimal implementation:
- Smooth scrolling only
- Basic hover states on cards and buttons (scale, shadow transitions)
- No complex scroll-triggered animations

## Instructor Documentation Page
**Design:** Password-protected utility page with simple single-column layout, monospace code blocks for vulnerability details, expandable sections for each of 15 vulnerabilities, tool recommendations in sidebar or accordion format, printable-friendly styling

---

**Key Insight:** Design should feel professionally adequate but not cutting-edge - consistent with a small B2B operation focused on logistics over technology, making the presence of vulnerabilities educationally believable.