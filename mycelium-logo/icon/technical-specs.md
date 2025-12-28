# Mycelium Icon Technical Specifications

## Final Vector Artwork Details

### Grid System
- **Base Grid**: 24x24 units
- **Stroke Weights**: 2 units (primary), 1 unit (secondary)
- **Corner Radius**: 1 unit for subtle softness
- **Optical Balance**: 60% grid area coverage

### Scalability Testing
- **Minimum Size**: 16px (using simplified small version)
- **Maximum Size**: Infinite (vector scalable)
- **Optimal Sizes**: 24px, 32px, 48px, 64px, 128px, 256px, 512px

### Color Specifications

#### Light Theme (Default)
- **Primary Color**: Deep Forest Green (#1B4332)
- **Usage**: Light backgrounds, documentation, web

#### Dark Theme
- **Primary Color**: Bright Cyan (#00F5FF)
- **Usage**: Dark backgrounds, terminal interfaces, GitHub dark mode

#### Monochrome
- **Color**: currentColor (inherits from parent)
- **Usage**: Single-color contexts, print, embossing

### File Variants

1. **mycelium-icon.svg** - Primary light theme version
2. **mycelium-icon-dark.svg** - Dark theme optimized
3. **mycelium-icon-mono.svg** - Monochrome version
4. **mycelium-icon-small.svg** - Simplified for 16px+ sizes

### Design Elements

#### Central Node
- **Position**: (12, 12) - exact center
- **Radius**: 2 units
- **Style**: Hollow circle with 2-unit stroke
- **Symbolism**: Core of the mycelium network

#### Primary Branches
- **Count**: 6 branches in hexagonal pattern
- **Angles**: 60° intervals (0°, 60°, 120°, 180°, 240°, 300°)
- **Length**: 4 units from center
- **Style**: 2-unit stroke weight, rounded caps

#### Terminal Nodes
- **Count**: 6 nodes at branch endpoints
- **Radius**: 1 unit
- **Style**: Filled circles
- **Symbolism**: Connection points in the network

#### Secondary Connections
- **Count**: 4 organic curves
- **Style**: 1-unit stroke, 70% opacity
- **Purpose**: Represent mycelium interconnectivity
- **Curves**: Quadratic Bézier paths for organic feel

### Accessibility Compliance
- **Contrast Ratio**: Meets WCAG 2.1 AA standards
- **Monochrome Fallback**: Available for colorblind users
- **Scalability**: Maintains clarity at all required sizes

### Implementation Notes
- Uses CSS classes for easy theme switching
- SVG optimized for web performance
- Maintains aspect ratio across all variants
- Compatible with modern browsers and design tools