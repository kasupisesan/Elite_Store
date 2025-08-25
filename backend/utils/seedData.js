const mongoose = require('mongoose');
const User = require('../models/User');
const Product = require('../models/Product');
require('dotenv').config();

const products = [
  // Electronics Category - Smartphones
  {
    name: 'iPhone 15 Pro',
    description: 'Latest iPhone with A17 Pro chip, titanium design, and advanced camera system. Features include 48MP main camera, 5x telephoto zoom, and all-day battery life.',
    price: 134900,
    originalPrice: 139900,
    discount: 4,
    category: 'electronics',
    subcategory: 'smartphones',
    brand: 'Apple',
    stockQuantity: 50,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1592750475338-74b7b21085ab?w=800',
        publicId: 'iphone_15_pro',
        alt: 'iPhone 15 Pro'
      }
    ],
    specifications: {
      'Display': '6.1-inch Super Retina XDR',
      'Chip': 'A17 Pro',
      'Storage': '128GB',
      'Camera': '48MP Main + 12MP Ultra Wide + 12MP Telephoto',
      'Battery': 'Up to 23 hours video playback'
    },
    features: ['Face ID', 'Wireless Charging', '5G Capable', 'Water Resistant'],
    tags: ['smartphone', 'apple', 'iphone', 'premium'],
    isFeatured: true
  },
  {
    name: 'Samsung Galaxy S24 Ultra',
    description: 'Premium Android smartphone with S Pen, 200MP camera, and AI-powered features. Perfect for productivity and creativity.',
    price: 129999,
    originalPrice: 134999,
    discount: 4,
    category: 'electronics',
    subcategory: 'smartphones',
    brand: 'Samsung',
    stockQuantity: 30,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=800',
        publicId: 'samsung_galaxy_s24',
        alt: 'Samsung Galaxy S24 Ultra'
      }
    ],
    specifications: {
      'Display': '6.8-inch Dynamic AMOLED 2X',
      'Processor': 'Snapdragon 8 Gen 3',
      'Storage': '256GB',
      'Camera': '200MP Main + 50MP Periscope + 12MP Ultra Wide + 10MP Telephoto',
      'Battery': '5000mAh'
    },
    features: ['S Pen', 'Wireless Charging', '5G', 'IP68 Water Resistant'],
    tags: ['smartphone', 'samsung', 'android', 'premium', 's-pen'],
    isFeatured: true
  },
  // Electronics Category - Laptops
  {
    name: 'MacBook Air M3',
    description: 'Incredibly thin and light laptop powered by the M3 chip. Perfect for students and professionals with all-day battery life.',
    price: 114900,
    originalPrice: 119900,
    discount: 4,
    category: 'electronics',
    subcategory: 'laptops',
    brand: 'Apple',
    stockQuantity: 25,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1541807084-5c52b6b3adef?w=800',
        publicId: 'macbook_air_m3',
        alt: 'MacBook Air M3'
      }
    ],
    specifications: {
      'Display': '13.6-inch Liquid Retina',
      'Chip': 'Apple M3',
      'Memory': '8GB Unified Memory',
      'Storage': '256GB SSD',
      'Battery': 'Up to 18 hours'
    },
    features: ['Touch ID', 'Backlit Keyboard', 'Force Touch Trackpad', 'Thunderbolt Ports'],
    tags: ['laptop', 'apple', 'macbook', 'ultrabook'],
    isFeatured: true
  },
  {
    name: 'Dell XPS 13',
    description: 'Premium Windows ultrabook with stunning InfinityEdge display and exceptional performance in a compact design.',
    price: 98999,
    originalPrice: 109999,
    discount: 10,
    category: 'electronics',
    subcategory: 'laptops',
    brand: 'Dell',
    stockQuantity: 20,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1603302576837-37561b2e2302?w=800',
        publicId: 'dell_xps_13',
        alt: 'Dell XPS 13'
      }
    ],
    specifications: {
      'Display': '13.4-inch FHD+ InfinityEdge',
      'Processor': 'Intel Core i7-1360P',
      'Memory': '16GB LPDDR5',
      'Storage': '512GB SSD',
      'Battery': 'Up to 12 hours'
    },
    features: ['Fingerprint Reader', 'Backlit Keyboard', 'Thunderbolt 4', 'WiFi 6E'],
    tags: ['laptop', 'dell', 'windows', 'ultrabook', 'business'],
    isFeatured: false
  },
  // Electronics Category - Audio
  {
    name: 'Sony WH-1000XM5 Headphones',
    description: 'Industry-leading noise canceling wireless headphones with exceptional sound quality and 30-hour battery life.',
    price: 29990,
    originalPrice: 34990,
    discount: 14,
    category: 'electronics',
    subcategory: 'audio',
    brand: 'Sony',
    stockQuantity: 75,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=800',
        publicId: 'sony_wh1000xm5',
        alt: 'Sony WH-1000XM5 Headphones'
      }
    ],
    specifications: {
      'Driver': '30mm',
      'Frequency Response': '4Hz-40kHz',
      'Battery Life': '30 hours',
      'Charging': 'USB-C Quick Charge',
      'Weight': '250g'
    },
    features: ['Active Noise Canceling', 'Touch Controls', 'Voice Assistant', 'Foldable Design'],
    tags: ['headphones', 'sony', 'wireless', 'noise-canceling'],
    isFeatured: false
  },
  {
    name: 'Apple AirPods Pro (2nd Gen)',
    description: 'Premium wireless earbuds with adaptive transparency, personalized spatial audio, and up to 30 hours of listening time.',
    price: 24900,
    originalPrice: 26900,
    discount: 7,
    category: 'electronics',
    subcategory: 'audio',
    brand: 'Apple',
    stockQuantity: 100,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1606220945770-b5b6c2c55bf1?w=800',
        publicId: 'airpods_pro_2',
        alt: 'Apple AirPods Pro 2nd Generation'
      }
    ],
    specifications: {
      'Driver': 'Custom Apple Driver',
      'Chip': 'H2 Chip',
      'Battery Life': '6 hours (30 hours with case)',
      'Charging': 'Lightning/Wireless/MagSafe',
      'Weight': '5.3g per earbud'
    },
    features: ['Active Noise Cancellation', 'Adaptive Transparency', 'Spatial Audio', 'Touch Controls'],
    tags: ['earbuds', 'apple', 'airpods', 'wireless', 'premium'],
    isFeatured: true
  },
  
  // Clothing Category
  {
    name: 'Nike Air Max 270',
    description: 'Comfortable lifestyle sneakers with Max Air unit in the heel for all-day comfort and style.',
    price: 12995,
    originalPrice: 14995,
    discount: 13,
    category: 'clothing',
    subcategory: 'shoes',
    brand: 'Nike',
    stockQuantity: 100,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=800',
        publicId: 'nike_air_max_270',
        alt: 'Nike Air Max 270'
      }
    ],
    specifications: {
      'Upper': 'Mesh and synthetic materials',
      'Sole': 'Rubber outsole',
      'Cushioning': 'Max Air unit',
      'Closure': 'Lace-up',
      'Weight': '300g (per shoe)'
    },
    features: ['Max Air Cushioning', 'Breathable Mesh', 'Durable Outsole', 'Iconic Design'],
    tags: ['shoes', 'nike', 'sneakers', 'air-max', 'lifestyle'],
    isFeatured: false
  },
  {
    name: 'Levi\'s 501 Original Jeans',
    description: 'The original blue jean since 1873. Crafted with premium denim in a classic straight fit that never goes out of style.',
    price: 7999,
    originalPrice: 8999,
    discount: 11,
    category: 'clothing',
    subcategory: 'jeans',
    brand: 'Levi\'s',
    stockQuantity: 150,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1542272604-787c3835535d?w=800',
        publicId: 'levis_501_jeans',
        alt: 'Levi\'s 501 Original Jeans'
      }
    ],
    specifications: {
      'Material': '100% Cotton Denim',
      'Fit': 'Original Straight',
      'Rise': 'Mid-rise',
      'Closure': 'Button fly',
      'Care': 'Machine wash cold'
    },
    features: ['Button Fly', 'Arcuate Stitching', 'Leather Patch', 'Classic Fit'],
    tags: ['jeans', 'levis', 'denim', 'classic', 'straight-fit'],
    isFeatured: false
  },
  {
    name: 'Adidas Ultraboost 23',
    description: 'Premium running shoes with responsive BOOST cushioning and Primeknit upper for ultimate comfort and performance.',
    price: 18995,
    originalPrice: 21995,
    discount: 14,
    category: 'clothing',
    subcategory: 'shoes',
    brand: 'Adidas',
    stockQuantity: 80,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1539185441755-769473a23570?w=800',
        publicId: 'adidas_ultraboost_23',
        alt: 'Adidas Ultraboost 23'
      }
    ],
    specifications: {
      'Upper': 'Primeknit textile',
      'Midsole': 'BOOST cushioning',
      'Outsole': 'Continental rubber',
      'Drop': '10mm',
      'Weight': '320g (size 9)'
    },
    features: ['BOOST Technology', 'Primeknit Upper', 'Continental Outsole', 'Energy Return'],
    tags: ['running-shoes', 'adidas', 'ultraboost', 'performance', 'boost'],
    isFeatured: true
  },
  {
    name: 'Champion Reverse Weave Hoodie',
    description: 'Classic heavyweight hoodie made with reverse weave construction to resist shrinking and maintain shape.',
    price: 5999,
    originalPrice: 6999,
    discount: 14,
    category: 'clothing',
    subcategory: 'hoodies',
    brand: 'Champion',
    stockQuantity: 120,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1556821840-3a63f95609a7?w=800',
        publicId: 'champion_hoodie',
        alt: 'Champion Reverse Weave Hoodie'
      }
    ],
    specifications: {
      'Material': '82% Cotton, 18% Polyester',
      'Construction': 'Reverse Weave',
      'Features': 'Drawstring hood, kangaroo pocket',
      'Fit': 'Classic fit',
      'Care': 'Machine wash warm'
    },
    features: ['Reverse Weave Construction', 'Shrink Resistant', 'Kangaroo Pocket', 'Adjustable Hood'],
    tags: ['hoodie', 'champion', 'streetwear', 'classic', 'heavyweight'],
    isFeatured: false
  },

  // Books Category
  {
    name: 'The Psychology of Money',
    description: 'Timeless lessons on wealth, greed, and happiness by Morgan Housel. A bestselling guide to understanding the psychology behind financial decisions.',
    price: 1299,
    originalPrice: 1499,
    discount: 13,
    category: 'books',
    subcategory: 'business',
    brand: 'Harriman House',
    stockQuantity: 200,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=800',
        publicId: 'psychology_of_money',
        alt: 'The Psychology of Money Book'
      }
    ],
    specifications: {
      'Author': 'Morgan Housel',
      'Pages': '256',
      'Publisher': 'Harriman House',
      'Language': 'English',
      'Format': 'Paperback'
    },
    features: ['Bestseller', 'Financial Wisdom', 'Easy to Read', 'Practical Insights'],
    tags: ['finance', 'psychology', 'money', 'bestseller', 'business'],
    isFeatured: true
  },
  {
    name: 'Atomic Habits',
    description: 'An easy & proven way to build good habits & break bad ones by James Clear. Transform your life with tiny changes in behavior.',
    price: 1199,
    originalPrice: 1399,
    discount: 14,
    category: 'books',
    subcategory: 'self-help',
    brand: 'Avery',
    stockQuantity: 180,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=800',
        publicId: 'atomic_habits',
        alt: 'Atomic Habits Book'
      }
    ],
    specifications: {
      'Author': 'James Clear',
      'Pages': '320',
      'Publisher': 'Avery',
      'Language': 'English',
      'Format': 'Hardcover'
    },
    features: ['#1 New York Times Bestseller', 'Habit Formation', 'Self-Improvement', 'Practical Strategies'],
    tags: ['habits', 'self-help', 'productivity', 'bestseller', 'personal-development'],
    isFeatured: true
  },
  {
    name: 'Dune: Frank Herbert',
    description: 'Epic science fiction masterpiece set on the desert planet Arrakis. Winner of Hugo and Nebula Awards.',
    price: 899,
    originalPrice: 1099,
    discount: 18,
    category: 'books',
    subcategory: 'fiction',
    brand: 'Ace Books',
    stockQuantity: 150,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?w=800',
        publicId: 'dune_book',
        alt: 'Dune Science Fiction Novel'
      }
    ],
    specifications: {
      'Author': 'Frank Herbert',
      'Pages': '688',
      'Publisher': 'Ace Books',
      'Language': 'English',
      'Format': 'Mass Market Paperback'
    },
    features: ['Hugo Award Winner', 'Nebula Award Winner', 'Science Fiction Classic', 'Epic World-Building'],
    tags: ['science-fiction', 'classic', 'award-winner', 'epic', 'space-opera'],
    isFeatured: false
  },
  {
    name: 'The Complete Cookbook for Young Chefs',
    description: 'Kid-tested and kid-approved cookbook with over 100 recipes designed to get young chefs excited about cooking.',
    price: 1599,
    originalPrice: 1899,
    discount: 16,
    category: 'books',
    subcategory: 'cooking',
    brand: 'America\'s Test Kitchen Kids',
    stockQuantity: 100,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=800',
        publicId: 'young_chefs_cookbook',
        alt: 'Complete Cookbook for Young Chefs'
      }
    ],
    specifications: {
      'Author': 'America\'s Test Kitchen Kids',
      'Pages': '224',
      'Publisher': 'America\'s Test Kitchen Kids',
      'Language': 'English',
      'Format': 'Hardcover'
    },
    features: ['100+ Kid-Friendly Recipes', 'Step-by-Step Instructions', 'Safety Tips', 'Colorful Illustrations'],
    tags: ['cooking', 'kids', 'recipes', 'kitchen', 'family'],
    isFeatured: false
  },

  // Home Category
  {
    name: 'Instant Pot Duo 7-in-1',
    description: 'Multi-use programmable pressure cooker that replaces 7 kitchen appliances. Cook rice, slow cook, steam, sauté, and more.',
    price: 7999,
    originalPrice: 9999,
    discount: 20,
    category: 'home',
    subcategory: 'kitchen',
    brand: 'Instant Pot',
    stockQuantity: 60,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1584622650111-993a426fbf0a?w=800',
        publicId: 'instant_pot_duo',
        alt: 'Instant Pot Duo 7-in-1 Pressure Cooker'
      }
    ],
    specifications: {
      'Capacity': '6 Quart',
      'Functions': '7-in-1 Multi-Cooker',
      'Material': 'Stainless Steel',
      'Power': '1000 Watts',
      'Dimensions': '13" x 12.5" x 12.5"'
    },
    features: ['Pressure Cook', 'Slow Cook', 'Rice Cooker', 'Steamer', 'Sauté', 'Yogurt Maker', 'Warmer'],
    tags: ['kitchen', 'appliance', 'pressure-cooker', 'multi-cooker', 'instant-pot'],
    isFeatured: true
  },
  {
    name: 'Dyson V15 Detect Cordless Vacuum',
    description: 'Intelligent cordless vacuum with laser dust detection and powerful suction. See the microscopic dust you miss.',
    price: 64999,
    originalPrice: 74999,
    discount: 13,
    category: 'home',
    subcategory: 'cleaning',
    brand: 'Dyson',
    stockQuantity: 25,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=800',
        publicId: 'dyson_v15_vacuum',
        alt: 'Dyson V15 Detect Cordless Vacuum'
      }
    ],
    specifications: {
      'Runtime': 'Up to 60 minutes',
      'Dustbin': '0.2 gallons',
      'Weight': '6.8 lbs',
      'Filtration': 'Whole-machine HEPA',
      'Charging': '4.5 hours'
    },
    features: ['Laser Dust Detection', 'Powerful Suction', 'HEPA Filtration', 'Cordless Design', 'Multiple Attachments'],
    tags: ['vacuum', 'dyson', 'cordless', 'cleaning', 'home-appliance'],
    isFeatured: true
  },
  {
    name: 'Philips Hue Smart Light Starter Kit',
    description: 'Smart lighting system with 16 million colors and warm-to-cool white light. Control with voice or app.',
    price: 19999,
    originalPrice: 24999,
    discount: 20,
    category: 'home',
    subcategory: 'lighting',
    brand: 'Philips',
    stockQuantity: 40,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1513475382585-d06e58bcb0e0?w=800',
        publicId: 'philips_hue_lights',
        alt: 'Philips Hue Smart Light Starter Kit'
      }
    ],
    specifications: {
      'Bulbs': '3 A19 LED bulbs + Bridge',
      'Colors': '16 million colors',
      'Brightness': '800 lumens',
      'Lifespan': '25,000 hours',
      'Compatibility': 'Alexa, Google, Apple HomeKit'
    },
    features: ['Voice Control', 'App Control', '16M Colors', 'Scheduling', 'Energy Efficient'],
    tags: ['smart-home', 'lighting', 'philips', 'led', 'voice-control'],
    isFeatured: false
  },
  {
    name: 'Ninja Foodi Personal Blender',
    description: 'Personal blender with Auto-iQ technology for perfectly blended smoothies, shakes, and frozen drinks.',
    price: 5999,
    originalPrice: 7999,
    discount: 25,
    category: 'home',
    subcategory: 'kitchen',
    brand: 'Ninja',
    stockQuantity: 80,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1570197788417-0e82375c9371?w=800',
        publicId: 'ninja_blender',
        alt: 'Ninja Foodi Personal Blender'
      }
    ],
    specifications: {
      'Capacity': '18 oz cup',
      'Power': '700 watts',
      'Blades': 'Pro Extractor Blades',
      'Programs': '1-Touch Auto-iQ',
      'Material': 'BPA-free Tritan'
    },
    features: ['Auto-iQ Technology', 'Pro Extractor Blades', 'To-Go Cup', 'Easy Clean', 'Compact Design'],
    tags: ['blender', 'ninja', 'kitchen', 'smoothie', 'personal-blender'],
    isFeatured: false
  },

  // Sports Category
  {
    name: 'Wilson Pro Staff Tennis Racket',
    description: 'Professional-grade tennis racket with precision and power. Used by tennis champions worldwide.',
    price: 15999,
    originalPrice: 19999,
    discount: 20,
    category: 'sports',
    subcategory: 'tennis',
    brand: 'Wilson',
    stockQuantity: 30,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=800',
        publicId: 'wilson_tennis_racket',
        alt: 'Wilson Pro Staff Tennis Racket'
      }
    ],
    specifications: {
      'Head Size': '97 sq inches',
      'Weight': '315g unstrung',
      'Balance': '31.5cm',
      'String Pattern': '16x19',
      'Beam Width': '21.5mm'
    },
    features: ['Professional Grade', 'Precision Control', 'Carbon Fiber Frame', 'Comfortable Grip'],
    tags: ['tennis', 'racket', 'wilson', 'professional', 'sports-equipment'],
    isFeatured: false
  },
  {
    name: 'Nike Basketball Official Size',
    description: 'Official size basketball with superior grip and durability. Perfect for indoor and outdoor play.',
    price: 2999,
    originalPrice: 3499,
    discount: 14,
    category: 'sports',
    subcategory: 'basketball',
    brand: 'Nike',
    stockQuantity: 150,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1546519638-68e109498ffc?w=800',
        publicId: 'nike_basketball',
        alt: 'Nike Basketball Official Size'
      }
    ],
    specifications: {
      'Size': 'Official Size 7',
      'Material': 'Synthetic leather',
      'Weight': '22 oz',
      'Circumference': '29.5-29.875 inches',
      'Use': 'Indoor/Outdoor'
    },
    features: ['Official Size', 'Superior Grip', 'Durable Construction', 'All-Surface Play'],
    tags: ['basketball', 'nike', 'official-size', 'sports', 'ball'],
    isFeatured: false
  },
  {
    name: 'Bowflex Adjustable Dumbbells',
    description: 'Space-efficient adjustable dumbbells that replace 15 sets of weights. Quick weight changes from 5-52.5 lbs.',
    price: 39999,
    originalPrice: 49999,
    discount: 20,
    category: 'sports',
    subcategory: 'fitness',
    brand: 'Bowflex',
    stockQuantity: 20,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=800',
        publicId: 'bowflex_dumbbells',
        alt: 'Bowflex Adjustable Dumbbells'
      }
    ],
    specifications: {
      'Weight Range': '5-52.5 lbs per dumbbell',
      'Increments': '2.5 lb increments',
      'Total Sets': 'Replaces 15 sets',
      'Dimensions': '16.9" x 8.3" x 9"',
      'Material': 'Metal plates with polymer coating'
    },
    features: ['Space Saving', 'Quick Weight Change', 'Durable Construction', '15 Weight Settings'],
    tags: ['dumbbells', 'bowflex', 'adjustable', 'fitness', 'strength-training'],
    isFeatured: true
  },
  {
    name: 'Spalding Portable Basketball Hoop',
    description: 'Adjustable height portable basketball system perfect for driveways, patios, and recreational areas.',
    price: 24999,
    originalPrice: 29999,
    discount: 17,
    category: 'sports',
    subcategory: 'basketball',
    brand: 'Spalding',
    stockQuantity: 15,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1504450758481-7338eba7524a?w=800',
        publicId: 'spalding_hoop',
        alt: 'Spalding Portable Basketball Hoop'
      }
    ],
    specifications: {
      'Backboard': '54-inch Acrylic',
      'Height Range': '7.5 - 10 feet',
      'Base': '34-gallon portable base',
      'Rim': 'Pro-style breakaway rim',
      'Assembly': 'Pre-assembled components'
    },
    features: ['Adjustable Height', 'Portable Design', 'Pro-Style Rim', 'Weather Resistant'],
    tags: ['basketball-hoop', 'spalding', 'portable', 'outdoor', 'adjustable'],
    isFeatured: false
  },

  // Beauty Category
  {
    name: 'Fenty Beauty Foundation',
    description: 'Award-winning liquid foundation with buildable, medium to full coverage and a natural, longwearing finish.',
    price: 3400,
    originalPrice: 3800,
    discount: 11,
    category: 'beauty',
    subcategory: 'makeup',
    brand: 'Fenty Beauty',
    stockQuantity: 200,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1596462502278-27bfdc403348?w=800',
        publicId: 'fenty_foundation',
        alt: 'Fenty Beauty Pro Filt\'r Foundation'
      }
    ],
    specifications: {
      'Coverage': 'Medium to Full',
      'Finish': 'Natural Matte',
      'Size': '32ml',
      'Shades': '50 available shades',
      'Type': 'Liquid Foundation'
    },
    features: ['50 Shades Available', 'Long-wearing', 'Buildable Coverage', 'Sweat & Humidity Resistant'],
    tags: ['foundation', 'fenty', 'makeup', 'inclusive', 'longwear'],
    isFeatured: true
  },
  {
    name: 'The Ordinary Niacinamide Serum',
    description: 'High-strength vitamin and zinc serum that targets textural irregularities and signs of congestion.',
    price: 650,
    originalPrice: 750,
    discount: 13,
    category: 'beauty',
    subcategory: 'skincare',
    brand: 'The Ordinary',
    stockQuantity: 300,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1620916566398-39f1143ab7be?w=800',
        publicId: 'the_ordinary_serum',
        alt: 'The Ordinary Niacinamide 10% + Zinc 1% Serum'
      }
    ],
    specifications: {
      'Volume': '30ml',
      'Key Ingredients': '10% Niacinamide, 1% Zinc',
      'Skin Type': 'All skin types',
      'pH': '5.5-6.5',
      'Formulation': 'Water-based serum'
    },
    features: ['Reduces Sebum Activity', 'Minimizes Pores', 'Balances Skin', 'Affordable Skincare'],
    tags: ['serum', 'niacinamide', 'the-ordinary', 'skincare', 'affordable'],
    isFeatured: false
  },
  {
    name: 'Dyson Supersonic Hair Dryer',
    description: 'Intelligent heat control hair dryer that prevents extreme heat damage for healthy-looking, shiny hair.',
    price: 39900,
    originalPrice: 42900,
    discount: 7,
    category: 'beauty',
    subcategory: 'hair-tools',
    brand: 'Dyson',
    stockQuantity: 40,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1522338242992-e1a54906a8da?w=800',
        publicId: 'dyson_hair_dryer',
        alt: 'Dyson Supersonic Hair Dryer'
      }
    ],
    specifications: {
      'Motor': 'Digital motor V9',
      'Heat Settings': '4 heat settings',
      'Speed Settings': '3 speed settings',
      'Attachments': '5 styling attachments',
      'Weight': '1.8 lbs'
    },
    features: ['Intelligent Heat Control', 'Fast Drying', 'Engineered for Different Hair Types', 'Quiet Operation'],
    tags: ['hair-dryer', 'dyson', 'professional', 'intelligent', 'hair-care'],
    isFeatured: true
  },
  {
    name: 'Charlotte Tilbury Pillow Talk Lipstick',
    description: 'Universally flattering matte-finish lipstick in the iconic Pillow Talk shade. Hydrating formula with long-lasting color.',
    price: 3200,
    originalPrice: 3600,
    discount: 11,
    category: 'beauty',
    subcategory: 'makeup',
    brand: 'Charlotte Tilbury',
    stockQuantity: 150,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1586495777744-4413f21062fa?w=800',
        publicId: 'charlotte_tilbury_lipstick',
        alt: 'Charlotte Tilbury Pillow Talk Lipstick'
      }
    ],
    specifications: {
      'Shade': 'Pillow Talk (universally flattering nude-pink)',
      'Finish': 'Matte',
      'Formula': 'Matte Revolution',
      'Size': '3.5g',
      'Longevity': 'Up to 8 hours'
    },
    features: ['Universally Flattering', 'Hydrating Formula', 'Long-lasting', 'Iconic Shade'],
    tags: ['lipstick', 'charlotte-tilbury', 'pillow-talk', 'matte', 'luxury'],
    isFeatured: false
  },

  // Toys Category
  {
    name: 'LEGO Creator Expert Modular Building',
    description: 'Detailed LEGO building set featuring intricate architecture with multiple floors, rooms, and accessories.',
    price: 15999,
    originalPrice: 19999,
    discount: 20,
    category: 'toys',
    subcategory: 'building-toys',
    brand: 'LEGO',
    stockQuantity: 50,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=800',
        publicId: 'lego_modular_building',
        alt: 'LEGO Creator Expert Modular Building'
      }
    ],
    specifications: {
      'Pieces': '2,354 pieces',
      'Age Range': '16+',
      'Dimensions': '15" x 10" x 15"',
      'Minifigures': '8 included',
      'Theme': 'Creator Expert'
    },
    features: ['Modular Design', 'Detailed Interior', 'Compatible with Other Sets', 'Adult Collector Item'],
    tags: ['lego', 'building', 'modular', 'creator', 'collector'],
    isFeatured: true
  },
  {
    name: 'Barbie Dreamhouse Dollhouse',
    description: 'Three-story dollhouse with 10 indoor and outdoor play areas, lights, sounds, and over 70 accessories.',
    price: 18999,
    originalPrice: 22999,
    discount: 17,
    category: 'toys',
    subcategory: 'dolls',
    brand: 'Barbie',
    stockQuantity: 30,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1515488042361-ee00e0ddd4e4?w=800',
        publicId: 'barbie_dreamhouse',
        alt: 'Barbie Dreamhouse Dollhouse'
      }
    ],
    specifications: {
      'Height': '3.75 feet tall',
      'Stories': '3 stories',
      'Rooms': '10 indoor/outdoor areas',
      'Age Range': '3-7 years',
      'Accessories': '70+ pieces'
    },
    features: ['Lights & Sounds', 'Working Elevator', 'Pool with Slide', 'Modern Design'],
    tags: ['barbie', 'dollhouse', 'dreamhouse', 'imaginative-play', 'girls'],
    isFeatured: true
  },
  {
    name: 'Hot Wheels Track Builder System',
    description: 'Build epic racing tracks with curves, loops, and jumps. Includes launcher and die-cast car.',
    price: 4999,
    originalPrice: 5999,
    discount: 17,
    category: 'toys',
    subcategory: 'vehicles',
    brand: 'Hot Wheels',
    stockQuantity: 100,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1558618047-3c8c76ca7d13?w=800',
        publicId: 'hot_wheels_track',
        alt: 'Hot Wheels Track Builder System'
      }
    ],
    specifications: {
      'Track Length': '16+ feet of track',
      'Age Range': '4+ years',
      'Includes': 'Launcher, curves, straights, connectors',
      'Cars': '1 die-cast vehicle included',
      'Expandable': 'Compatible with other Hot Wheels sets'
    },
    features: ['Modular Track System', 'High-Speed Racing', 'Easy Assembly', 'Expandable Design'],
    tags: ['hot-wheels', 'track-builder', 'racing', 'cars', 'action'],
    isFeatured: false
  },
  {
    name: 'Melissa & Doug Wooden Puzzle Set',
    description: 'Educational wooden puzzles featuring animals, shapes, and letters. Perfect for developing problem-solving skills.',
    price: 2999,
    originalPrice: 3499,
    discount: 14,
    category: 'toys',
    subcategory: 'educational',
    brand: 'Melissa & Doug',
    stockQuantity: 80,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1606107557195-0e29a4b5b4aa?w=800',
        publicId: 'wooden_puzzle_set',
        alt: 'Melissa & Doug Wooden Puzzle Set'
      }
    ],
    specifications: {
      'Material': 'High-quality wood',
      'Age Range': '2-4 years',
      'Puzzles': '4 different puzzles included',
      'Pieces': '8-12 pieces per puzzle',
      'Theme': 'Animals and Shapes'
    },
    features: ['Educational Play', 'Durable Wood Construction', 'Chunky Pieces', 'Problem-Solving Skills'],
    tags: ['puzzle', 'wooden', 'educational', 'melissa-doug', 'preschool'],
    isFeatured: false
  },

  // Automotive Category
  {
    name: 'Michelin Defender T+H All-Season Tires',
    description: 'Premium all-season tires with superior tread life, fuel efficiency, and all-weather performance.',
    price: 12999,
    originalPrice: 14999,
    discount: 13,
    category: 'automotive',
    subcategory: 'tires',
    brand: 'Michelin',
    stockQuantity: 40,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1558618047-3c8c76ca7d13?w=800',
        publicId: 'michelin_tires',
        alt: 'Michelin Defender T+H All-Season Tires'
      }
    ],
    specifications: {
      'Size': '225/65R17',
      'Season': 'All-Season',
      'Tread Life': '90,000 miles',
      'Speed Rating': 'T (118 mph)',
      'Load Index': '102'
    },
    features: ['Long Tread Life', 'Fuel Efficient', 'All-Weather Traction', 'Comfortable Ride'],
    tags: ['tires', 'michelin', 'all-season', 'defender', 'long-lasting'],
    isFeatured: false
  },
  {
    name: 'Mobil 1 Full Synthetic Motor Oil',
    description: 'Advanced full synthetic motor oil that helps protect against engine wear and deposits for up to 15,000 miles.',
    price: 2999,
    originalPrice: 3499,
    discount: 14,
    category: 'automotive',
    subcategory: 'fluids',
    brand: 'Mobil 1',
    stockQuantity: 200,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1487925876428-ebd8a23ee1d4?w=800',
        publicId: 'mobil1_motor_oil',
        alt: 'Mobil 1 Full Synthetic Motor Oil'
      }
    ],
    specifications: {
      'Viscosity': '5W-30',
      'Type': 'Full Synthetic',
      'Size': '5 Quart',
      'Protection': 'Up to 15,000 miles',
      'Temperature Range': '-40°F to 400°F'
    },
    features: ['Extended Protection', 'Superior Engine Cleanliness', 'Extreme Temperature Performance', 'Fuel Economy'],
    tags: ['motor-oil', 'mobil1', 'synthetic', 'engine-protection', 'automotive'],
    isFeatured: false
  },
  {
    name: 'Bosch ICON Windshield Wipers',
    description: 'Beam wiper blades with exclusive dual rubber compound for superior wiping performance in all weather.',
    price: 3999,
    originalPrice: 4999,
    discount: 20,
    category: 'automotive',
    subcategory: 'parts',
    brand: 'Bosch',
    stockQuantity: 150,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1503376780353-7e6692767b70?w=800',
        publicId: 'bosch_wipers',
        alt: 'Bosch ICON Windshield Wipers'
      }
    ],
    specifications: {
      'Size': '26" + 18" (Driver + Passenger)',
      'Type': 'Beam blade',
      'Material': 'Dual rubber compound',
      'Installation': 'Easy clip-on',
      'Weather': 'All-season performance'
    },
    features: ['Superior Wiping', 'All-Weather Performance', 'Easy Installation', 'Long Lasting'],
    tags: ['windshield-wipers', 'bosch', 'beam-blade', 'all-weather', 'replacement'],
    isFeatured: false
  },
  {
    name: 'Chemical Guys Car Wash Kit',
    description: 'Complete car care kit with premium shampoo, microfiber towels, applicators, and detailing spray.',
    price: 7999,
    originalPrice: 9999,
    discount: 20,
    category: 'automotive',
    subcategory: 'care',
    brand: 'Chemical Guys',
    stockQuantity: 75,
    images: [
      {
        url: 'https://images.unsplash.com/photo-1607860108855-64acf2078ed9?w=800',
        publicId: 'chemical_guys_kit',
        alt: 'Chemical Guys Complete Car Wash Kit'
      }
    ],
    specifications: {
      'Contents': '16oz Shampoo, Microfiber towels, Applicators, Detailer',
      'Applications': '20+ washes',
      'Safe For': 'All paint types and finishes',
      'pH Balanced': 'Yes',
      'Biodegradable': 'Yes'
    },
    features: ['Complete Kit', 'pH Balanced Formula', 'Professional Grade', 'Eco-Friendly'],
    tags: ['car-wash', 'chemical-guys', 'detailing', 'complete-kit', 'premium'],
    isFeatured: true
  }
];

// Users array should be defined here (keeping the original structure)
const users = [
  {
    name: 'Admin User',
    email: 'admin@ecommerce.com',
    password: 'admin123', // This will be hashed by pre-save middleware
    role: 'admin',
    isVerified: true
  },
  {
    name: 'John Doe',
    email: 'john@example.com',
    password: 'user123', // This will be hashed by pre-save middleware
    role: 'user',
    isVerified: true
  },
  {
    name: 'Jane Smith',
    email: 'jane@example.com',
    password: 'user123', // This will be hashed by pre-save middleware
    role: 'user',
    isVerified: true
  }
];

const seedData = async () => {
  try {
    // Connect to database
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('Connected to MongoDB');

    // Clear existing data
    await User.deleteMany({});
    await Product.deleteMany({});
    console.log('Cleared existing data');

    // Create admin user first
    const adminUser = await User.create(users[0]);
    console.log('Admin user created');

    // Create other users
    const otherUsers = await User.create(users.slice(1));
    console.log(`${otherUsers.length} regular users created`);

    // Create products with admin as creator
    const productsWithCreator = products.map(product => ({
      ...product,
      createdBy: adminUser._id
    }));

    const createdProducts = await Product.create(productsWithCreator);
    console.log(`${createdProducts.length} products created`);

    console.log('\n=== SEED DATA SUMMARY ===');
    console.log(`✅ ${users.length} users created`);
    console.log(`✅ ${products.length} products created`);
    console.log('\n=== PRODUCT BREAKDOWN BY CATEGORY ===');
    
    const categoryBreakdown = {};
    products.forEach(product => {
      if (!categoryBreakdown[product.category]) {
        categoryBreakdown[product.category] = 0;
      }
      categoryBreakdown[product.category]++;
    });
    
    Object.entries(categoryBreakdown).forEach(([category, count]) => {
      console.log(`📦 ${category}: ${count} products`);
    });
    
    console.log('\n=== LOGIN CREDENTIALS ===');
    console.log('Admin: admin@ecommerce.com / admin123');
    console.log('User 1: john@example.com / user123');
    console.log('User 2: jane@example.com / user123');

    process.exit(0);
  } catch (error) {
    console.error('Error seeding data:', error);
    process.exit(1);
  }
};

seedData();
