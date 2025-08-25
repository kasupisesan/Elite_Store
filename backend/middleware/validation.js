const { z } = require('zod');

// Zod validation middleware
const validate = (schema) => {
  return (req, res, next) => {
    try {
      // Validate request body, query, and params
      const validationData = {
        ...(req.body && Object.keys(req.body).length > 0 && { body: req.body }),
        ...(req.query && Object.keys(req.query).length > 0 && { query: req.query }),
        ...(req.params && Object.keys(req.params).length > 0 && { params: req.params })
      };

      const result = schema.parse(validationData);
      
      // Update req with validated data
      if (result.body) req.body = result.body;
      if (result.query) req.query = result.query;
      if (result.params) req.params = result.params;
      
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const errors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message
        }));
        
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors
        });
      }
      next(error);
    }
  };
};

// Auth validation schemas
const registerSchema = z.object({
  body: z.object({
    name: z.string()
      .min(2, 'Name must be at least 2 characters')
      .max(50, 'Name cannot exceed 50 characters')
      .trim(),
    email: z.string()
      .email('Please provide a valid email')
      .toLowerCase(),
    password: z.string()
      .min(6, 'Password must be at least 6 characters'),
    phone: z.string().optional(),
    address: z.object({
      street: z.string().optional(),
      city: z.string().optional(),
      state: z.string().optional(),
      zipCode: z.string().optional(),
      country: z.string().optional()
    }).optional()
  })
});

const loginSchema = z.object({
  body: z.object({
    email: z.string()
      .email('Please provide a valid email')
      .toLowerCase(),
    password: z.string()
      .min(1, 'Password is required')
  })
});

const changePasswordSchema = z.object({
  body: z.object({
    currentPassword: z.string()
      .min(1, 'Current password is required'),
    newPassword: z.string()
      .min(6, 'New password must be at least 6 characters')
  })
});

// Product validation schemas
const productSchema = z.object({
  body: z.object({
    name: z.string()
      .min(2, 'Product name must be at least 2 characters')
      .max(100, 'Product name cannot exceed 100 characters')
      .trim(),
    description: z.string()
      .min(10, 'Description must be at least 10 characters')
      .max(2000, 'Description cannot exceed 2000 characters')
      .trim(),
    price: z.number()
      .positive('Price must be a positive number'),
    originalPrice: z.number()
      .positive('Original price must be a positive number')
      .optional(),
    discount: z.number()
      .min(0, 'Discount cannot be negative')
      .max(100, 'Discount cannot exceed 100%')
      .optional(),
    category: z.enum(['electronics', 'clothing', 'books', 'home', 'sports', 'beauty', 'toys', 'automotive', 'other']),
    subcategory: z.string().optional(),
    brand: z.string().optional(),
    stockQuantity: z.number()
      .int('Stock quantity must be an integer')
      .min(0, 'Stock quantity cannot be negative'),
    specifications: z.record(z.string()).optional(),
    features: z.array(z.string()).optional(),
    tags: z.array(z.string()).optional(),
    isFeatured: z.boolean().optional()
  })
});

const reviewSchema = z.object({
  body: z.object({
    rating: z.number()
      .int('Rating must be an integer')
      .min(1, 'Rating must be at least 1')
      .max(5, 'Rating cannot exceed 5'),
    comment: z.string()
      .max(500, 'Comment cannot exceed 500 characters')
      .optional()
  })
});

// Cart validation schemas
const addToCartSchema = z.object({
  body: z.object({
    productId: z.string()
      .regex(/^[0-9a-fA-F]{24}$/, 'Please provide a valid product ID'),
    quantity: z.number()
      .int('Quantity must be an integer')
      .min(1, 'Quantity must be at least 1')
  })
});

const updateCartSchema = z.object({
  body: z.object({
    quantity: z.number()
      .int('Quantity must be an integer')
      .min(1, 'Quantity must be at least 1')
  }),
  params: z.object({
    productId: z.string()
      .regex(/^[0-9a-fA-F]{24}$/, 'Please provide a valid product ID')
  })
});

// Order validation schemas
const createOrderSchema = z.object({
  body: z.object({
    shippingAddress: z.object({
      fullName: z.string()
        .min(1, 'Full name is required')
        .trim(),
      address: z.string()
        .min(1, 'Address is required')
        .trim(),
      city: z.string()
        .min(1, 'City is required')
        .trim(),
      postalCode: z.string()
        .min(1, 'Postal code is required')
        .trim(),
      country: z.string()
        .default('India'),
      phone: z.string()
        .min(1, 'Phone number is required')
        .trim()
    }),
    paymentMethod: z.enum(['credit_card', 'debit_card', 'paypal', 'cash_on_delivery', 'upi']),
    paymentResult: z.object({
      id: z.string().optional(),
      status: z.string().optional(),
      update_time: z.string().optional(),
      email_address: z.string().optional()
    }).optional()
  })
});

const updateOrderStatusSchema = z.object({
  body: z.object({
    status: z.enum(['pending', 'processing', 'shipped', 'delivered', 'cancelled']),
    note: z.string()
      .max(500, 'Note cannot exceed 500 characters')
      .optional(),
    trackingNumber: z.string().optional()
  }),
  params: z.object({
    id: z.string()
      .regex(/^[0-9a-fA-F]{24}$/, 'Please provide a valid order ID')
  })
});

// Common parameter schemas
const mongoIdSchema = z.object({
  params: z.object({
    id: z.string()
      .regex(/^[0-9a-fA-F]{24}$/, 'Please provide a valid ID')
  })
});

const paginationSchema = z.object({
  query: z.object({
    page: z.string().transform((val) => val === '' ? undefined : Number(val)).optional(),
    limit: z.string().transform((val) => val === '' ? undefined : Number(val)).optional(),
    sortBy: z.string().transform((val) => val === '' ? undefined : val).optional(),
    category: z.string().transform((val) => val === '' ? undefined : val).optional(),
    minPrice: z.string().transform((val) => val === '' ? undefined : Number(val)).optional(),
    maxPrice: z.string().transform((val) => val === '' ? undefined : Number(val)).optional(),
    brand: z.string().transform((val) => val === '' ? undefined : val).optional(),
    q: z.string().transform((val) => val === '' ? undefined : val).optional()
  }).optional()
});

module.exports = {
  validate,
  registerSchema,
  loginSchema,
  changePasswordSchema,
  productSchema,
  reviewSchema,
  addToCartSchema,
  updateCartSchema,
  createOrderSchema,
  updateOrderStatusSchema,
  mongoIdSchema,
  paginationSchema
};
