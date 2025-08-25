const express = require('express');
const {
  getProducts,
  getProduct,
  createProduct,
  updateProduct,
  deleteProduct,
  uploadProductImages,
  addProductReview,
  getProductReviews,
  deleteProductReview,
  getFeaturedProducts,
  getProductsByCategory,
  searchProducts
} = require('../controllers/products');
const { protect, authorize } = require('../middleware/auth');
const { upload } = require('../utils/cloudinary');
const {
  validate,
  productSchema,
  reviewSchema,
  mongoIdSchema,
  paginationSchema
} = require('../middleware/validation');

const router = express.Router();

// Public routes
router.get('/', validate(paginationSchema), getProducts);
router.get('/search', validate(paginationSchema), searchProducts);
router.get('/featured', getFeaturedProducts);
router.get('/category/:category', validate(paginationSchema), getProductsByCategory);
router.get('/:id', validate(mongoIdSchema), getProduct);
router.get('/:id/reviews', validate(mongoIdSchema), getProductReviews);

// Protected routes (users) - require authentication
router.post('/:id/reviews', protect, validate(reviewSchema), addProductReview);
router.delete('/:id/reviews/:reviewId', protect, validate(mongoIdSchema), deleteProductReview);

// Admin only routes - require authentication and admin role
router.post('/', protect, authorize('admin'), validate(productSchema), createProduct);
router.put('/:id', protect, authorize('admin'), validate(mongoIdSchema), updateProduct);
router.delete('/:id', protect, authorize('admin'), validate(mongoIdSchema), deleteProduct);
router.post('/:id/images', protect, authorize('admin'), upload.array('images', 5), uploadProductImages);

module.exports = router;
