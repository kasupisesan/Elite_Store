const express = require('express');
const {
  createOrder,
  getOrders,
  getOrder,
  updateOrderStatus,
  getUserOrders,
  cancelOrder,
  getOrderStats
} = require('../controllers/orders');
const { protect, authorize } = require('../middleware/auth');
const {
  validate,
  createOrderSchema,
  updateOrderStatusSchema,
  mongoIdSchema,
  paginationSchema
} = require('../middleware/validation');

const router = express.Router();

// Protected routes (users) - all order routes require authentication
router.use(protect);

router.post('/', validate(createOrderSchema), createOrder);
router.get('/my-orders', validate(paginationSchema), getUserOrders);
router.get('/:id', validate(mongoIdSchema), getOrder);
router.put('/:id/cancel', validate(mongoIdSchema), cancelOrder);

// Admin only routes - require authentication and admin role
router.get('/', authorize('admin'), validate(paginationSchema), getOrders);
router.put('/:id/status', authorize('admin'), validate(updateOrderStatusSchema), updateOrderStatus);
router.get('/stats/overview', authorize('admin'), getOrderStats);

module.exports = router;
