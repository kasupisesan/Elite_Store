const express = require('express');
const {
  getCart,
  addToCart,
  updateCartItem,
  removeFromCart,
  clearCart
} = require('../controllers/cart');
const { protect } = require('../middleware/auth');
const {
  validate,
  addToCartSchema,
  updateCartSchema,
  mongoIdSchema
} = require('../middleware/validation');

const router = express.Router();

// All cart routes require authentication - user must be logged in
router.use(protect);

router.get('/', getCart);
router.post('/add', addToCart);
router.put('/update/:productId', updateCartItem);
router.delete('/remove/:productId', removeFromCart);
router.delete('/clear', clearCart);

module.exports = router;
