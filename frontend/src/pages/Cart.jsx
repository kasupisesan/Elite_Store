import { Link } from 'react-router-dom'
import { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Trash2,
  Plus,
  Minus,
  ShoppingBag,
  Heart,
  ArrowRight,
  Package,
  Truck,
  Shield,
  Gift,
  Sparkles,
  X
} from 'lucide-react'
import { useCart } from '../contexts/CartContext'
import toast from 'react-hot-toast'

function Cart() {
  // Scroll to top whenever Cart component mounts
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])

  const {
    items,
    totalItems,
    totalPrice,
    updateCartItem,
    removeFromCart,
    clearCart,
    loading
  } = useCart()

  const handleUpdateQuantity = async (productId, newQuantity) => {
    if (newQuantity < 1) return
    await updateCartItem(productId, newQuantity)
  }

  const handleRemoveItem = async (productId) => {
    await removeFromCart(productId)
  }

  const handleClearCart = async () => {
    if (window.confirm('Are you sure you want to clear your cart?')) {
      await clearCart()
    }
  }

  const shippingCost = totalPrice >= 999 ? 0 : 99
  const finalTotal = totalPrice + shippingCost
  const freeShippingThreshold = 999
  const remainingForFreeShipping = Math.max(0, freeShippingThreshold - totalPrice)

  if (loading) {
    return (
      <div className="min-h-screen py-4 sm:py-8">
        <div className="max-w-6xl mx-auto px-3 sm:px-4 lg:px-6 xl:px-8">
          <div className="animate-pulse">
            <div className="skeleton h-6 sm:h-8 w-32 sm:w-48 mb-6 sm:mb-8" />
            <div className="space-y-3 sm:space-y-4">
              {[...Array(3)].map((_, index) => (
                <div key={index} className="bg-white rounded-xl p-4 sm:p-6">
                  <div className="flex gap-3 sm:gap-4">
                    <div className="skeleton h-16 w-16 sm:h-20 sm:w-20 rounded-xl" />
                    <div className="flex-1">
                      <div className="skeleton h-4 sm:h-6 mb-2" />
                      <div className="skeleton h-3 sm:h-4 mb-3 sm:mb-4 w-3/4" />
                      <div className="skeleton h-6 sm:h-8 w-24 sm:w-32" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (!items || items.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="text-center max-w-md w-full">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="w-24 h-24 sm:w-32 sm:h-32 mx-auto mb-6 sm:mb-8 bg-gradient-to-br from-violet-100 to-indigo-100 rounded-full flex items-center justify-center"
          >
            <ShoppingBag className="w-12 h-12 sm:w-16 sm:h-16 text-violet-600" />
          </motion.div>
          <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 mb-3 sm:mb-4">Your cart is empty</h2>
          <p className="text-lg sm:text-xl text-slate-600 mb-6 sm:mb-8">Start shopping to add items to your cart</p>
          <Link to="/products" className="btn btn-primary btn-lg w-full sm:w-auto group">
            <ShoppingBag className="w-5 h-5 mr-2 group-hover:animate-bounce" />
            Continue Shopping
            <ArrowRight className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform" />
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen py-4 sm:py-6 lg:py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-6xl mx-auto px-3 sm:px-4 lg:px-6 xl:px-8">

        {/* 📱 Mobile-Optimized Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-6 sm:mb-8">
          <div className="mb-4 sm:mb-0">
            <h1 className="text-2xl sm:text-3xl font-bold gradient-text">Shopping Cart</h1>
            <p className="text-slate-600 mt-1 sm:mt-2 text-sm sm:text-base">
              {totalItems} {totalItems === 1 ? 'item' : 'items'} in your cart
            </p>
          </div>
          {items.length > 0 && (
            <button
              onClick={handleClearCart}
              className="w-full sm:w-auto btn btn-ghost btn-sm sm:btn-md text-red-600 hover:bg-red-50 group touch-manipulation"
            >
              <Trash2 className="w-4 h-4 mr-2 group-hover:animate-bounce" />
              Clear Cart
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8">

          {/* 📱 Mobile-Friendly Cart Items */}
          <div className="lg:col-span-2">
            <div className="space-y-3 sm:space-y-4">
              <AnimatePresence mode="popLayout">
                {items.map((item) => (
                  <motion.div
                    key={item._id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, x: -100, height: 0 }}
                    transition={{ duration: 0.3 }}
                    className="bg-white rounded-xl sm:rounded-2xl shadow-sm hover:shadow-md transition-shadow p-4 sm:p-6"
                  >
                    <div className="flex flex-col sm:flex-row gap-4 sm:gap-6">

                      {/* Product Image & Remove Button Row */}
                      <div className="flex items-start justify-between sm:block sm:flex-shrink-0">
                        <Link to={`/products/${item.product._id}`} className="block">
                          <div className="w-16 h-16 sm:w-20 sm:h-20 lg:w-24 lg:h-24 rounded-lg sm:rounded-xl overflow-hidden bg-slate-100 group">
                            <img
                              src={
                                item.product.images?.[0]?.url ||
                                item.product.images?.[0] ||
                                'https://images.unsplash.com/photo-1560472355-536de3962603?w=300'
                              }
                              alt={item.product.name}
                              className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                              onError={(e) => {
                                e.target.src = 'https://images.unsplash.com/photo-1560472355-536de3962603?w=300';
                              }}
                              loading="lazy"
                            />
                          </div>
                        </Link>

                        {/* Remove Button - Top Right on Mobile */}
                        <motion.button
                          whileHover={{ scale: 1.1 }}
                          whileTap={{ scale: 0.9 }}
                          onClick={() => handleRemoveItem(item.product._id)}
                          className="sm:hidden p-2 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all touch-manipulation"
                        >
                          <X className="w-5 h-5" />
                        </motion.button>
                      </div>

                      {/* Product Details */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between">
                          <div className="flex-1 min-w-0 pr-2">
                            <Link
                              to={`/products/${item.product._id}`}
                              className="block text-base sm:text-lg font-semibold text-slate-900 hover:text-violet-600 transition-colors line-clamp-2 mb-1"
                            >
                              {item.product.name}
                            </Link>
                            {item.product.brand && (
                              <p className="text-xs sm:text-sm text-slate-500 mb-2 truncate">
                                {item.product.brand}
                              </p>
                            )}

                            {/* 💰 Fixed Price Display */}
                            <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 mb-3">
                              <span className="text-lg sm:text-xl lg:text-2xl font-bold text-slate-900 break-all">
                                ₹{item.product.price?.toLocaleString()}
                              </span>
                              <span className="text-xs sm:text-sm text-slate-500">each</span>
                            </div>

                            {/* Stock Warning */}
                            {item.product.stockQuantity < 10 && (
                              <div className="flex items-center text-amber-600 mb-3">
                                <Package className="w-3 h-3 sm:w-4 sm:h-4 mr-1 flex-shrink-0" />
                                <span className="text-xs sm:text-sm font-medium">
                                  Only {item.product.stockQuantity} left in stock
                                </span>
                              </div>
                            )}
                          </div>

                          {/* Remove Button - Desktop Only */}
                          <motion.button
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            onClick={() => handleRemoveItem(item.product._id)}
                            className="hidden sm:block p-2 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-xl transition-all flex-shrink-0"
                          >
                            <X className="w-5 h-5" />
                          </motion.button>
                        </div>

                        {/* 📱 Mobile-Optimized Quantity Controls & Total */}
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 sm:gap-4">
                          <div className="flex items-center justify-between sm:justify-start gap-3 sm:gap-4">

                            {/* Quantity Controls */}
                            <div className="flex items-center bg-slate-100 rounded-lg sm:rounded-xl p-1">
                              <motion.button
                                whileHover={{ scale: 1.1 }}
                                whileTap={{ scale: 0.9 }}
                                onClick={() => handleUpdateQuantity(item.product._id, item.quantity - 1)}
                                disabled={item.quantity <= 1}
                                className="w-8 h-8 sm:w-9 sm:h-9 rounded-md sm:rounded-lg bg-white shadow-sm border border-slate-200 flex items-center justify-center hover:border-violet-300 disabled:opacity-50 disabled:cursor-not-allowed transition-all touch-manipulation"
                              >
                                <Minus className="w-3 h-3 sm:w-4 sm:h-4" />
                              </motion.button>
                              <span className="w-10 sm:w-12 text-center font-semibold text-sm sm:text-base">
                                {item.quantity}
                              </span>
                              <motion.button
                                whileHover={{ scale: 1.1 }}
                                whileTap={{ scale: 0.9 }}
                                onClick={() => handleUpdateQuantity(item.product._id, item.quantity + 1)}
                                disabled={item.quantity >= item.product.stockQuantity}
                                className="w-8 h-8 sm:w-9 sm:h-9 rounded-md sm:rounded-lg bg-white shadow-sm border border-slate-200 flex items-center justify-center hover:border-violet-300 disabled:opacity-50 disabled:cursor-not-allowed transition-all touch-manipulation"
                              >
                                <Plus className="w-3 h-3 sm:w-4 sm:h-4" />
                              </motion.button>
                            </div>

                            {/* Wishlist Button */}
                            <motion.button
                              whileHover={{ scale: 1.1 }}
                              whileTap={{ scale: 0.9 }}
                              className="p-2 sm:p-2.5 text-slate-400 hover:text-red-500 hover:bg-red-50 rounded-lg sm:rounded-xl transition-all touch-manipulation"
                            >
                              <Heart className="w-4 h-4 sm:w-5 sm:h-5" />
                            </motion.button>

                            {/* Item Total - Mobile */}
                            <div className="sm:hidden">
                              <div className="text-lg font-bold text-slate-900 break-all">
                                ₹{(item.product.price * item.quantity).toLocaleString()}
                              </div>
                            </div>
                          </div>

                          {/* Item Total - Desktop */}
                          <div className="hidden sm:block text-right">
                            <div className="text-xl lg:text-2xl font-bold gradient-text break-all">
                              ₹{(item.product.price * item.quantity).toLocaleString()}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </div>

          {/* 📱 Mobile-Optimized Order Summary */}
          <div className="lg:col-span-1">
            <div className="lg:sticky lg:top-24 space-y-4 sm:space-y-6">

              {/* Free Shipping Progress */}
              {remainingForFreeShipping > 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-gradient-to-r from-violet-50 to-indigo-50 border border-violet-200 rounded-xl sm:rounded-2xl p-4 sm:p-6"
                >
                  <div className="flex items-center mb-3">
                    <Truck className="w-5 h-5 text-violet-600 mr-2 flex-shrink-0" />
                    <h3 className="font-semibold text-violet-900 text-sm sm:text-base">Free Shipping</h3>
                  </div>
                  <p className="text-xs sm:text-sm text-violet-700 mb-3 break-all">
                    Add ₹{remainingForFreeShipping.toLocaleString()} more to get free shipping!
                  </p>
                  <div className="w-full bg-violet-200 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-violet-600 to-indigo-600 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${Math.min(100, (totalPrice / freeShippingThreshold) * 100)}%` }}
                    />
                  </div>
                </motion.div>
              )}

              {/* Order Summary Card */}
              <div className="bg-white rounded-xl sm:rounded-2xl shadow-sm p-4 sm:p-6">
                <h3 className="text-lg sm:text-xl font-bold text-slate-900 mb-4 sm:mb-6 flex items-center">
                  <Sparkles className="w-5 h-5 mr-2 text-violet-600 flex-shrink-0" />
                  Order Summary
                </h3>

                <div className="space-y-3 sm:space-y-4">
                  <div className="flex justify-between text-slate-600 text-sm sm:text-base">
                    <span>Subtotal ({totalItems} items)</span>
                    <span className="font-medium break-all">₹{totalPrice.toLocaleString()}</span>
                  </div>

                  <div className="flex justify-between text-slate-600 text-sm sm:text-base">
                    <span className="flex items-center">
                      <Truck className="w-4 h-4 mr-1 flex-shrink-0" />
                      Shipping
                    </span>
                    <span className={`font-medium ${shippingCost === 0 ? 'text-green-600' : ''} break-all`}>
                      {shippingCost === 0 ? 'FREE' : `₹${shippingCost}`}
                    </span>
                  </div>

                  <div className="border-t border-slate-200 pt-3 sm:pt-4">
                    <div className="flex justify-between items-center">
                      <span className="text-lg sm:text-xl font-bold text-slate-900">Total</span>
                      <span className="text-xl sm:text-2xl font-bold gradient-text break-all">
                        ₹{finalTotal.toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Features */}
                <div className="mt-4 sm:mt-6 pt-4 sm:pt-6 border-t border-slate-200 space-y-2 sm:space-y-3">
                  {[
                    { icon: Shield, text: 'Secure checkout' },
                    { icon: Truck, text: 'Fast delivery' },
                    { icon: Gift, text: 'Free returns' }
                  ].map((feature, index) => (
                    <div key={index} className="flex items-center text-xs sm:text-sm text-slate-600">
                      <feature.icon className="w-4 h-4 mr-2 text-green-600 flex-shrink-0" />
                      <span>{feature.text}</span>
                    </div>
                  ))}
                </div>

                {/* Checkout Button */}
                <Link to="/checkout" className="block mt-4 sm:mt-6">
                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    className="w-full btn btn-primary btn-lg text-base sm:text-lg font-semibold py-3 sm:py-4 group touch-manipulation"
                  >
                    <Shield className="w-5 h-5 mr-2 group-hover:animate-pulse flex-shrink-0" />
                    Proceed to Checkout
                    <ArrowRight className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform flex-shrink-0" />
                  </motion.button>
                </Link>

                <Link to="/products" className="block mt-3 sm:mt-4">
                  <button className="w-full btn btn-outline btn-md sm:btn-lg touch-manipulation">
                    Continue Shopping
                  </button>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Cart
