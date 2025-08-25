import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { 
  Star, 
  ShoppingCart, 
  Heart, 
  Share2, 
  Truck, 
  Shield, 
  RotateCcw, 
  Plus, 
  Minus,
  ChevronLeft,
  ChevronRight,
  Check,
  AlertCircle,
  MessageCircle,
  ThumbsUp,
  ArrowLeft,
  Zap,
  Award,
  Users
} from 'lucide-react'
import { productsAPI } from '../utils/api'
import { useCart } from '../contexts/CartContext'
import { useAuth } from '../contexts/AuthContext'
import toast from 'react-hot-toast'

function ProductDetail() {
  const { id } = useParams()
  const [selectedImage, setSelectedImage] = useState(0)
  const [quantity, setQuantity] = useState(1)
  const [showReviewForm, setShowReviewForm] = useState(false)
  const [reviewData, setReviewData] = useState({ rating: 5, comment: '' })
  const [activeTab, setActiveTab] = useState('description')

  const { addToCart } = useCart()
  const { isAuthenticated, user } = useAuth()
  const queryClient = useQueryClient()

  const { data: product, isLoading, error } = useQuery(
    ['product', id],
    () => productsAPI.getProduct(id),
    { select: (response) => response.data.data }
  )

  const { data: reviews } = useQuery(
    ['reviews', id],
    () => productsAPI.getReviews(id),
    { 
      select: (response) => response.data.data, 
      enabled: !!id 
    }
  )

  const addReviewMutation = useMutation(
    (data) => productsAPI.addReview(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['reviews', id])
        queryClient.invalidateQueries(['product', id])
        setShowReviewForm(false)
        setReviewData({ rating: 5, comment: '' })
        toast.success('Review added successfully')
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to add review')
      }
    }
  )

  const handleAddToCart = async () => {
    if (!isAuthenticated) {
      toast.error('Please login to add items to cart')
      return
    }
    await addToCart(id, quantity)
  }

  const handleSubmitReview = (e) => {
    e.preventDefault()
    if (!isAuthenticated) {
      toast.error('Please login to add a review')
      return
    }
    addReviewMutation.mutate(reviewData)
  }

  const nextImage = () => {
    if (product?.images?.length > 1) {
      setSelectedImage((prev) => (prev + 1) % product.images.length)
    }
  }

  const prevImage = () => {
    if (product?.images?.length > 1) {
      setSelectedImage((prev) => (prev - 1 + product.images.length) % product.images.length)
    }
  }

  const tabs = [
    { id: 'description', label: 'Description', icon: MessageCircle },
    { id: 'reviews', label: 'Reviews', icon: Star, count: reviews?.length || 0 },
    { id: 'shipping', label: 'Shipping & Returns', icon: Truck }
  ]

  if (isLoading) {
    return (
      <div className="min-h-screen py-8">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            <div className="space-y-4">
              <div className="skeleton h-96 rounded-2xl" />
              <div className="flex space-x-2">
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="skeleton h-20 w-20 rounded-xl" />
                ))}
              </div>
            </div>
            <div className="space-y-6">
              <div className="skeleton h-8 w-3/4" />
              <div className="skeleton h-6 w-1/2" />
              <div className="skeleton h-12 w-1/3" />
              <div className="skeleton h-32" />
              <div className="skeleton h-12" />
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (error || !product) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-24 h-24 mx-auto mb-6 bg-red-100 rounded-full flex items-center justify-center">
            <AlertCircle className="w-12 h-12 text-red-600" />
          </div>
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Product not found</h2>
          <p className="text-slate-600 mb-6">The product you're looking for doesn't exist.</p>
          <Link to="/products" className="btn btn-primary btn-md">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Products
          </Link>
        </div>
      </div>
    )
  }

  const discountPercentage = product.comparePrice && product.comparePrice > product.price
    ? Math.round((1 - product.price / product.comparePrice) * 100)
    : 0

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Breadcrumb */}
        <nav className="mb-8">
          <div className="flex items-center space-x-2 text-sm text-slate-600">
            <Link to="/" className="hover:text-violet-600">Home</Link>
            <span>/</span>
            <Link to="/products" className="hover:text-violet-600">Products</Link>
            <span>/</span>
            <span className="text-slate-900 font-medium truncate">{product.name}</span>
          </div>
        </nav>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
          
          {/* Product Images */}
          <div className="space-y-4">
            <div className="relative aspect-square bg-white rounded-2xl overflow-hidden shadow-lg group">
              <AnimatePresence mode="wait">
                <motion.img
                  key={selectedImage}
                  src={product.images?.[0]?.url || 'https://via.placeholder.com/600'}
                  alt={product.name}
                  className="w-full h-full object-cover"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.3 }}
                />
              </AnimatePresence>
              
              {/* Discount Badge */}
              {discountPercentage > 0 && (
                <div className="absolute top-4 left-4 bg-red-500 text-white px-3 py-1 rounded-full text-sm font-bold">
                  -{discountPercentage}%
                </div>
              )}

              {/* Image Navigation */}
              {product.images?.length > 1 && (
                <>
                  <button
                    onClick={prevImage}
                    className="absolute left-4 top-1/2 transform -translate-y-1/2 w-10 h-10 bg-white/80 backdrop-blur-sm rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity hover:bg-white"
                  >
                    <ChevronLeft className="w-5 h-5" />
                  </button>
                  <button
                    onClick={nextImage}
                    className="absolute right-4 top-1/2 transform -translate-y-1/2 w-10 h-10 bg-white/80 backdrop-blur-sm rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity hover:bg-white"
                  >
                    <ChevronRight className="w-5 h-5" />
                  </button>
                </>
              )}

              {/* Wishlist & Share */}
              <div className="absolute top-4 right-4 space-y-2">
                <button className="w-10 h-10 bg-white/80 backdrop-blur-sm rounded-full flex items-center justify-center hover:bg-white group/btn">
                  <Heart className="w-5 h-5 text-slate-600 group-hover/btn:text-red-500 transition-colors" />
                </button>
                <button className="w-10 h-10 bg-white/80 backdrop-blur-sm rounded-full flex items-center justify-center hover:bg-white group/btn">
                  <Share2 className="w-5 h-5 text-slate-600 group-hover/btn:text-violet-500 transition-colors" />
                </button>
              </div>
            </div>

            {/* Image Thumbnails */}
            {product.images?.length > 1 && (
              <div className="flex space-x-2 overflow-x-auto pb-2">
                {product.images.map((image, index) => (
                  <button
                    key={index}
                    onClick={() => setSelectedImage(index)}
                    className={`flex-shrink-0 w-20 h-20 rounded-xl overflow-hidden border-2 transition-all ${
                      selectedImage === index 
                        ? 'border-violet-500 shadow-lg' 
                        : 'border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    <img
                      src={image}
                      alt={`${product.name} ${index + 1}`}
                      className="w-full h-full object-cover"
                    />
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Product Info */}
          <div className="space-y-6">
            
            {/* Product Title & Rating */}
            <div>
              <div className="flex items-center space-x-2 mb-2">
                {product.brand && (
                  <span className="px-3 py-1 bg-violet-100 text-violet-800 rounded-full text-sm font-medium">
                    {product.brand}
                  </span>
                )}
                {product.stockQuantity < 10 && (
                  <span className="px-3 py-1 bg-amber-100 text-amber-800 rounded-full text-sm font-medium flex items-center">
                    <AlertCircle className="w-3 h-3 mr-1" />
                    Low Stock
                  </span>
                )}
              </div>
              
              <h1 className="text-3xl font-bold text-slate-900 mb-4">{product.name}</h1>
              
              <div className="flex items-center space-x-4 mb-4">
                <div className="flex items-center">
                  {[...Array(5)].map((_, i) => (
                    <Star
                      key={i}
                      className={`w-5 h-5 ${
                        i < (product.rating || 4) 
                          ? 'text-yellow-400 fill-current' 
                          : 'text-slate-300'
                      }`}
                    />
                  ))}
                  <span className="ml-2 text-slate-600">
                    ({product.numReviews || 0} reviews)
                  </span>
                </div>
              </div>
            </div>

            {/* Price */}
            <div className="space-y-2">
              <div className="flex items-baseline space-x-4">
                <div className="text-4xl font-bold gradient-text">
                  ₹{product.price?.toLocaleString()}
                </div>
                {product.comparePrice && product.comparePrice > product.price && (
                  <div className="text-xl text-slate-500 line-through">
                    ₹{product.comparePrice.toLocaleString()}
                  </div>
                )}
              </div>
              {discountPercentage > 0 && (
                <div className="text-green-600 font-medium">
                  You save ₹{(product.comparePrice - product.price).toLocaleString()} ({discountPercentage}% off)
                </div>
              )}
            </div>

            {/* Key Features */}
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-4 bg-slate-50 rounded-xl">
                <Truck className="w-6 h-6 mx-auto mb-2 text-violet-600" />
                <div className="text-sm font-medium text-slate-900">Free Shipping</div>
                <div className="text-xs text-slate-600">On orders over ₹999</div>
              </div>
              <div className="text-center p-4 bg-slate-50 rounded-xl">
                <Shield className="w-6 h-6 mx-auto mb-2 text-violet-600" />
                <div className="text-sm font-medium text-slate-900">Secure Payment</div>
                <div className="text-xs text-slate-600">100% secure</div>
              </div>
              <div className="text-center p-4 bg-slate-50 rounded-xl">
                <RotateCcw className="w-6 h-6 mx-auto mb-2 text-violet-600" />
                <div className="text-sm font-medium text-slate-900">Easy Returns</div>
                <div className="text-xs text-slate-600">30-day return policy</div>
              </div>
            </div>

            {/* Quantity & Add to Cart */}
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <span className="text-slate-700 font-medium">Quantity:</span>
                <div className="flex items-center bg-slate-100 rounded-xl p-1">
                  <button
                    onClick={() => setQuantity(Math.max(1, quantity - 1))}
                    className="w-10 h-10 rounded-lg bg-white shadow-sm border border-slate-200 flex items-center justify-center hover:border-violet-300 transition-all"
                  >
                    <Minus className="w-4 h-4" />
                  </button>
                  <span className="w-12 text-center font-semibold">{quantity}</span>
                  <button
                    onClick={() => setQuantity(Math.min(product.stockQuantity, quantity + 1))}
                    disabled={quantity >= product.stockQuantity}
                    className="w-10 h-10 rounded-lg bg-white shadow-sm border border-slate-200 flex items-center justify-center hover:border-violet-300 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
                <span className="text-sm text-slate-600">
                  {product.stockQuantity} available
                </span>
              </div>
              
              <div className="flex space-x-4">
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={handleAddToCart}
                  disabled={product.stockQuantity === 0}
                  className="flex-1 btn btn-primary btn-lg disabled:opacity-50 disabled:cursor-not-allowed group"
                >
                  <ShoppingCart className="w-5 h-5 mr-2 group-hover:animate-bounce" />
                  {product.stockQuantity === 0 ? 'Out of Stock' : 'Add to Cart'}
                </motion.button>
                
                <button className="btn btn-outline btn-lg px-6 group">
                  <Heart className="w-5 h-5 group-hover:fill-current group-hover:text-red-500 transition-all" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Product Details Tabs */}
        <div className="mt-16">
          <div className="border-b border-slate-200">
            <div className="flex space-x-8">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`py-4 px-2 font-medium text-sm border-b-2 transition-colors flex items-center space-x-2 ${
                    activeTab === tab.id
                      ? 'border-violet-500 text-violet-600'
                      : 'border-transparent text-slate-500 hover:text-slate-700'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                  {tab.count !== undefined && tab.count > 0 && (
                    <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded-full text-xs">
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>

          <div className="py-8">
            <AnimatePresence mode="wait">
              {activeTab === 'description' && (
                <motion.div
                  key="description"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="prose prose-slate max-w-none"
                >
                  <div className="text-slate-700 leading-relaxed whitespace-pre-line">
                    {product.description || 'No description available for this product.'}
                  </div>
                </motion.div>
              )}

              {activeTab === 'reviews' && (
                <motion.div
                  key="reviews"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-8"
                >
                  {/* Add Review Button */}
                  {isAuthenticated && !showReviewForm && (
                    <button
                      onClick={() => setShowReviewForm(true)}
                      className="btn btn-primary btn-md"
                    >
                      Write a Review
                    </button>
                  )}

                  {/* Review Form */}
                  {showReviewForm && (
                    <form onSubmit={handleSubmitReview} className="card p-6 space-y-4">
                      <h3 className="text-lg font-semibold text-slate-900">Write a Review</h3>
                      
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">Rating</label>
                        <div className="flex space-x-1">
                          {[1, 2, 3, 4, 5].map((rating) => (
                            <button
                              key={rating}
                              type="button"
                              onClick={() => setReviewData(prev => ({ ...prev, rating }))}
                              className="p-1"
                            >
                              <Star
                                className={`w-6 h-6 ${
                                  rating <= reviewData.rating
                                    ? 'text-yellow-400 fill-current'
                                    : 'text-slate-300'
                                }`}
                              />
                            </button>
                          ))}
                        </div>
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">Review</label>
                        <textarea
                          value={reviewData.comment}
                          onChange={(e) => setReviewData(prev => ({ ...prev, comment: e.target.value }))}
                          className="input min-h-[120px]"
                          placeholder="Share your experience with this product..."
                          required
                        />
                      </div>
                      
                      <div className="flex space-x-4">
                        <button
                          type="submit"
                          disabled={addReviewMutation.isLoading}
                          className="btn btn-primary btn-md disabled:opacity-50"
                        >
                          {addReviewMutation.isLoading ? 'Submitting...' : 'Submit Review'}
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowReviewForm(false)}
                          className="btn btn-outline btn-md"
                        >
                          Cancel
                        </button>
                      </div>
                    </form>
                  )}

                  {/* Reviews List */}
                  <div className="space-y-6">
                    {reviews?.map((review, index) => (
                      <motion.div
                        key={review._id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1 }}
                        className="card p-6"
                      >
                        <div className="flex items-start space-x-4">
                          <div className="w-12 h-12 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-full flex items-center justify-center">
                            <span className="text-white font-semibold">
                              {review.user?.name?.charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-2">
                              <div>
                                <h4 className="font-semibold text-slate-900">{review.user?.name}</h4>
                                <div className="flex items-center space-x-2">
                                  <div className="flex">
                                    {[...Array(5)].map((_, i) => (
                                      <Star
                                        key={i}
                                        className={`w-4 h-4 ${
                                          i < review.rating
                                            ? 'text-yellow-400 fill-current'
                                            : 'text-slate-300'
                                        }`}
                                      />
                                    ))}
                                  </div>
                                  <span className="text-sm text-slate-500">
                                    {new Date(review.createdAt).toLocaleDateString()}
                                  </span>
                                </div>
                              </div>
                              <button className="p-2 text-slate-400 hover:text-violet-600 transition-colors">
                                <ThumbsUp className="w-4 h-4" />
                              </button>
                            </div>
                            {review.comment && (
                              <p className="text-slate-700 leading-relaxed">{review.comment}</p>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    ))}

                    {(!reviews || reviews.length === 0) && (
                      <div className="text-center py-12">
                        <div className="w-16 h-16 mx-auto mb-4 bg-slate-100 rounded-full flex items-center justify-center">
                          <Star className="w-8 h-8 text-slate-400" />
                        </div>
                        <h3 className="text-lg font-semibold text-slate-900 mb-2">No reviews yet</h3>
                        <p className="text-slate-600">Be the first to review this product!</p>
                      </div>
                    )}
                  </div>
                </motion.div>
              )}

              {activeTab === 'shipping' && (
                <motion.div
                  key="shipping"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="grid grid-cols-1 md:grid-cols-2 gap-8"
                >
                  <div className="card p-6">
                    <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center">
                      <Truck className="w-5 h-5 mr-2 text-violet-600" />
                      Shipping Information
                    </h3>
                    <div className="space-y-4 text-slate-700">
                      <div>
                        <h4 className="font-medium mb-2">Free Shipping</h4>
                        <p className="text-sm">On orders over ₹999. Standard delivery takes 3-5 business days.</p>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Express Shipping</h4>
                        <p className="text-sm">₹99 for orders under ₹999. Delivery in 1-2 business days.</p>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Same Day Delivery</h4>
                        <p className="text-sm">Available in select cities for ₹199. Order before 2 PM.</p>
                      </div>
                    </div>
                  </div>

                  <div className="card p-6">
                    <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center">
                      <RotateCcw className="w-5 h-5 mr-2 text-violet-600" />
                      Returns & Exchanges
                    </h3>
                    <div className="space-y-4 text-slate-700">
                      <div>
                        <h4 className="font-medium mb-2">30-Day Returns</h4>
                        <p className="text-sm">Easy returns within 30 days of delivery. No questions asked.</p>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Free Returns</h4>
                        <p className="text-sm">We'll cover the return shipping cost for defective or incorrect items.</p>
                      </div>
                      <div>
                        <h4 className="font-medium mb-2">Quick Refunds</h4>
                        <p className="text-sm">Refunds processed within 5-7 business days after we receive your return.</p>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ProductDetail
