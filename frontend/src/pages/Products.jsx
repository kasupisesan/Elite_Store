import { useState, useEffect } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from 'react-query'
import { 
  Filter, 
  Grid, 
  List, 
  Star, 
  ShoppingCart, 
  ChevronDown, 
  X, 
  Search, 
  Heart, 
  SlidersHorizontal, 
  ArrowUpDown, 
  Zap, 
  Package 
} from 'lucide-react'
import { productsAPI } from '../utils/api'
import { useCart } from '../contexts/CartContext'
import { useAuth } from '../contexts/AuthContext'
import toast from 'react-hot-toast'

function Products() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [viewMode, setViewMode] = useState('grid')
  const [showFilters, setShowFilters] = useState(false)
  const [filters, setFilters] = useState({
    category: searchParams.get('category') || '',
    minPrice: searchParams.get('minPrice') || '',
    maxPrice: searchParams.get('maxPrice') || '',
    brand: searchParams.get('brand') || '',
    sortBy: searchParams.get('sortBy') || 'createdAt',
    page: parseInt(searchParams.get('page')) || 1,
    limit: 12,
    q: searchParams.get('q') || ''
  })

  const { addToCart } = useCart()
  const { isAuthenticated } = useAuth()

  const { data, isLoading, error } = useQuery(
    ['products', filters],
    () => {
      if (filters.q && filters.q.trim() !== '') {
        return productsAPI.searchProducts(filters)
      }
      return productsAPI.getProducts(filters)
    },
    {
      select: (response) => response.data,
      keepPreviousData: true
    }
  )

  const categories = [
    { value: 'electronics', label: ' Electronics', count: 245 },
    { value: 'clothing', label: ' Fashion', count: 189 },
    { value: 'books', label: ' Books', count: 156 },
    { value: 'home', label: ' Home & Garden', count: 198 },
    { value: 'sports', label: ' Sports', count: 134 },
    { value: 'beauty', label: ' Beauty', count: 87 },
    { value: 'toys', label: ' Toys', count: 76 },
    { value: 'automotive', label: ' Automotive', count: 92 },
    { value: 'other', label: ' Other', count: 53 }
  ]

  const sortOptions = [
    { value: 'createdAt:desc', label: ' Newest First' },
    { value: 'createdAt', label: ' Oldest First' },
    { value: 'price', label: ' Price: Low to High' },
    { value: 'price:desc', label: ' Price: High to Low' },
    { value: 'name', label: ' Name: A to Z' },
    { value: 'name:desc', label: ' Name: Z to A' },
    { value: 'rating:desc', label: ' Top Rated' }
  ]

  useEffect(() => {
    const params = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => {
      if (value && value !== '') {
        params.set(key, value.toString())
      }
    })
    setSearchParams(params)
  }, [filters, setSearchParams])

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value,
      page: 1
    }))
  }

  const clearFilters = () => {
    setFilters({
      category: '',
      minPrice: '',
      maxPrice: '',
      brand: '',
      sortBy: 'createdAt',
      page: 1,
      limit: 12,
      q: ''
    })
  }

  const handleAddToCart = async (productId) => {
    if (!isAuthenticated) {
      toast.error('Please login to add items to cart')
      return
    }
    await addToCart(productId, 1)
  }

  const handlePageChange = (newPage) => {
    setFilters(prev => ({ ...prev, page: newPage }))
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 flex items-center justify-center p-4">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center max-w-md w-full"
        >
          <div className="w-16 h-16 sm:w-20 sm:h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4 sm:mb-6">
            <Package className="w-8 h-8 sm:w-10 sm:h-10 text-red-600" />
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 mb-3 sm:mb-4">Oops! Something went wrong</h2>
          <p className="text-slate-600 mb-4 sm:mb-6 text-sm sm:text-base">We couldn't load the products. Please try again later.</p>
          <button 
            onClick={() => window.location.reload()}
            className="btn btn-primary btn-md sm:btn-lg w-full sm:w-auto"
          >
            Try Again
          </button>
        </motion.div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50">
      <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6 xl:px-8 py-4 sm:py-6 lg:py-8">
        
        {/* 📱 Mobile-Optimized Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 sm:mb-8 lg:mb-12"
        >
          <div className="text-center mb-6 sm:mb-8">
            <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold gradient-text mb-2 sm:mb-4">
              Discover Amazing Products
            </h1>
            <p className="text-slate-600 text-sm sm:text-base lg:text-lg max-w-2xl mx-auto px-4">
              {data?.pagination?.total || 0} carefully curated products waiting for you
              {filters.q && (
                <span className="block mt-1 sm:mt-2 text-violet-600 font-medium text-sm sm:text-base">
                  Search results for "{filters.q}"
                </span>
              )}
            </p>
          </div>

          {/* 📱 Mobile-First Action Bar */}
          <div className="space-y-4">
            {/* Mobile Search Bar */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-4 h-4 sm:w-5 sm:h-5" />
              <input
                type="text"
                value={filters.q}
                onChange={(e) => handleFilterChange('q', e.target.value)}
                placeholder="Search products..."
                className="w-full pl-10 sm:pl-12 pr-4 py-3 sm:py-3 bg-white border border-slate-200 rounded-xl focus:ring-2 focus:ring-violet-500 focus:border-transparent text-sm sm:text-base"
              />
            </div>

            {/* Mobile Controls Row */}
            <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
              {/* Sort Dropdown - Full width on mobile */}
              <div className="relative flex-1">
                <select
                  value={filters.sortBy}
                  onChange={(e) => handleFilterChange('sortBy', e.target.value)}
                  className="w-full appearance-none bg-white border border-slate-200 rounded-xl px-3 sm:px-4 py-3 pr-8 focus:ring-2 focus:ring-violet-500 focus:border-transparent text-sm sm:text-base"
                >
                  {sortOptions.map(option => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
                <ArrowUpDown className="absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              </div>

              {/* View Toggle & Filter Button */}
              <div className="flex gap-2 sm:gap-3">
                {/* View Toggle */}
                <div className="flex bg-white rounded-xl p-1 shadow-sm border border-slate-200">
                  <button
                    onClick={() => setViewMode('grid')}
                    className={`p-2 sm:p-2.5 rounded-lg transition-all ${
                      viewMode === 'grid'
                        ? 'bg-violet-600 text-white shadow-sm'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                  >
                    <Grid className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setViewMode('list')}
                    className={`p-2 sm:p-2.5 rounded-lg transition-all ${
                      viewMode === 'list'
                        ? 'bg-violet-600 text-white shadow-sm'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                  >
                    <List className="w-4 h-4" />
                  </button>
                </div>

                {/* Filter Button */}
                <button
                  onClick={() => setShowFilters(!showFilters)}
                  className={`flex items-center px-3 sm:px-4 py-2.5 bg-white border border-slate-200 rounded-xl transition-all ${
                    showFilters ? 'bg-violet-50 border-violet-200 text-violet-700' : 'text-slate-600'
                  }`}
                >
                  <SlidersHorizontal className="w-4 h-4 mr-2" />
                  <span className="text-sm sm:text-base">Filters</span>
                </button>
              </div>
            </div>
          </div>
        </motion.div>

        <div className="flex flex-col lg:flex-row gap-4 sm:gap-6 lg:gap-8">
          
          {/* 📱 Mobile-Friendly Filters Sidebar */}
          <AnimatePresence>
            {showFilters && (
              <>
                {/* Mobile Overlay */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="fixed inset-0 bg-black/50 z-40 lg:hidden"
                  onClick={() => setShowFilters(false)}
                />
                
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="fixed left-0 top-0 bottom-0 w-80 max-w-[85vw] bg-white z-50 lg:relative lg:z-auto lg:w-72 xl:w-80 lg:max-w-none overflow-y-auto"
                >
                  <div className="p-4 sm:p-6 h-full">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-lg sm:text-xl font-bold text-slate-900 flex items-center">
                        <Filter className="w-5 h-5 mr-2 text-violet-600" />
                        Filters
                      </h3>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={clearFilters}
                          className="text-sm text-violet-600 hover:text-violet-700 font-medium"
                        >
                          Clear All
                        </button>
                        <button
                          onClick={() => setShowFilters(false)}
                          className="p-1 hover:bg-slate-100 rounded-lg"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    </div>

                    {/* Categories */}
                    <div className="mb-6 sm:mb-8">
                      <h4 className="font-semibold text-slate-900 mb-4 flex items-center text-sm sm:text-base">
                        <Package className="w-4 h-4 mr-2 text-slate-600" />
                        Categories
                      </h4>
                      <div className="space-y-1 sm:space-y-2">
                        <label className="flex items-center p-2 rounded-lg hover:bg-slate-50 cursor-pointer">
                          <input
                            type="radio"
                            name="category"
                            value=""
                            checked={filters.category === ''}
                            onChange={(e) => handleFilterChange('category', e.target.value)}
                            className="sr-only"
                          />
                          <div className={`w-4 h-4 rounded-full border-2 mr-3 ${
                            filters.category === '' ? 'border-violet-600 bg-violet-600' : 'border-slate-300'
                          }`}>
                            {filters.category === '' && <div className="w-2 h-2 bg-white rounded-full mx-auto mt-0.5" />}
                          </div>
                          <span className="text-slate-700 text-sm sm:text-base">All Categories</span>
                        </label>
                        {categories.map(category => (
                          <label key={category.value} className="flex items-center justify-between p-2 rounded-lg hover:bg-slate-50 cursor-pointer">
                            <div className="flex items-center flex-1">
                              <input
                                type="radio"
                                name="category"
                                value={category.value}
                                checked={filters.category === category.value}
                                onChange={(e) => handleFilterChange('category', e.target.value)}
                                className="sr-only"
                              />
                              <div className={`w-4 h-4 rounded-full border-2 mr-3 flex-shrink-0 ${
                                filters.category === category.value ? 'border-violet-600 bg-violet-600' : 'border-slate-300'
                              }`}>
                                {filters.category === category.value && <div className="w-2 h-2 bg-white rounded-full mx-auto mt-0.5" />}
                              </div>
                              <span className="text-slate-700 text-sm sm:text-base truncate">{category.label}</span>
                            </div>
                            <span className="text-xs text-slate-500 bg-slate-100 px-2 py-1 rounded-full flex-shrink-0 ml-2">
                              {category.count}
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>

                    {/* Price Range */}
                    <div className="mb-6 sm:mb-8">
                      <h4 className="font-semibold text-slate-900 mb-4 text-sm sm:text-base">Price Range</h4>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs sm:text-sm text-slate-600 mb-1">Min Price</label>
                          <input
                            type="number"
                            value={filters.minPrice}
                            onChange={(e) => handleFilterChange('minPrice', e.target.value)}
                            placeholder="₹0"
                            className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg focus:ring-2 focus:ring-violet-500 focus:border-transparent text-sm"
                          />
                        </div>
                        <div>
                          <label className="block text-xs sm:text-sm text-slate-600 mb-1">Max Price</label>
                          <input
                            type="number"
                            value={filters.maxPrice}
                            onChange={(e) => handleFilterChange('maxPrice', e.target.value)}
                            placeholder="₹99999"
                            className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg focus:ring-2 focus:ring-violet-500 focus:border-transparent text-sm"
                          />
                        </div>
                      </div>
                    </div>

                    {/* Brand Filter */}
                    <div className="mb-6">
                      <h4 className="font-semibold text-slate-900 mb-4 text-sm sm:text-base">Brand</h4>
                      <input
                        type="text"
                        value={filters.brand}
                        onChange={(e) => handleFilterChange('brand', e.target.value)}
                        placeholder="Enter brand name..."
                        className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg focus:ring-2 focus:ring-violet-500 focus:border-transparent text-sm"
                      />
                    </div>
                  </div>
                </motion.div>
              </>
            )}
          </AnimatePresence>

          {/* 📱 Mobile-Optimized Products Display */}
          <div className="flex-1">
            {isLoading ? (
              /* Loading Skeletons - Responsive Grid */
              <div className={`grid gap-3 sm:gap-4 lg:gap-6 ${
                viewMode === 'grid' 
                  ? 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3' 
                  : 'grid-cols-1'
              }`}>
                {[...Array(6)].map((_, index) => (
                  <div key={index} className="bg-white rounded-xl sm:rounded-2xl overflow-hidden shadow-sm">
                    <div className="skeleton h-40 sm:h-48 w-full"></div>
                    <div className="p-3 sm:p-4 lg:p-6">
                      <div className="skeleton h-4 sm:h-6 w-3/4 mb-2 sm:mb-3"></div>
                      <div className="skeleton h-3 sm:h-4 w-1/2 mb-3 sm:mb-4"></div>
                      <div className="skeleton h-8 sm:h-10 w-full rounded-lg sm:rounded-xl"></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : data?.data?.length === 0 ? (
              /* Empty State */
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-center py-8 sm:py-12 lg:py-16 px-4"
              >
                <div className="w-16 h-16 sm:w-20 sm:h-20 lg:w-24 lg:h-24 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4 sm:mb-6">
                  <Package className="w-8 h-8 sm:w-10 sm:h-10 lg:w-12 lg:h-12 text-slate-400" />
                </div>
                <h3 className="text-xl sm:text-2xl font-bold text-slate-900 mb-2 sm:mb-3">No products found</h3>
                <p className="text-slate-600 mb-6 sm:mb-8 max-w-md mx-auto text-sm sm:text-base">
                  Try adjusting your filters or search terms to find what you're looking for.
                </p>
                <button
                  onClick={clearFilters}
                  className="btn btn-primary btn-md sm:btn-lg w-full sm:w-auto"
                >
                  <Zap className="w-4 h-4 sm:w-5 sm:h-5 mr-2" />
                  Clear All Filters
                </button>
              </motion.div>
            ) : (
              <>
                {/* 📱 Responsive Products Grid */}
                <div className={`grid gap-3 sm:gap-4 lg:gap-6 ${
                  viewMode === 'grid' 
                    ? 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3' 
                    : 'grid-cols-1'
                }`}>
                  <AnimatePresence mode="popLayout">
                    {data?.data?.map((product, index) => (
                      <motion.div
                        key={product._id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.3, delay: index * 0.05 }}
                        className="group"
                      >
                        <div className={`bg-white rounded-xl sm:rounded-2xl overflow-hidden shadow-sm hover:shadow-lg transition-shadow ${
                          viewMode === 'list' ? 'flex flex-col sm:flex-row' : ''
                        }`}>
                          
                          {/* Product Image */}
                          <Link 
                            to={`/products/${product._id}`} 
                            className={`relative block ${
                              viewMode === 'list' ? 'w-full sm:w-48 flex-shrink-0' : ''
                            }`}
                          >
                            <div className="relative h-40 sm:h-48 bg-slate-100 overflow-hidden">
                              <img
                                src={product.images?.[0]?.url || 'https://via.placeholder.com/300'}
                                alt={product.name}
                                className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                                onError={(e) => {
                                  e.target.src = 'https://via.placeholder.com/300';
                                }}
                                loading="lazy"
                              />
                              {/* Wishlist Button */}
                              <button className="absolute top-2 right-2 sm:top-3 sm:right-3 w-7 h-7 sm:w-8 sm:h-8 bg-white/90 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity hover:bg-white shadow-sm">
                                <Heart className="w-3 h-3 sm:w-4 sm:h-4 text-slate-600 hover:text-red-500" />
                              </button>
                            </div>
                          </Link>

                          {/* Product Info */}
                          <div className="p-3 sm:p-4 lg:p-6 flex-1">
                            {/* Brand */}
                            {product.brand && (
                              <p className="text-xs sm:text-sm font-medium text-violet-600 mb-1 sm:mb-2">
                                {product.brand}
                              </p>
                            )}

                            {/* Product Name */}
                            <Link to={`/products/${product._id}`}>
                              <h3 className="font-bold text-slate-900 mb-2 sm:mb-3 hover:text-violet-600 transition-colors line-clamp-2 text-sm sm:text-base lg:text-lg">
                                {product.name}
                              </h3>
                            </Link>

                            {/* Description for List View */}
                            {viewMode === 'list' && (
                              <p className="text-slate-600 text-xs sm:text-sm mb-3 sm:mb-4 line-clamp-2">
                                {product.description}
                              </p>
                            )}

                            {/* Rating */}
                            <div className="flex items-center mb-3 sm:mb-4">
                              <div className="flex items-center">
                                {[...Array(5)].map((_, i) => (
                                  <Star
                                    key={i}
                                    className={`w-3 h-3 sm:w-4 sm:h-4 ${
                                      i < Math.floor(product.averageRating || 0)
                                        ? 'text-yellow-400 fill-current'
                                        : 'text-slate-300'
                                    }`}
                                  />
                                ))}
                              </div>
                              <span className="text-xs sm:text-sm text-slate-600 ml-1 sm:ml-2">
                                {product.averageRating?.toFixed(1) || '0.0'} ({product.numReviews || 0})
                              </span>
                            </div>

                            {/* Price */}
                            <div className="flex items-center justify-between mb-3 sm:mb-4 lg:mb-6">
                              <div className="flex items-center space-x-2">
                                <span className="text-lg sm:text-xl lg:text-2xl font-bold text-slate-900">
                                  ₹{product.price?.toLocaleString()}
                                </span>
                                {product.originalPrice && product.originalPrice > product.price && (
                                  <div className="flex items-center space-x-1 sm:space-x-2">
                                    <span className="text-xs sm:text-sm text-slate-500 line-through">
                                      ₹{product.originalPrice.toLocaleString()}
                                    </span>
                                    <span className="bg-green-100 text-green-800 text-xs px-1.5 py-0.5 sm:px-2 sm:py-1 rounded-full font-medium">
                                      {Math.round(((product.originalPrice - product.price) / product.originalPrice) * 100)}% OFF
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* Add to Cart Button */}
                            <button
                              onClick={() => handleAddToCart(product._id)}
                              className="w-full bg-gradient-to-r from-violet-600 to-indigo-600 text-white py-2.5 sm:py-3 px-4 rounded-lg sm:rounded-xl hover:from-violet-700 hover:to-indigo-700 transition-all flex items-center justify-center text-sm sm:text-base font-medium group/btn touch-manipulation"
                            >
                              <ShoppingCart className="w-3 h-3 sm:w-4 sm:h-4 mr-2 group-hover/btn:animate-bounce" />
                              Add to Cart
                            </button>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>

                {/* 📱 Mobile-Friendly Pagination */}
                {data?.pagination && data.pagination.pages > 1 && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="flex flex-col sm:flex-row justify-center items-center space-y-3 sm:space-y-0 sm:space-x-2 mt-8 sm:mt-12"
                  >
                    <button
                      onClick={() => handlePageChange(filters.page - 1)}
                      disabled={filters.page === 1}
                      className="w-full sm:w-auto px-4 py-2.5 bg-white border border-slate-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 text-sm sm:text-base transition-all touch-manipulation"
                    >
                      Previous
                    </button>
                    
                    <div className="flex space-x-1 sm:space-x-2 overflow-x-auto pb-2 sm:pb-0 max-w-full">
                      {[...Array(Math.min(5, data.pagination.pages))].map((_, index) => {
                        const page = index + 1
                        return (
                          <button
                            key={page}
                            onClick={() => handlePageChange(page)}
                            className={`w-8 h-8 sm:w-10 sm:h-10 rounded-lg sm:rounded-xl text-sm font-medium transition-all flex-shrink-0 touch-manipulation ${
                              page === filters.page
                                ? 'bg-violet-600 text-white shadow-lg'
                                : 'text-slate-600 hover:bg-slate-100'
                            }`}
                          >
                            {page}
                          </button>
                        )
                      })}
                    </div>
                    
                    <button
                      onClick={() => handlePageChange(filters.page + 1)}
                      disabled={filters.page === data.pagination.pages}
                      className="w-full sm:w-auto px-4 py-2.5 bg-white border border-slate-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 text-sm sm:text-base transition-all touch-manipulation"
                    >
                      Next
                    </button>
                  </motion.div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Products
