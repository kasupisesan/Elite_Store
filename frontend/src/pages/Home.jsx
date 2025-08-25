import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from 'react-query'
import { 
  ArrowRight, 
  Star, 
  ShoppingCart, 
  Truck, 
  Shield, 
  Headphones,
  Zap,
  TrendingUp,
  Award,
  Users,
  Sparkles,
  Play,
  Gift,
  ChevronLeft,
  ChevronRight
} from 'lucide-react'
import { productsAPI } from '../utils/api'
import { useCart } from '../contexts/CartContext'
import { useAuth } from '../contexts/AuthContext'
import toast from 'react-hot-toast'

function Home() {
  const { addToCart } = useCart()
  const { isAuthenticated } = useAuth()
  const [currentSlide, setCurrentSlide] = useState(0)
  const [isAutoPlaying, setIsAutoPlaying] = useState(true)
  const [slideDirection, setSlideDirection] = useState('next')

  const { data: featuredProducts, isLoading } = useQuery(
    ['featuredProducts'],
    () => productsAPI.getProducts({ 
      sortBy: 'createdAt:desc', 
      limit: 8, 
      page: 1
    }),
    { 
      select: (response) => response.data, 
      staleTime: 5 * 60 * 1000,           
      cacheTime: 10 * 60 * 1000           
    }
  )

  const handleAddToCart = async (productId) => {
    if (!isAuthenticated) {
      toast.error('Please login to add items to cart')
      return
    }
    await addToCart(productId, 1)
  }

  const heroSlides = [
    {
      id: 1,
      title: "Summer Collection",
      subtitle: "Up to 70% Off",
      description: "Discover the latest trends in fashion and lifestyle",
      image: "https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=1200&h=800&fit=crop&q=80",
      cta: "Shop Now",
      color: "from-orange-500 to-pink-500"
    },
    {
      id: 2,
      title: "Tech Essentials",
      subtitle: "Latest Gadgets",
      description: "Stay ahead with cutting-edge technology",
      image: "https://images.unsplash.com/photo-1498049794561-7780e7231661?w=1200&h=800&fit=crop&q=80",
      cta: "Explore",
      color: "from-blue-500 to-purple-500"
    },
    {
      id: 3,
      title: "Home & Garden",
      subtitle: "Transform Your Space",
      description: "Create your perfect living environment",
      image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=1200&h=800&fit=crop&q=80",
      cta: "Shop Collection",
      color: "from-green-500 to-teal-500"
    },
    {
      id: 4,
      title: "Sports & Fitness",
      subtitle: "Get Active",
      description: "Premium gear for your active lifestyle",
      image: "https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=1200&h=800&fit=crop&q=80",
      cta: "Get Moving",
      color: "from-red-500 to-orange-500"
    }
  ]

  const categories = [
    { 
      name: 'Electronics', 
      image: 'https://images.unsplash.com/photo-1498049794561-7780e7231661?w=400',
      link: '/products?category=electronics',
      icon: Zap,
      description: 'Latest gadgets & tech'
    },
    { 
      name: 'Fashion', 
      image: 'https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=400',
      link: '/products?category=clothing',
      icon: Sparkles,
      description: 'Trending styles'
    },
    { 
      name: 'Home & Garden', 
      image: 'https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400',
      link: '/products?category=home',
      icon: Award,
      description: 'Premium quality'
    },
    { 
      name: 'Sports', 
      image: 'https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400',
      link: '/products?category=sports',
      icon: TrendingUp,
      description: 'Stay active'
    }
  ]

  const features = [
    { 
      icon: Truck, 
      title: 'Free Shipping', 
      description: 'Free shipping on orders over ₹999',
      color: 'from-blue-500 to-cyan-500'
    },
    { 
      icon: Shield, 
      title: 'Secure Payment', 
      description: '100% secure payment processing',
      color: 'from-green-500 to-emerald-500'
    },
    { 
      icon: Headphones, 
      title: '24/7 Support', 
      description: 'Round the clock customer support',
      color: 'from-purple-500 to-pink-500'
    },
    { 
      icon: Gift, 
      title: 'Easy Returns', 
      description: '30-day hassle-free returns',
      color: 'from-orange-500 to-red-500'
    }
  ]

  const stats = [
    { number: '10K+', label: 'Happy Customers', icon: Users },
    { number: '50K+', label: 'Products Sold', icon: ShoppingCart },
    { number: '99.9%', label: 'Satisfaction Rate', icon: Star },
    { number: '24/7', label: 'Support Available', icon: Headphones }
  ]

  // Enhanced navigation functions
  const nextSlide = () => {
    setSlideDirection('next')
    setCurrentSlide((prev) => (prev + 1) % heroSlides.length)
    setIsAutoPlaying(false)
    // Resume auto-play after 3 seconds
    setTimeout(() => setIsAutoPlaying(true), 3000)
  }

  const prevSlide = () => {
    setSlideDirection('prev')
    setCurrentSlide((prev) => (prev - 1 + heroSlides.length) % heroSlides.length)
    setIsAutoPlaying(false)
    // Resume auto-play after 3 seconds
    setTimeout(() => setIsAutoPlaying(true), 3000)
  }

  const goToSlide = (index) => {
    setSlideDirection(index > currentSlide ? 'next' : 'prev')
    setCurrentSlide(index)
    setIsAutoPlaying(false)
    setTimeout(() => setIsAutoPlaying(true), 3000)
  }

  // Enhanced auto-slide functionality
  useEffect(() => {
    if (!isAutoPlaying) return
    
    const timer = setInterval(() => {
      setSlideDirection('next')
      setCurrentSlide((prev) => (prev + 1) % heroSlides.length)
    }, 6000)
    
    return () => clearInterval(timer)
  }, [isAutoPlaying, heroSlides.length])

  // Animation variants
  const slideVariants = {
    enter: (direction) => ({
      x: direction === 'next' ? '100%' : '-100%',
      opacity: 0,
      scale: 1.1
    }),
    center: {
      x: 0,
      opacity: 1,
      scale: 1,
      transition: {
        duration: 0.8,
        ease: [0.25, 0.46, 0.45, 0.94]
      }
    },
    exit: (direction) => ({
      x: direction === 'next' ? '-100%' : '100%',
      opacity: 0,
      scale: 0.9,
      transition: {
        duration: 0.3,
        ease: [0.25, 0.46, 0.45, 0.94]
      }
    })
  }

  const textVariants = {
    hidden: {
      opacity: 0,
      y: 50,
      scale: 0.9
    },
    visible: (delay) => ({
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        duration: 0.8,
        delay: delay * 0.2,
        ease: [0.25, 0.46, 0.45, 0.94]
      }
    })
  }

  return (
    <div className="min-h-screen">
      {/* Enhanced Hero Section with Navigation */}
      <section className="relative h-[80vh] md:h-[90vh] overflow-hidden">
        <AnimatePresence mode="wait" custom={slideDirection}>
          <motion.div
            key={currentSlide}
            custom={slideDirection}
            variants={slideVariants}
            initial="enter"
            animate="center"
            exit="exit"
            className={`absolute inset-0 bg-gradient-to-r ${heroSlides[currentSlide].color}`}
          >
            {/* Background overlay */}
            <div className="absolute inset-0 bg-black/30" />
            
            {/* Background image with parallax effect */}
            <motion.div 
              className="absolute inset-0 bg-cover bg-center"
              style={{ backgroundImage: `url(${heroSlides[currentSlide].image})` }}
              initial={{ scale: 1.2 }}
              animate={{ scale: 1 }}
              transition={{ duration: 8, ease: "linear" }}
            />
            
            {/* Gradient overlay */}
            <div className="absolute inset-0 bg-gradient-to-t from-black/50 via-transparent to-black/20" />
            
            {/* Content */}
            <div className="relative z-10 h-full flex items-center">
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full">
                <div className="max-w-4xl">
                  <motion.div
                    custom={0}
                    variants={textVariants}
                    initial="hidden"
                    animate="visible"
                    className="mb-6"
                  >
                    <span className="inline-block px-6 py-3 bg-white/20 backdrop-blur-md rounded-full text-white text-sm font-medium shadow-lg border border-white/20">
                      ✨ {heroSlides[currentSlide].subtitle}
                    </span>
                  </motion.div>
                  
                  <motion.h1
                    custom={1}
                    variants={textVariants}
                    initial="hidden"
                    animate="visible"
                    className="text-5xl md:text-7xl lg:text-8xl font-bold text-white mb-8 leading-tight"
                  >
                    {heroSlides[currentSlide].title}
                  </motion.h1>
                  
                  <motion.p
                    custom={2}
                    variants={textVariants}
                    initial="hidden"
                    animate="visible"
                    className="text-xl md:text-3xl text-white/90 mb-12 leading-relaxed max-w-3xl"
                  >
                    {heroSlides[currentSlide].description}
                  </motion.p>
                  
                  <motion.div
                    custom={3}
                    variants={textVariants}
                    initial="hidden"
                    animate="visible"
                    className="flex flex-col sm:flex-row gap-6"
                  >
                    <Link
                      to="/products"
                      className="group px-10 py-5 bg-white text-slate-900 rounded-2xl font-bold text-lg hover:bg-slate-100 transition-all inline-flex items-center justify-center shadow-2xl hover:shadow-white/25 hover:scale-105"
                    >
                      <span>{heroSlides[currentSlide].cta}</span>
                      <ArrowRight className="ml-3 w-6 h-6 group-hover:translate-x-2 transition-transform" />
                    </Link>
                    
                  </motion.div>
                </div>
              </div>
            </div>
          </motion.div>
        </AnimatePresence>

        {/* Navigation Arrows */}
        <button
          onClick={prevSlide}
          className="absolute left-6 top-1/2 -translate-y-1/2 z-20 w-14 h-14 bg-white/20 backdrop-blur-md rounded-full flex items-center justify-center text-white hover:bg-white/30 transition-all hover:scale-110 shadow-xl border border-white/20 group"
          aria-label="Previous slide"
        >
          <ChevronLeft className="w-7 h-7 group-hover:scale-110 transition-transform" />
        </button>
        
        <button
          onClick={nextSlide}
          className="absolute right-6 top-1/2 -translate-y-1/2 z-20 w-14 h-14 bg-white/20 backdrop-blur-md rounded-full flex items-center justify-center text-white hover:bg-white/30 transition-all hover:scale-110 shadow-xl border border-white/20 group"
          aria-label="Next slide"
        >
          <ChevronRight className="w-7 h-7 group-hover:scale-110 transition-transform" />
        </button>

        {/* Enhanced Slide Indicators */}
        <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2 flex space-x-4 z-20">
          {heroSlides.map((_, index) => (
            <button
              key={index}
              onClick={() => goToSlide(index)}
              className={`relative transition-all duration-300 ${
                currentSlide === index 
                  ? 'w-12 h-4' 
                  : 'w-4 h-4 hover:w-6'
              }`}
              aria-label={`Go to slide ${index + 1}`}
            >
              <div className={`absolute inset-0 rounded-full transition-all duration-300 ${
                currentSlide === index 
                  ? 'bg-white shadow-lg' 
                  : 'bg-white/50 hover:bg-white/70'
              }`} />
              {currentSlide === index && (
                <motion.div
                  layoutId="activeSlide"
                  className="absolute inset-0 bg-white rounded-full shadow-lg"
                  transition={{ type: "spring", stiffness: 300, damping: 30 }}
                />
              )}
            </button>
          ))}
        </div>

        {/* Progress Bar */}
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/20 z-20">
          <motion.div
            className="h-full bg-white"
            initial={{ width: "0%" }}
            animate={{ width: "100%" }}
            transition={{ duration: 6, ease: "linear", repeat: Infinity }}
            key={currentSlide}
          />
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="text-center group"
              >
                <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-3xl flex items-center justify-center shadow-xl group-hover:shadow-violet-500/25 transition-all group-hover:scale-110">
                  <stat.icon className="w-10 h-10 text-white" />
                </div>
                <div className="text-4xl md:text-5xl font-bold text-slate-900 mb-3">{stat.number}</div>
                <div className="text-slate-600 font-medium text-lg">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 bg-gradient-to-br from-slate-50 to-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            className="text-center mb-20"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-slate-900 mb-6">
              Why Choose <span className="gradient-text">EliteStore</span>?
            </h2>
            <p className="text-xl text-slate-600 max-w-3xl mx-auto">
              Experience the difference with our premium service and unmatched quality
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="group"
              >
                <div className="card card-hover p-10 text-center h-full">
                  <div className={`w-20 h-20 mx-auto mb-8 bg-gradient-to-r ${feature.color} rounded-3xl flex items-center justify-center shadow-xl group-hover:shadow-lg transition-all group-hover:scale-110 group-hover:rotate-3`}>
                    <feature.icon className="w-10 h-10 text-white" />
                  </div>
                  <h3 className="text-2xl font-semibold text-slate-900 mb-4">{feature.title}</h3>
                  <p className="text-slate-600 leading-relaxed text-lg">{feature.description}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Categories Section */}
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            className="text-center mb-20"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-slate-900 mb-6">
              Shop by <span className="gradient-text">Category</span>
            </h2>
            <p className="text-xl text-slate-600 max-w-3xl mx-auto">
              Explore our wide range of categories and find exactly what you're looking for
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {categories.map((category, index) => (
              <motion.div
                key={category.name}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className="group"
              >
                <Link to={category.link} className="block">
                  <div className="card card-hover overflow-hidden">
                    <div className="relative h-80 overflow-hidden">
                      <img
                        src={category.image}
                        alt={category.name}
                        className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500"
                        loading="lazy"
                      />
                      <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                      <div className="absolute top-6 left-6">
                        <div className="w-16 h-16 bg-white/20 backdrop-blur-sm rounded-2xl flex items-center justify-center">
                          <category.icon className="w-8 h-8 text-white" />
                        </div>
                      </div>
                      <div className="absolute bottom-6 left-6 right-6">
                        <h3 className="text-2xl font-bold text-white mb-2">{category.name}</h3>
                        <p className="text-white/90 text-lg">{category.description}</p>
                      </div>
                    </div>
                  </div>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Enhanced Featured Products Section */}
      <section className="py-24 bg-gradient-to-br from-slate-50 to-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            className="text-center mb-20"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-slate-900 mb-6">
              Latest <span className="gradient-text">Arrivals</span>
            </h2>
            <p className="text-xl text-slate-600 max-w-3xl mx-auto">
              Discover our newest products, fresh from the store
            </p>
            {featuredProducts?.pagination && (
              <div className="mt-4 text-sm text-slate-500">
                Showing latest 8 of {featuredProducts.pagination.total} products
              </div>
            )}
          </motion.div>

          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
              {[...Array(8)].map((_, index) => (
                <div key={index} className="card p-6">
                  <div className="skeleton h-56 mb-6 rounded-2xl" />
                  <div className="skeleton h-6 mb-3" />
                  <div className="skeleton h-4 mb-6" />
                  <div className="skeleton h-12 rounded-xl" />
                </div>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
              {featuredProducts?.data?.map((product, index) => (
                <motion.div
                  key={product._id}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="group"
                >
                  <div className="card card-hover overflow-hidden">
                    <div className="relative">
                      <img
                        src={product.images?.[0]?.url || product.images?.[0] || 'https://images.unsplash.com/photo-1560472355-536de3962603?w=400'}
                        alt={product.name}
                        className="w-full h-56 object-cover group-hover:scale-105 transition-transform duration-300"
                        onError={(e) => {
                          e.target.src = 'https://images.unsplash.com/photo-1560472355-536de3962603?w=400';
                        }}
                        loading="lazy"
                      />
                      <div className="absolute top-4 right-4 space-y-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button className="w-12 h-12 bg-white/90 rounded-xl flex items-center justify-center hover:bg-white shadow-lg transition-all hover:scale-110">
                          <Star className="w-6 h-6 text-slate-600 hover:text-yellow-400" />
                        </button>
                      </div>
                      <div className="absolute top-4 left-4">
                        <span className="inline-block px-3 py-1 bg-green-500 text-white text-sm font-medium rounded-full">
                          New
                        </span>
                      </div>
                    </div>
                    <div className="p-8">
                      <Link to={`/products/${product._id}`}>
                        <h3 className="font-bold text-xl text-slate-900 mb-3 group-hover:text-violet-600 transition-colors line-clamp-2">
                          {product.name}
                        </h3>
                      </Link>
                      {product.brand && (
                        <p className="text-sm text-slate-500 mb-3 font-medium">{product.brand}</p>
                      )}
                      <div className="flex items-center mb-4">
                        {[...Array(5)].map((_, i) => (
                          <Star
                            key={i}
                            className={`w-5 h-5 ${
                              i < Math.floor(product.averageRating || 4) 
                                ? 'text-yellow-400 fill-current' 
                                : 'text-slate-300'
                            }`}
                          />
                        ))}
                        <span className="text-sm text-slate-500 ml-2 font-medium">
                          ({product.numReviews || 0})
                        </span>
                      </div>
                      <div className="flex items-center justify-between mb-6">
                        <div className="text-3xl font-bold gradient-text">
                          ₹{product.price?.toLocaleString()}
                        </div>
                        {product.originalPrice && product.originalPrice > product.price && (
                          <span className="text-lg text-slate-500 line-through">
                            ₹{product.originalPrice.toLocaleString()}
                          </span>
                        )}
                      </div>
                      <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => handleAddToCart(product._id)}
                        className="w-full btn btn-primary btn-lg group"
                      >
                        <ShoppingCart className="w-5 h-5 mr-2 group-hover:animate-bounce" />
                        Add to Cart
                      </motion.button>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            className="text-center mt-16"
          >
            <Link to="/products" className="btn btn-outline btn-lg group">
              View All Products
              <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </Link>
          </motion.div>
        </div>
      </section>

    
    </div>
  )
}

export default Home
