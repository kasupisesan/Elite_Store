import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { 
  Plus, 
  Search, 
  Filter, 
  Edit, 
  Trash2, 
  Eye, 
  Package, 
  AlertCircle,
  Star,
  TrendingUp,
  Image,
  DollarSign,
  Archive
} from 'lucide-react'
import { productsAPI } from '../../utils/api'
import { Link } from 'react-router-dom'
import toast from 'react-hot-toast'

function AdminProducts() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [productToDelete, setProductToDelete] = useState(null)
  const [viewMode, setViewMode] = useState('grid')

  const queryClient = useQueryClient()

  const { data: productsData, isLoading } = useQuery(
    ['adminProducts', currentPage, searchTerm, selectedCategory],
    () => productsAPI.getProducts({ 
      page: currentPage, 
      limit: viewMode === 'grid' ? 12 : 10, 
      search: searchTerm, 
      category: selectedCategory 
    }),
    { keepPreviousData: true }
  )

  const deleteProductMutation = useMutation(
    productsAPI.deleteProduct,
    {
      onSuccess: () => {
        queryClient.invalidateQueries('adminProducts')
        toast.success('Product deleted successfully')
        setShowDeleteModal(false)
        setProductToDelete(null)
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to delete product')
      }
    }
  )

  const handleDeleteProduct = (product) => {
    setProductToDelete(product)
    setShowDeleteModal(true)
  }

  const confirmDelete = () => {
    if (productToDelete) {
      deleteProductMutation.mutate(productToDelete._id)
    }
  }

  const categories = [
    { label: 'Electronics', value: 'electronics', emoji: '⚡' },
    { label: 'Fashion', value: 'clothing', emoji: '👕' },
    { label: 'Books', value: 'books', emoji: '📚' },
    { label: 'Home & Garden', value: 'home', emoji: '🏠' },
    { label: 'Sports', value: 'sports', emoji: '🏃' },
    { label: 'Beauty', value: 'beauty', emoji: '💄' },
    { label: 'Toys', value: 'toys', emoji: '🧸' },
    { label: 'Automotive', value: 'automotive', emoji: '🚗' },
    { label: 'Other', value: 'other', emoji: '📦' }
  ]

  const products = productsData?.data?.data || []
  const pagination = productsData?.data?.pagination || {}

  const totalValue = products.reduce((sum, product) => sum + (product.price * product.stockQuantity), 0)
  const lowStockCount = products.filter(product => product.stockQuantity < 10).length
  const outOfStockCount = products.filter(product => product.stockQuantity === 0).length

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex flex-col lg:flex-row lg:items-center justify-between gap-4"
          >
            <div>
              <h1 className="text-3xl font-bold gradient-text mb-2">Product Management</h1>
              <p className="text-slate-600">Manage your product inventory and listings</p>
            </div>
            <Link to="/admin/products/new" className="btn btn-primary btn-lg group">
              <Plus className="w-5 h-5 mr-2 group-hover:animate-bounce" />
              Add New Product
            </Link>
          </motion.div>
        </div>

        {/* Stats Cards */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8"
        >
          {[
            { 
              title: 'Total Products', 
              value: pagination.total || 0, 
              icon: Package, 
              color: 'from-blue-500 to-cyan-600',
              bgColor: 'bg-blue-50',
              textColor: 'text-blue-700'
            },
            { 
              title: 'Total Value', 
              value: `₹${totalValue.toLocaleString()}`, 
              icon: DollarSign, 
              color: 'from-green-500 to-emerald-600',
              bgColor: 'bg-green-50',
              textColor: 'text-green-700'
            },
            { 
              title: 'Low Stock', 
              value: lowStockCount, 
              icon: AlertCircle, 
              color: 'from-amber-500 to-orange-600',
              bgColor: 'bg-amber-50',
              textColor: 'text-amber-700'
            },
            { 
              title: 'Out of Stock', 
              value: outOfStockCount, 
              icon: Archive, 
              color: 'from-red-500 to-rose-600',
              bgColor: 'bg-red-50',
              textColor: 'text-red-700'
            }
          ].map((stat, index) => (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1 + index * 0.05 }}
              className="card p-6 relative overflow-hidden group hover:shadow-lg transition-all"
            >
              <div className="flex items-center justify-between">
                <div className={`w-12 h-12 rounded-2xl ${stat.bgColor} flex items-center justify-center group-hover:scale-110 transition-transform`}>
                  <stat.icon className={`w-6 h-6 ${stat.textColor}`} />
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium text-slate-600 mb-1">{stat.title}</p>
                  <p className="text-2xl font-bold text-slate-900">{stat.value}</p>
                </div>
              </div>
              <div className={`absolute bottom-0 right-0 w-16 h-16 bg-gradient-to-br ${stat.color} opacity-10 rounded-full transform translate-x-6 translate-y-6`} />
            </motion.div>
          ))}
        </motion.div>

        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card p-6 mb-6"
        >
          <div className="flex flex-col lg:flex-row gap-4 mb-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search products by name, category, or ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-12"
              />
            </div>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="input min-w-48"
            >
              <option value="">All Categories</option>
              {categories.map(category => (
                <option key={category.value} value={category.value}>
                  {category.emoji} {category.label}
                </option>
              ))}
            </select>
            <div className="flex gap-2">
              <button
                onClick={() => setViewMode('grid')}
                className={`p-2 rounded-xl transition-all ${
                  viewMode === 'grid' 
                    ? 'bg-violet-100 text-violet-600' 
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <Package className="w-5 h-5" />
              </button>
              <button
                onClick={() => setViewMode('table')}
                className={`p-2 rounded-xl transition-all ${
                  viewMode === 'table' 
                    ? 'bg-violet-100 text-violet-600' 
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <Filter className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Category Quick Filters */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory('')}
              className={`px-3 py-1 rounded-lg text-sm font-medium transition-all ${
                selectedCategory === '' 
                  ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white' 
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              All
            </button>
            {categories.slice(0, 6).map(category => (
              <button
                key={category.value}
                onClick={() => setSelectedCategory(category.value)}
                className={`px-3 py-1 rounded-lg text-sm font-medium transition-all ${
                  selectedCategory === category.value 
                    ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white' 
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {category.emoji} {category.label}
              </button>
            ))}
          </div>
        </motion.div>

        {/* Products Display */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {[...Array(8)].map((_, index) => (
                <div key={index} className="card p-6">
                  <div className="skeleton h-40 mb-4 rounded-xl" />
                  <div className="skeleton h-6 mb-2" />
                  <div className="skeleton h-4 mb-4" />
                  <div className="skeleton h-10" />
                </div>
              ))}
            </div>
          ) : products.length === 0 ? (
            <div className="card p-12 text-center">
              <Package className="w-16 h-16 mx-auto mb-4 text-slate-400" />
              <h3 className="text-xl font-semibold text-slate-900 mb-2">No products found</h3>
              <p className="text-slate-600 mb-6">Try adjusting your search or filters</p>
              <Link to="/admin/products/new" className="btn btn-primary btn-lg">
                <Plus className="w-5 h-5 mr-2" />
                Add Your First Product
              </Link>
            </div>
          ) : viewMode === 'grid' ? (
            /* Grid View */
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              <AnimatePresence mode="popLayout">
                {products.map((product, index) => (
                  <motion.div
                    key={product._id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ delay: index * 0.05 }}
                    className="group"
                  >
                    <div className="card card-hover overflow-hidden">
                      <div className="relative">
                        <img
                          src={product.images?.[0]?.url || 'https://via.placeholder.com/300'}
                          alt={product.name}
                          className="w-full h-48 object-cover group-hover:scale-105 transition-transform duration-300"
                        />
                        <div className="absolute top-3 right-3 flex flex-col gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Link
                            to={`/admin/products/${product._id}/edit`}
                            className="w-8 h-8 bg-white/90 rounded-lg flex items-center justify-center hover:bg-white shadow-sm transition-all hover:scale-110"
                          >
                            <Edit className="w-4 h-4 text-slate-600" />
                          </Link>
                          <button
                            onClick={() => handleDeleteProduct(product)}
                            className="w-8 h-8 bg-white/90 rounded-lg flex items-center justify-center hover:bg-red-50 hover:text-red-600 shadow-sm transition-all hover:scale-110"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                        {product.stockQuantity === 0 && (
                          <div className="absolute top-3 left-3">
                            <span className="badge bg-red-500 text-white">Out of Stock</span>
                          </div>
                        )}
                        {product.stockQuantity > 0 && product.stockQuantity < 10 && (
                          <div className="absolute top-3 left-3">
                            <span className="badge bg-amber-500 text-white">Low Stock</span>
                          </div>
                        )}
                      </div>
                      
                      <div className="p-4">
                        <div className="mb-2">
                          <span className="text-xs font-medium text-violet-600 bg-violet-100 px-2 py-1 rounded-full">
                            {product.category}
                          </span>
                        </div>
                        <h3 className="font-semibold text-slate-900 mb-2 line-clamp-2 group-hover:text-violet-600 transition-colors">
                          {product.name}
                        </h3>
                        <p className="text-sm text-slate-600 mb-3">
                          ID: {product._id.slice(-8)}
                        </p>
                        
                        <div className="flex items-center justify-between mb-3">
                          <div className="text-2xl font-bold gradient-text">
                            ₹{product.price?.toLocaleString()}
                          </div>
                          <div className="text-right">
                            <div className="text-sm text-slate-600">Stock</div>
                            <div className={`font-semibold ${
                              product.stockQuantity === 0 
                                ? 'text-red-600' 
                                : product.stockQuantity < 10 
                                ? 'text-amber-600' 
                                : 'text-green-600'
                            }`}>
                              {product.stockQuantity}
                            </div>
                          </div>
                        </div>

                        <div className="flex gap-2">
                          <Link
                            to={`/products/${product._id}`}
                            className="flex-1 btn btn-outline btn-sm group/btn"
                          >
                            <Eye className="w-4 h-4 mr-1 group-hover/btn:animate-pulse" />
                            View
                          </Link>
                          <Link
                            to={`/admin/products/${product._id}/edit`}
                            className="flex-1 btn btn-primary btn-sm"
                          >
                            Edit
                          </Link>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          ) : (
            /* Table View */
            <div className="card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200">
                  <thead className="bg-slate-50">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Product
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Category
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Price
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Stock
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-slate-200">
                    <AnimatePresence mode="popLayout">
                      {products.map((product, index) => (
                        <motion.tr
                          key={product._id}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -20 }}
                          transition={{ delay: index * 0.05 }}
                          className="hover:bg-slate-50 transition-colors"
                        >
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center space-x-4">
                              <img
                                src={product.images?.[0] || 'https://via.placeholder.com/60'}
                                alt={product.name}
                                className="w-12 h-12 rounded-lg object-cover"
                              />
                              <div>
                                <div className="text-sm font-medium text-slate-900 line-clamp-1">
                                  {product.name}
                                </div>
                                <div className="text-sm text-slate-500">
                                  ID: {product._id.slice(-8)}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className="badge badge-primary capitalize">
                              {product.category}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-bold text-slate-900">
                              ₹{product.price?.toLocaleString()}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <span className={`font-semibold ${
                                product.stockQuantity === 0 
                                  ? 'text-red-600' 
                                  : product.stockQuantity < 10 
                                  ? 'text-amber-600' 
                                  : 'text-green-600'
                              }`}>
                                {product.stockQuantity}
                              </span>
                              {product.stockQuantity < 10 && product.stockQuantity > 0 && (
                                <AlertCircle className="w-4 h-4 ml-2 text-amber-500" />
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`badge ${
                              product.stockQuantity > 0 ? 'badge-success' : 'badge-danger'
                            }`}>
                              {product.stockQuantity > 0 ? 'In Stock' : 'Out of Stock'}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <div className="flex items-center space-x-2">
                              <Link
                                to={`/products/${product._id}`}
                                className="btn btn-ghost btn-sm group"
                              >
                                <Eye className="w-4 h-4 mr-1 group-hover:animate-pulse" />
                                View
                              </Link>
                              <Link
                                to={`/admin/products/${product._id}/edit`}
                                className="btn btn-outline btn-sm"
                              >
                                <Edit className="w-4 h-4 mr-1" />
                                Edit
                              </Link>
                              <button
                                onClick={() => handleDeleteProduct(product)}
                                className="btn btn-ghost btn-sm text-red-600 hover:bg-red-50"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </motion.tr>
                      ))}
                    </AnimatePresence>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Pagination */}
          {pagination.pages > 1 && (
            <div className="mt-8 flex items-center justify-between">
              <div className="text-sm text-slate-500">
                Showing {((currentPage - 1) * (viewMode === 'grid' ? 12 : 10)) + 1} to{' '}
                {Math.min(currentPage * (viewMode === 'grid' ? 12 : 10), pagination.total)}{' '}
                of {pagination.total} results
              </div>
              <div className="flex space-x-1">
                <button
                  onClick={() => setCurrentPage(currentPage - 1)}
                  disabled={currentPage === 1}
                  className="btn btn-outline btn-sm disabled:opacity-50"
                >
                  Previous
                </button>
                {[...Array(Math.min(5, pagination.pages))].map((_, i) => {
                  const page = i + 1
                  return (
                    <button
                      key={page}
                      onClick={() => setCurrentPage(page)}
                      className={`w-8 h-8 rounded-lg text-sm font-medium transition-all ${
                        currentPage === page
                          ? 'bg-violet-600 text-white'
                          : 'text-slate-600 hover:bg-slate-100'
                      }`}
                    >
                      {page}
                    </button>
                  )
                })}
                <button
                  onClick={() => setCurrentPage(currentPage + 1)}
                  disabled={currentPage === pagination.pages}
                  className="btn btn-outline btn-sm disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </motion.div>

        {/* Delete Confirmation Modal */}
        <AnimatePresence>
          {showDeleteModal && productToDelete && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
            >
              <motion.div
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.9, opacity: 0 }}
                className="bg-white rounded-2xl p-6 max-w-md w-full"
              >
                <div className="flex items-center mb-4">
                  <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mr-4">
                    <Trash2 className="w-6 h-6 text-red-600" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-slate-900">Delete Product</h3>
                    <p className="text-sm text-slate-600">This action cannot be undone</p>
                  </div>
                </div>
                
                <p className="text-slate-700 mb-6">
                  Are you sure you want to delete <strong>"{productToDelete.name}"</strong>? 
                  This will permanently remove the product and all associated data.
                </p>
                
                <div className="flex space-x-3">
                  <button
                    onClick={() => setShowDeleteModal(false)}
                    className="flex-1 btn btn-outline btn-md"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmDelete}
                    disabled={deleteProductMutation.isLoading}
                    className="flex-1 btn btn-danger btn-md disabled:opacity-50"
                  >
                    {deleteProductMutation.isLoading ? (
                      <>
                        <div className="loading-spinner mr-2" />
                        Deleting...
                      </>
                    ) : (
                      <>
                        <Trash2 className="w-4 h-4 mr-2" />
                        Delete
                      </>
                    )}
                  </button>
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}

export default AdminProducts
