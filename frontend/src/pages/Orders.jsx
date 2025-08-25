import { useState } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from 'react-query'
import {
  Package,
  Eye,
  Calendar,
  CreditCard,
  Truck,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  Search,
  Filter,
  ArrowRight,
  Download
} from 'lucide-react'
import { ordersAPI } from '../utils/api'

function Orders() {
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState('all')
  const limit = 10

  const { data, isLoading, error } = useQuery(
    ['userOrders', { page, limit, status: statusFilter !== 'all' ? statusFilter : undefined }],
    () => ordersAPI.getUserOrders({
      page,
      limit,
      ...(statusFilter !== 'all' && { status: statusFilter })
    }),
    {
      select: (response) => response.data,
      keepPreviousData: true
    }
  )

  const getStatusColor = (status) => {
    const colors = {
      pending: 'bg-amber-100 text-amber-800 border-amber-200',
      processing: 'bg-blue-100 text-blue-800 border-blue-200',
      shipped: 'bg-purple-100 text-purple-800 border-purple-200',
      delivered: 'bg-green-100 text-green-800 border-green-200',
      cancelled: 'bg-red-100 text-red-800 border-red-200'
    }
    return colors[status] || 'bg-slate-100 text-slate-800 border-slate-200'
  }

  const getStatusIcon = (status) => {
    const icons = {
      pending: Clock,
      processing: Package,
      shipped: Truck,
      delivered: CheckCircle,
      cancelled: XCircle
    }
    const IconComponent = icons[status] || AlertCircle
    return <IconComponent className="w-4 h-4" />
  }

  const statusOptions = [
    { value: 'all', label: 'All Orders', count: data?.pagination?.total || 0 },
    { value: 'pending', label: 'Pending', count: 0 },
    { value: 'processing', label: 'Processing', count: 0 },
    { value: 'shipped', label: 'Shipped', count: 0 },
    { value: 'delivered', label: 'Delivered', count: 0 },
    { value: 'cancelled', label: 'Cancelled', count: 0 }
  ]

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-24 h-24 mx-auto mb-6 bg-red-100 rounded-full flex items-center justify-center">
            <XCircle className="w-12 h-12 text-red-600" />
          </div>
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Something went wrong</h2>
          <p className="text-slate-600 mb-6">We couldn't load your orders. Please try again later.</p>
          <button
            onClick={() => window.location.reload()}
            className="btn btn-primary btn-md"
          >
            Try Again
          </button>
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="min-h-screen py-8">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="animate-pulse">
            <div className="skeleton h-8 w-48 mb-8" />
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="skeleton h-24 rounded-xl" />
              ))}
            </div>
            <div className="space-y-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="skeleton h-32 rounded-xl" />
              ))}
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (!data?.data || data.data.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="w-32 h-32 mx-auto mb-8 bg-gradient-to-br from-violet-100 to-indigo-100 rounded-full flex items-center justify-center"
          >
            <Package className="w-16 h-16 text-violet-600" />
          </motion.div>
          <h2 className="text-3xl font-bold text-slate-900 mb-4">No orders yet</h2>
          <p className="text-xl text-slate-600 mb-8">Start shopping to see your orders here</p>
          <Link to="/products" className="btn btn-primary btn-lg group">
            <Package className="w-5 h-5 mr-2 group-hover:animate-bounce" />
            Start Shopping
            <ArrowRight className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform" />
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold gradient-text mb-2">My Orders</h1>
          <p className="text-slate-600">Track and manage your orders</p>
        </div>

        {/* Status Filter Tabs */}
        <div className="mb-8">
          <div className="flex flex-wrap gap-2">
            {statusOptions.map((option) => (
              <button
                key={option.value}
                onClick={() => {
                  setStatusFilter(option.value)
                  setPage(1)
                }}
                className={`px-4 py-2 rounded-xl text-sm font-medium transition-all ${statusFilter === option.value
                    ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white shadow-lg'
                    : 'bg-white text-slate-600 hover:bg-slate-50 border border-slate-200'
                  }`}
              >
                {option.label}
                {option.count > 0 && (
                  <span className={`ml-2 px-2 py-0.5 rounded-full text-xs ${statusFilter === option.value
                      ? 'bg-white/20 text-white'
                      : 'bg-slate-100 text-slate-600'
                    }`}>
                    {option.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Orders List */}
        <div className="space-y-6">
          <AnimatePresence mode="popLayout">
            {data.data.map((order, index) => {
              const itemsArr = order.orderItems ?? order.items ?? [];
              const subtotal = (typeof order.itemsPrice === 'number' && !isNaN(order.itemsPrice)) ? order.itemsPrice : itemsArr.reduce((acc, item) => acc + (Number(item.price) || 0) * (Number(item.quantity) || 0), 0);
              const shippingCost = order.shippingPrice ?? 0;
              const total = (typeof order.totalPrice === 'number' && !isNaN(order.totalPrice)) ? order.totalPrice : subtotal + shippingCost;
              return (
              <motion.div
                key={order._id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ delay: index * 0.05 }}
                className="card card-hover overflow-hidden"
              >
                <div className="p-6">

                  {/* Order Header */}
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6">
                    <div className="flex items-center space-x-4">
                      <div className="w-12 h-12 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-xl flex items-center justify-center">
                        <Package className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold text-slate-900">
                          Order #{order._id?.slice(-8).toUpperCase()}
                        </h3>
                        <div className="flex items-center text-sm text-slate-500 mt-1">
                          <Calendar className="w-4 h-4 mr-1" />
                          Placed on {new Date(order.createdAt).toLocaleDateString('en-IN', {
                            day: 'numeric',
                            month: 'long',
                            year: 'numeric'
                          })}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center space-x-4">
                      <div className={`px-3 py-1.5 rounded-xl border text-sm font-medium flex items-center space-x-2 ${getStatusColor(order.status)}`}>
                        {getStatusIcon(order.status)}
                        <span className="capitalize">{order.status}</span>
                      </div>
                      <Link
                        to={`/orders/${order._id}`}
                        className="btn btn-outline btn-sm group"
                      >
                        <Eye className="w-4 h-4 mr-2 group-hover:animate-pulse" />
                        View Details
                      </Link>
                    </div>
                  </div>

                  {/* Order Info Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">

                    {/* Items */}
                    <div className="bg-slate-50 rounded-xl p-4">
                      <div className="flex items-center text-slate-600 mb-2">
                        <Package className="w-4 h-4 mr-2" />
                        <span className="text-sm font-medium">Items</span>
                      </div>
                      <div className="text-2xl font-bold text-slate-900">
                        {itemsArr.length} {itemsArr.length === 1 ? 'item' : 'items'}
                      </div>
                    </div>

                    {/* Total Amount */}
                    <div className="bg-slate-50 rounded-xl p-4">
                      <div className="flex items-center text-slate-600 mb-2">
                        <CreditCard className="w-4 h-4 mr-2" />
                        <span className="text-sm font-medium">Total Amount</span>
                      </div>
                      <div className="text-2xl font-bold gradient-text">
                        ₹{total.toLocaleString()}
                      </div>
                    </div>

                    {/* Delivery Address */}
                    <div className="bg-slate-50 rounded-xl p-4">
                      <div className="flex items-center text-slate-600 mb-2">
                        <Truck className="w-4 h-4 mr-2" />
                        <span className="text-sm font-medium">Delivery Address</span>
                      </div>
                      <div className="text-sm text-slate-900 font-medium">
                        {order.shippingAddress?.city}, {order.shippingAddress?.postalCode}
                      </div>
                    </div>
                  </div>

                  {/* Order Items Preview */}
                  {itemsArr.length > 0 && (
                    <div className="border-t border-slate-200 pt-6">
                      <h4 className="text-sm font-medium text-slate-900 mb-4">Items in this order</h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                        {itemsArr.slice(0, 4).map((item, itemIndex) => (
                          <div key={itemIndex} className="flex items-center space-x-3 p-3 bg-white rounded-xl border border-slate-100">
                            <img
                              src={
                                item.product?.images?.[0]?.url ||
                                item.product?.images?.[0] ||
                                item.image?.url ||
                                item.image
                              }
                              alt={item.product?.name || 'Product'}
                              className="w-16 h-16 object-cover rounded-lg"
                              onError={(e) => {
                                e.target.src = 'https://images.unsplash.com/photo-1560472355-536de3962603?w=300';
                              }}
                              loading="lazy"
                            />

                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium text-slate-900 truncate">
                                {item.product?.name}
                              </p>
                              <p className="text-xs text-slate-500">
                                Qty: {item.quantity}
                              </p>
                            </div>
                          </div>
                        ))}
                        {itemsArr.length > 4 && (
                          <div className="flex items-center justify-center p-3 bg-slate-50 rounded-xl border border-slate-100">
                            <span className="text-sm text-slate-600 font-medium">
                              +{itemsArr.length - 4} more
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex flex-col sm:flex-row gap-3 mt-6 pt-6 border-t border-slate-200">
                    <Link
                      to={`/orders/${order._id}`}
                      className="btn btn-primary btn-md flex-1 group"
                    >
                      <Eye className="w-4 h-4 mr-2 group-hover:animate-pulse" />
                      View Order Details
                    </Link>

                    {order.status === 'delivered' && (
                      <button className="btn btn-outline btn-md group">
                        <Download className="w-4 h-4 mr-2 group-hover:animate-bounce" />
                        Download Invoice
                      </button>
                    )}

                    {(order.status === 'pending' || order.status === 'processing') && (
                      <button className="btn btn-ghost btn-md text-red-600 hover:bg-red-50">
                        Cancel Order
                      </button>
                    )}
                  </div>
                </div>
              </motion.div>
              );
              })}
          </AnimatePresence>
        </div>

        {/* Pagination */}
        {data?.pagination?.pages > 1 && (
          <div className="flex items-center justify-center mt-12 space-x-2">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page === 1}
              className="btn btn-outline btn-md disabled:opacity-50"
            >
              Previous
            </button>
            {[...Array(data.pagination.pages)].map((_, index) => (
              <button
                key={index + 1}
                onClick={() => setPage(index + 1)}
                className={`w-10 h-10 rounded-xl font-medium transition-all ${page === index + 1
                    ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white'
                    : 'bg-white text-slate-600 hover:bg-slate-100 border border-slate-200'
                  }`}
              >
                {index + 1}
              </button>
            ))}
            <button
              onClick={() => setPage(page + 1)}
              disabled={page === data.pagination.pages}
              className="btn btn-outline btn-md disabled:opacity-50"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export default Orders
