import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import {
  Package,
  Calendar,
  CreditCard,
  MapPin,
  Phone,
  User,
  Truck,
  CheckCircle,
  XCircle,
  Clock,
  AlertCircle,
  ArrowLeft,
  Download,
  MessageCircle,
  Star,
  Copy,
  Check
} from 'lucide-react'
import { ordersAPI } from '../utils/api'
import toast from 'react-hot-toast'

function OrderDetail() {
  const { id } = useParams()
  const queryClient = useQueryClient()
  const [copied, setCopied] = useState(false)

  const { data: order, isLoading, error } = useQuery(
    ['order', id],
    () => ordersAPI.getOrder(id),
    { select: (response) => response.data.data }
  )

  const cancelOrderMutation = useMutation(
    () => ordersAPI.cancelOrder(id),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['order', id])
        queryClient.invalidateQueries(['userOrders'])
        toast.success('Order cancelled successfully')
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to cancel order')
      }
    }
  )

  const handleCancelOrder = () => {
    if (window.confirm('Are you sure you want to cancel this order?')) {
      cancelOrderMutation.mutate()
    }
  }

  const copyOrderId = () => {
    navigator.clipboard.writeText(order._id)
    setCopied(true)
    toast.success('Order ID copied!')
    setTimeout(() => setCopied(false), 2000)
  }

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
    return <IconComponent className="w-5 h-5" />
  }

  const orderSteps = [
    { key: 'pending', label: 'Order Placed', icon: CheckCircle },
    { key: 'processing', label: 'Processing', icon: Package },
    { key: 'shipped', label: 'Shipped', icon: Truck },
    { key: 'delivered', label: 'Delivered', icon: CheckCircle }
  ]

  const getCurrentStepIndex = (status) => {
    if (status === 'cancelled') return -1
    return orderSteps.findIndex(step => step.key === status)
  }

  if (isLoading) {
    return (
      <div className="min-h-screen py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="animate-pulse space-y-6">
            <div className="skeleton h-12 w-3/4" />
            <div className="skeleton h-32" />
            <div className="skeleton h-48" />
            <div className="skeleton h-40" />
          </div>
        </div>
      </div>
    )
  }

  if (error || !order) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-24 h-24 mx-auto mb-6 bg-red-100 rounded-full flex items-center justify-center">
            <XCircle className="w-12 h-12 text-red-600" />
          </div>
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Order not found</h2>
          <p className="text-slate-600 mb-6">The order you're looking for doesn't exist or you don't have permission to view it.</p>
          <Link to="/orders" className="btn btn-primary btn-md">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Orders
          </Link>
        </div>
      </div>
    )
  }

  const currentStepIndex = getCurrentStepIndex(order.status)

  // Unified items array (backend uses orderItems)
  const itemsArr = order.orderItems ?? order.items ?? [];


  // Calculate amounts safely
  const subtotal = (typeof order.itemsPrice === 'number' && !isNaN(order.itemsPrice)) 
    ? order.itemsPrice 
    : itemsArr.reduce((acc, item) => acc + (Number(item.price) || 0) * (Number(item.quantity) || 0), 0);
  const shippingCost = order.shippingPrice ?? 0;
  const total = order.totalPrice ?? (subtotal + shippingCost);

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <Link 
            to="/orders"
            className="inline-flex items-center text-slate-600 hover:text-violet-600 mb-4 group"
          >
            <ArrowLeft className="w-4 h-4 mr-2 group-hover:-translate-x-1 transition-transform" />
            Back to Orders
          </Link>
          
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold gradient-text mb-2">
                Order Details
              </h1>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <span className="text-slate-600">Order ID:</span>
                  <code className="px-2 py-1 bg-slate-100 rounded font-mono text-sm">
                    #{order._id?.slice(-8).toUpperCase()}
                  </code>
                  <button
                    onClick={copyOrderId}
                    className="p-1 text-slate-400 hover:text-violet-600 transition-colors"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
                <div className="flex items-center text-slate-500">
                  <Calendar className="w-4 h-4 mr-1" />
                  Placed on {new Date(order.createdAt).toLocaleDateString('en-IN', {
                    day: 'numeric',
                    month: 'long',
                    year: 'numeric'
                  })}
                </div>
              </div>
            </div>
            
            <div className={`px-4 py-2 rounded-2xl border text-lg font-semibold flex items-center space-x-2 ${getStatusColor(order.status)}`}>
              {getStatusIcon(order.status)}
              <span className="capitalize">{order.status}</span>
            </div>
          </div>
        </div>

        {/* Order Progress */}
        {order.status !== 'cancelled' && (
          <div className="card p-6 mb-8">
            <h3 className="text-lg font-semibold text-slate-900 mb-6">Order Progress</h3>
            <div className="relative">
              <div className="flex items-center justify-between">
                {orderSteps.map((step, index) => (
                  <div key={step.key} className="flex flex-col items-center relative">
                    <div className={`w-12 h-12 rounded-full flex items-center justify-center transition-all ${
                      index <= currentStepIndex
                        ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white'
                        : 'bg-slate-200 text-slate-500'
                    }`}>
                      <step.icon className="w-6 h-6" />
                    </div>
                    <span className={`mt-2 text-sm font-medium ${
                      index <= currentStepIndex ? 'text-violet-600' : 'text-slate-500'
                    }`}>
                      {step.label}
                    </span>
                    {index < orderSteps.length - 1 && (
                      <div className={`absolute top-6 left-12 w-full h-0.5 transition-all ${
                        index < currentStepIndex ? 'bg-violet-600' : 'bg-slate-200'
                      }`} style={{ width: 'calc(100vw / 4 - 3rem)' }} />
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Order Items */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold text-slate-900 mb-6 flex items-center">
                <Package className="w-5 h-5 mr-2 text-violet-600" />
                Items ({itemsArr.length})
              </h3>
              
              <div className="space-y-4">
                {itemsArr.map((item, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-center gap-4 p-4 bg-slate-50 rounded-xl"
                  >
                    <img
                      src={
                        item.product?.images?.[0]?.url || 
                        item.product?.images?.[0] 
                      }
                      alt={item.product?.name || 'Product'}
                      className="w-12 h-12 object-cover rounded-lg"
                      onError={(e) => {
                        e.target.src = 'https://images.unsplash.com/photo-1560472355-536de3962603?w=200';
                      }}
                      loading="lazy"
                    />

                    <div className="flex-1">
                      <h4 className="font-semibold text-slate-900 mb-1">
                        {item.product?.name}
                      </h4>
                      {item.product?.brand && (
                        <p className="text-sm text-slate-600 mb-2">{item.product.brand}</p>
                      )}
                      <div className="flex items-center justify-between">
                        <span className="text-slate-600">
                          ₹{item.price?.toLocaleString()} × {item.quantity}
                        </span>
                        <span className="text-lg font-bold gradient-text">
                          ₹{(item.price * item.quantity).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    
                    {order.status === 'delivered' && (
                      <button className="btn btn-outline btn-sm group">
                        <Star className="w-4 h-4 mr-1 group-hover:fill-current group-hover:text-yellow-500" />
                        Review
                      </button>
                    )}
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Shipping Address */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold text-slate-900 mb-6 flex items-center">
                <MapPin className="w-5 h-5 mr-2 text-violet-600" />
                Shipping Address
              </h3>
              
              <div className="bg-slate-50 rounded-xl p-4 space-y-2">
                <div className="flex items-center text-slate-900 font-medium">
                  <User className="w-4 h-4 mr-2" />
                  {order.shippingAddress?.fullName}
                </div>
                <div className="flex items-start text-slate-600">
                  <MapPin className="w-4 h-4 mr-2 mt-0.5 flex-shrink-0" />
                  <div>
                    <p>{order.shippingAddress?.address}</p>
                    <p>{order.shippingAddress?.city}, {order.shippingAddress?.postalCode}</p>
                    <p>{order.shippingAddress?.country}</p>
                  </div>
                </div>
                <div className="flex items-center text-slate-600">
                  <Phone className="w-4 h-4 mr-2" />
                  {order.shippingAddress?.phone}
                </div>
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            
            {/* Order Summary */}
            <div className="card p-6 bg-gradient-to-br from-white to-slate-50">
              <h3 className="text-lg font-semibold text-slate-900 mb-6">Order Summary</h3>
              
              <div className="space-y-4">
                <div className="flex justify-between text-slate-600">
                  <span>Subtotal ({order.orderItems?.length || order.items?.length || 0} items)</span>
                  <span>₹{subtotal.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-slate-600">
                  <span>Shipping</span>
                  <span>{shippingCost === 0 ? 'FREE' : `₹${shippingCost.toLocaleString()}`}</span>
                </div>
              </div>
              <div className="border-t border-slate-200 pt-4">
                <div className="flex justify-between items-center">
                  <span className="text-lg font-semibold text-slate-900">Total</span>
                  <span className="text-2xl font-bold gradient-text">
                    ₹{total.toLocaleString()}
                  </span>
                  </div>
                </div>
              </div>

            {/* Payment Information */}
            <div className="card p-6">
              <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center">
                <CreditCard className="w-5 h-5 mr-2 text-violet-600" />
                Payment Info
              </h3>
              
              <div className="space-y-3">
                <div>
                  <span className="text-slate-600">Payment Method:</span>
                  <p className="font-medium text-slate-900 capitalize">
                    {order.paymentMethod?.replace('_', ' ')}
                  </p>
                </div>
                <div>
                  <span className="text-slate-600">Payment Status:</span>
                  <div className={`inline-flex items-center mt-1 px-2 py-1 rounded-lg text-sm font-medium ${
                    order.isPaid 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-amber-100 text-amber-800'
                  }`}>
                    {order.isPaid ? 'Paid' : 'Payment Pending'}
                  </div>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="space-y-3">
              {order.status === 'delivered' && (
                <button className="w-full btn btn-primary btn-md group">
                  <Download className="w-4 h-4 mr-2 group-hover:animate-bounce" />
                  Download Invoice
                </button>
              )}
              
              {(order.status === 'pending' || order.status === 'processing') && (
                <button
                  onClick={handleCancelOrder}
                  disabled={cancelOrderMutation.isLoading}
                  className="w-full btn btn-danger btn-md disabled:opacity-50"
                >
                  {cancelOrderMutation.isLoading ? (
                    <>
                      <div className="loading-spinner mr-2" />
                      Cancelling...
                    </>
                  ) : (
                    <>
                      <XCircle className="w-4 h-4 mr-2" />
                      Cancel Order
                    </>
                  )}
                </button>
              )}
              
              <button className="w-full btn btn-outline btn-md group">
                <MessageCircle className="w-4 h-4 mr-2 group-hover:animate-pulse" />
                Contact Support
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


export default OrderDetail
