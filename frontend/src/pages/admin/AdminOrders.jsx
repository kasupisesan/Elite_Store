import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { 
  Search, 
  Filter, 
  Eye, 
  Package, 
  Truck, 
  CheckCircle, 
  XCircle, 
  Clock, 
  AlertCircle,
  ChevronDown,
  Calendar,
  User,
  Mail,
  MapPin,
  CreditCard
} from 'lucide-react'
import { ordersAPI } from '../../utils/api'
import { Link } from 'react-router-dom'
import toast from 'react-hot-toast'

function AdminOrders() {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [showStatusModal, setShowStatusModal] = useState(false)
  const [selectedOrder, setSelectedOrder] = useState(null)
  const [newStatus, setNewStatus] = useState('')

  const queryClient = useQueryClient()

  const { data: ordersData, isLoading } = useQuery(
    ['adminOrders', currentPage, searchTerm, statusFilter],
    () => ordersAPI.getAllOrders({ 
      page: currentPage, 
      limit: 10, 
      search: searchTerm, 
      status: statusFilter 
    }),
    { keepPreviousData: true }
  )

  const updateStatusMutation = useMutation(
    ({ orderId, status }) => ordersAPI.updateOrderStatus(orderId, { status }),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('adminOrders')
        toast.success('Order status updated successfully')
        setShowStatusModal(false)
        setSelectedOrder(null)
        setNewStatus('')
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to update order status')
      }
    }
  )

  const handleStatusUpdate = (order) => {
    setSelectedOrder(order)
    setNewStatus(order.status)
    setShowStatusModal(true)
  }

  const confirmStatusUpdate = () => {
    if (selectedOrder && newStatus) {
      updateStatusMutation.mutate({ orderId: selectedOrder._id, status: newStatus })
    }
  }

  const getStatusIcon = (status) => {
    const icons = {
      pending: Clock,
      processing: Package,
      shipped: Truck,
      delivered: CheckCircle,
      cancelled: XCircle
    }
    return icons[status] || Clock
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

  const statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
  const orders = ordersData?.data?.data || []
  const pagination = ordersData?.data?.pagination || {}

  const statusCounts = {
    all: orders.length,
    pending: orders.filter(o => o.status === 'pending').length,
    processing: orders.filter(o => o.status === 'processing').length,
    shipped: orders.filter(o => o.status === 'shipped').length,
    delivered: orders.filter(o => o.status === 'delivered').length,
    cancelled: orders.filter(o => o.status === 'cancelled').length
  }

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <h1 className="text-3xl font-bold gradient-text mb-2">Order Management</h1>
            <p className="text-slate-600">Manage customer orders and track deliveries</p>
          </motion.div>
        </div>

        {/* Status Filter Tabs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-6"
        >
          <div className="flex flex-wrap gap-2">
            {[
              { key: '', label: 'All Orders', count: pagination.total || 0 },
              { key: 'pending', label: 'Pending', count: statusCounts.pending },
              { key: 'processing', label: 'Processing', count: statusCounts.processing },
              { key: 'shipped', label: 'Shipped', count: statusCounts.shipped },
              { key: 'delivered', label: 'Delivered', count: statusCounts.delivered },
              { key: 'cancelled', label: 'Cancelled', count: statusCounts.cancelled }
            ].map((status) => (
              <button
                key={status.key}
                onClick={() => {
                  setStatusFilter(status.key)
                  setCurrentPage(1)
                }}
                className={`px-4 py-2 rounded-xl text-sm font-medium transition-all ${
                  statusFilter === status.key
                    ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white shadow-lg'
                    : 'bg-white text-slate-600 hover:bg-slate-50 border border-slate-200'
                }`}
              >
                {status.label}
                {status.count > 0 && (
                  <span className={`ml-2 px-2 py-0.5 rounded-full text-xs ${
                    statusFilter === status.key
                      ? 'bg-white/20 text-white'
                      : 'bg-slate-100 text-slate-600'
                  }`}>
                    {status.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </motion.div>

        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card p-6 mb-6"
        >
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search by order ID, customer name, or email..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-12"
              />
            </div>
            <div className="flex gap-3">
              <button className="btn btn-outline btn-md">
                <Filter className="w-4 h-4 mr-2" />
                Advanced Filters
              </button>
              <button className="btn btn-primary btn-md">
                Export Orders
              </button>
            </div>
          </div>
        </motion.div>

        {/* Orders List */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="card overflow-hidden"
        >
          {isLoading ? (
            <div className="p-8 text-center">
              <div className="loading-spinner mx-auto mb-4" />
              <p className="text-slate-600">Loading orders...</p>
            </div>
          ) : orders.length === 0 ? (
            <div className="p-8 text-center">
              <Package className="w-16 h-16 mx-auto mb-4 text-slate-400" />
              <h3 className="text-lg font-semibold text-slate-900 mb-2">No orders found</h3>
              <p className="text-slate-600">Try adjusting your search or filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Order
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Customer
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Date
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Total
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
                    {orders.map((order, index) => {
                      const StatusIcon = getStatusIcon(order.status)
                      return (
                        <motion.tr
                          key={order._id}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -20 }}
                          transition={{ delay: index * 0.05 }}
                          className="hover:bg-slate-50 transition-colors"
                        >
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center space-x-3">
                              <div className="w-10 h-10 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-xl flex items-center justify-center">
                                <Package className="w-5 h-5 text-white" />
                              </div>
                              <div>
                                <div className="text-sm font-medium text-slate-900">
                                  #{order.orderNumber || order._id.slice(-8)}
                                </div>
                                <div className="text-sm text-slate-500">
                                  {order.orderItems?.length || 0} items
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center space-x-3">
                              <div className="w-8 h-8 bg-slate-200 rounded-full flex items-center justify-center">
                                <User className="w-4 h-4 text-slate-600" />
                              </div>
                              <div>
                                <div className="text-sm font-medium text-slate-900">
                                  {order.user?.name || 'Unknown'}
                                </div>
                                <div className="text-sm text-slate-500">
                                  {order.user?.email || 'No email'}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center text-sm text-slate-900">
                              <Calendar className="w-4 h-4 mr-2 text-slate-400" />
                              {new Date(order.createdAt).toLocaleDateString()}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-bold text-slate-900">
                              ₹{order.totalPrice?.toLocaleString()}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getStatusColor(order.status)}`}>
                              <StatusIcon className="w-4 h-4 mr-2" />
                              {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <div className="flex items-center space-x-2">
                              <Link
                                to={`/admin/orders/${order._id}`}
                                className="btn btn-outline btn-sm group"
                              >
                                <Eye className="w-4 h-4 mr-1 group-hover:animate-pulse" />
                                View
                              </Link>
                              <button
                                onClick={() => handleStatusUpdate(order)}
                                className="btn btn-primary btn-sm"
                              >
                                Update Status
                              </button>
                            </div>
                          </td>
                        </motion.tr>
                      )
                    })}
                  </AnimatePresence>
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {pagination.pages > 1 && (
            <div className="px-6 py-4 border-t border-slate-200 flex items-center justify-between">
              <div className="text-sm text-slate-500">
                Showing {((currentPage - 1) * 10) + 1} to{' '}
                {Math.min(currentPage * 10, pagination.total)}{' '}
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

        {/* Status Update Modal */}
        <AnimatePresence>
          {showStatusModal && selectedOrder && (
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
                <h3 className="text-lg font-bold text-slate-900 mb-4">Update Order Status</h3>
                
                <div className="mb-4">
                  <p className="text-sm text-slate-600 mb-2">
                    Order #{selectedOrder.orderNumber || selectedOrder._id.slice(-8)}
                  </p>
                  <p className="text-sm text-slate-600 mb-4">
                    Customer: {selectedOrder.user?.name}
                  </p>
                  
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    New Status
                  </label>
                  <select
                    value={newStatus}
                    onChange={(e) => setNewStatus(e.target.value)}
                    className="input"
                  >
                    {statuses.map(status => (
                      <option key={status} value={status}>
                        {status.charAt(0).toUpperCase() + status.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>
                
                <div className="flex space-x-3">
                  <button
                    onClick={() => setShowStatusModal(false)}
                    className="flex-1 btn btn-outline btn-md"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmStatusUpdate}
                    disabled={updateStatusMutation.isLoading}
                    className="flex-1 btn btn-primary btn-md disabled:opacity-50"
                  >
                    {updateStatusMutation.isLoading ? 'Updating...' : 'Update'}
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

export default AdminOrders
