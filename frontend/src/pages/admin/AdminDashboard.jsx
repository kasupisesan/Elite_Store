import { motion } from 'framer-motion'
import { useQuery } from 'react-query'
import { 
  Users, 
  Package, 
  ShoppingCart, 
  DollarSign, 
  TrendingUp, 
  TrendingDown, 
  Eye,
  ArrowRight,
  Calendar,
  Star,
  Activity,
  BarChart3,
  PieChart,
  ShoppingBag
} from 'lucide-react'
import { ordersAPI, productsAPI, usersAPI } from '../../utils/api'
import { Link } from 'react-router-dom'

function AdminDashboard() {
  const { data: orderStats } = useQuery(
    'orderStats',
    ordersAPI.getOrderStats,
    { select: (response) => response.data.data }
  )

  const { data: recentOrders } = useQuery(
    'recentOrders',
    () => ordersAPI.getAllOrders({ limit: 5, sortBy: '-createdAt' }),
    { select: (response) => response.data.data }
  )

  const { data: products } = useQuery(
    'adminProducts',
    () => productsAPI.getProducts({ limit: 5, sortBy: '-createdAt' }),
    { select: (response) => response.data }
  )

  const { data: usersPagination } = useQuery(
    'userCount',
    () => usersAPI.getAllUsers({ limit: 1 }),
    { select: (response) => response.data.pagination }
  )

  const totalUsers = usersPagination?.total || '0'

  const stats = [
    {
      title: 'Total Revenue',
      value: `₹${orderStats?.totalRevenue?.toLocaleString() || '0'}`,
      change: '+12.5%',
      changeType: 'increase',
      icon: DollarSign,
      color: 'from-emerald-500 to-green-600',
      bgColor: 'bg-emerald-50',
      textColor: 'text-emerald-700'
    },
    {
      title: 'Total Orders',
      value: orderStats?.totalOrders || '0',
      change: '+8.2%',
      changeType: 'increase',
      icon: ShoppingCart,
      color: 'from-blue-500 to-cyan-600',
      bgColor: 'bg-blue-50',
      textColor: 'text-blue-700'
    },
    {
      title: 'Total Products',
      value: products?.pagination?.total || '0',
      change: '+3.1%',
      changeType: 'increase',
      icon: Package,
      color: 'from-purple-500 to-violet-600',
      bgColor: 'bg-purple-50',
      textColor: 'text-purple-700'
    },
    {
      title: 'Total Users',
      value: totalUsers,
      change: '+5.4%',
      changeType: 'increase',
      icon: Users,
      color: 'from-orange-500 to-red-600',
      bgColor: 'bg-orange-50',
      textColor: 'text-orange-700'
    }
  ]

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

  const quickActions = [
    { name: 'Add Product', href: '/admin/products/new', icon: Package, color: 'from-violet-600 to-purple-600' },
    { name: 'View Orders', href: '/admin/orders', icon: ShoppingBag, color: 'from-blue-600 to-cyan-600' },
    { name: 'Manage Users', href: '/admin/users', icon: Users, color: 'from-green-600 to-emerald-600' },
    { name: 'Analytics', href: '/admin/analytics', icon: BarChart3, color: 'from-orange-600 to-red-600' }
  ]

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <h1 className="text-3xl font-bold gradient-text mb-2">Admin Dashboard</h1>
            <p className="text-slate-600">Welcome back! Here's what's happening with your store.</p>
          </motion.div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {stats.map((stat, index) => (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="card card-hover p-6 relative overflow-hidden group"
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`w-12 h-12 rounded-2xl ${stat.bgColor} flex items-center justify-center group-hover:scale-110 transition-transform`}>
                  <stat.icon className={`w-6 h-6 ${stat.textColor}`} />
                </div>
                <div className={`px-2 py-1 rounded-full text-xs font-medium flex items-center ${
                  stat.changeType === 'increase' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                }`}>
                  {stat.changeType === 'increase' ? (
                    <TrendingUp className="w-3 h-3 mr-1" />
                  ) : (
                    <TrendingDown className="w-3 h-3 mr-1" />
                  )}
                  {stat.change}
                </div>
              </div>
              
              <div>
                <h3 className="text-sm font-medium text-slate-600 mb-1">{stat.title}</h3>
                <p className="text-3xl font-bold text-slate-900">{stat.value}</p>
              </div>

              {/* Background Gradient */}
              <div className={`absolute top-0 right-0 w-20 h-20 bg-gradient-to-br ${stat.color} opacity-5 rounded-full transform translate-x-8 -translate-y-8`} />
            </motion.div>
          ))}
        </div>

        {/* Quick Actions */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="mb-8"
        >
          <h2 className="text-xl font-bold text-slate-900 mb-4">Quick Actions</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {quickActions.map((action, index) => (
              <Link
                key={action.name}
                to={action.href}
                className="group"
              >
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.4 + index * 0.1 }}
                  className="card p-4 text-center hover:shadow-lg transition-all group-hover:-translate-y-1"
                >
                  <div className={`w-12 h-12 mx-auto mb-3 bg-gradient-to-r ${action.color} rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform`}>
                    <action.icon className="w-6 h-6 text-white" />
                  </div>
                  <h3 className="font-medium text-slate-900 group-hover:text-violet-600 transition-colors">
                    {action.name}
                  </h3>
                </motion.div>
              </Link>
            ))}
          </div>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          
          {/* Recent Orders */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4 }}
            className="card p-6"
          >
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-slate-900 flex items-center">
                <ShoppingCart className="w-5 h-5 mr-2 text-violet-600" />
                Recent Orders
              </h2>
              <Link 
                to="/admin/orders"
                className="text-sm font-medium text-violet-600 hover:text-violet-700 flex items-center group"
              >
                View All
                <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
              </Link>
            </div>

            <div className="space-y-4">
              {recentOrders?.length > 0 ? (
                recentOrders.map((order, index) => (
                  <motion.div
                    key={order._id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 + index * 0.1 }}
                    className="flex items-center justify-between p-4 bg-slate-50 rounded-xl hover:bg-slate-100 transition-colors"
                  >
                    <div className="flex items-center space-x-4">
                      <div className="w-10 h-10 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-full flex items-center justify-center">
                        <ShoppingCart className="w-5 h-5 text-white" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-slate-900">
                          Order #{order.orderNumber || order._id.slice(-8)}
                        </h3>
                        <p className="text-sm text-slate-600">
                          {order.user?.name} • {new Date(order.createdAt).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-bold text-slate-900">₹{order.totalPrice?.toLocaleString()}</p>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(order.status)}`}>
                        {order.status}
                      </span>
                    </div>
                  </motion.div>
                ))
              ) : (
                <div className="text-center py-8">
                  <ShoppingCart className="w-12 h-12 mx-auto text-slate-400 mb-3" />
                  <p className="text-slate-600">No recent orders</p>
                </div>
              )}
            </div>
          </motion.div>

          {/* Recent Products */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.5 }}
            className="card p-6"
          >
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-slate-900 flex items-center">
                <Package className="w-5 h-5 mr-2 text-violet-600" />
                Recent Products
              </h2>
              <Link 
                to="/admin/products"
                className="text-sm font-medium text-violet-600 hover:text-violet-700 flex items-center group"
              >
                View All
                <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
              </Link>
            </div>

            <div className="space-y-4">
              {products?.data?.length > 0 ? (
                products.data.map((product, index) => (
                  <motion.div
                    key={product._id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 + index * 0.1 }}
                    className="flex items-center justify-between p-4 bg-slate-50 rounded-xl hover:bg-slate-100 transition-colors"
                  >
                    <div className="flex items-center space-x-4">
                      <img
                       src={product.images?.[0]?.url || 'https://via.placeholder.com/300'}
                       alt={product.name}
                        className="w-10 h-10 rounded-lg object-cover"
                      />
                      <div>
                        <h3 className="font-semibold text-slate-900 line-clamp-1">{product.name}</h3>
                        <p className="text-sm text-slate-600">
                          {product.category} • Stock: {product.stockQuantity}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="font-bold text-slate-900">₹{product.price?.toLocaleString()}</p>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        product.stockQuantity > 0 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                      }`}>
                        {product.stockQuantity > 0 ? 'In Stock' : 'Out of Stock'}
                      </span>
                    </div>
                  </motion.div>
                ))
              ) : (
                <div className="text-center py-8">
                  <Package className="w-12 h-12 mx-auto text-slate-400 mb-3" />
                  <p className="text-slate-600">No products found</p>
                </div>
              )}
            </div>
          </motion.div>
        </div>

        {/* Performance Chart Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="mt-8 card p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-slate-900 flex items-center">
              <Activity className="w-5 h-5 mr-2 text-violet-600" />
              Performance Overview
            </h2>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-violet-100 text-violet-700 rounded-lg text-sm font-medium">7D</button>
              <button className="px-3 py-1 text-slate-600 hover:bg-slate-100 rounded-lg text-sm font-medium">30D</button>
              <button className="px-3 py-1 text-slate-600 hover:bg-slate-100 rounded-lg text-sm font-medium">90D</button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center p-6 bg-gradient-to-br from-blue-50 to-cyan-50 rounded-2xl">
              <PieChart className="w-8 h-8 mx-auto mb-3 text-blue-600" />
              <h3 className="font-semibold text-slate-900 mb-1">Conversion Rate</h3>
              <p className="text-2xl font-bold text-blue-600">3.2%</p>
              <p className="text-sm text-slate-600">+0.3% from last week</p>
            </div>
            
            <div className="text-center p-6 bg-gradient-to-br from-green-50 to-emerald-50 rounded-2xl">
              <BarChart3 className="w-8 h-8 mx-auto mb-3 text-green-600" />
              <h3 className="font-semibold text-slate-900 mb-1">Avg Order Value</h3>
              <p className="text-2xl font-bold text-green-600">₹1,247</p>
              <p className="text-sm text-slate-600">+₹89 from last week</p>
            </div>
            
            <div className="text-center p-6 bg-gradient-to-br from-purple-50 to-violet-50 rounded-2xl">
              <Star className="w-8 h-8 mx-auto mb-3 text-purple-600" />
              <h3 className="font-semibold text-slate-900 mb-1">Customer Satisfaction</h3>
              <p className="text-2xl font-bold text-purple-600">4.8/5</p>
              <p className="text-sm text-slate-600">Based on 234 reviews</p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default AdminDashboard
