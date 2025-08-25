import { useState } from 'react'
import { useQuery } from 'react-query'
import { ordersAPI } from '../utils/api'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  User, 
  Mail, 
  Phone, 
  MapPin, 
  Lock, 
  Save,
  Edit,
  Camera,
  Shield,
  Bell,
  Heart,
  Package,
  CreditCard,
  Eye,
  EyeOff,
  Check,
  AlertCircle,
  Settings,
  Trash2
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import toast from 'react-hot-toast'

function Profile() {
  const { user, updateProfile, changePassword } = useAuth()
  const [activeTab, setActiveTab] = useState('profile')
  const [isLoading, setIsLoading] = useState(false)
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  const [profileData, setProfileData] = useState({
    name: user?.name || '',
    email: user?.email || '',
    phone: user?.phone || '',
    address: {
      street: user?.address?.street || '',
      city: user?.address?.city || '',
      state: user?.address?.state || '',
      zipCode: user?.address?.zipCode || '',
      country: user?.address?.country || 'India'
    }
  })

  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  })

  const [preferences, setPreferences] = useState({
    emailNotifications: true,
    smsNotifications: false,
    orderUpdates: true,
    promotions: true,
    newsletter: false
  })

  const handleProfileChange = (e) => {
    const { name, value } = e.target
    if (name.startsWith('address.')) {
      const field = name.split('.')[1]
      setProfileData(prev => ({
        ...prev,
        address: { ...prev.address, [field]: value }
      }))
    } else {
      setProfileData(prev => ({ ...prev, [name]: value }))
    }
  }

  const handlePasswordChange = (e) => {
    const { name, value } = e.target
    setPasswordData(prev => ({ ...prev, [name]: value }))
  }

  const handlePreferenceChange = (key) => {
    setPreferences(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const handleProfileSubmit = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    const result = await updateProfile(profileData)
    if (result.success) {
      toast.success('Profile updated successfully')
    } else {
      toast.error(result.message)
    }
    setIsLoading(false)
  }

  const handlePasswordSubmit = async (e) => {
    e.preventDefault()
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      toast.error('New passwords do not match')
      return
    }
    if (passwordData.newPassword.length < 6) {
      toast.error('New password must be at least 6 characters')
      return
    }
    setIsLoading(true)
    const result = await changePassword({
      currentPassword: passwordData.currentPassword,
      newPassword: passwordData.newPassword
    })
    if (result.success) {
      setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' })
      toast.success('Password changed successfully')
    } else {
      toast.error(result.message)
    }
    setIsLoading(false)
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User, description: 'Personal information' },
    { id: 'security', label: 'Security', icon: Lock, description: 'Password & security' },
    { id: 'preferences', label: 'Preferences', icon: Settings, description: 'Notifications & settings' },
    { id: 'orders', label: 'Order History', icon: Package, description: 'Past purchases' }
  ]

    // Dynamic stats
  const { data: ordersPagination } = useQuery(
    'myOrdersCount',
    () => ordersAPI.getUserOrders({ limit: 1 }),
    { select: (res) => res.data.pagination }
  )

  const totalOrders = ordersPagination?.total || 0
  const wishlistCount = user?.wishlist?.length || 0
  const addressesCount = user?.addresses?.length || 0
  const memberSince = user?.createdAt ? new Date(user.createdAt).getFullYear() : ''

  const quickStats = [
    { label: 'Total Orders', value: totalOrders, icon: Package, color: 'from-blue-500 to-cyan-500' },
    { label: 'Wishlist Items', value: wishlistCount, icon: Heart, color: 'from-pink-500 to-rose-500' },
    { label: 'Saved Addresses', value: addressesCount, icon: MapPin, color: 'from-green-500 to-emerald-500' },
    { label: 'Member Since', value: memberSince, icon: Shield, color: 'from-purple-500 to-violet-500' }
  ]

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold gradient-text mb-2">My Profile</h1>
          <p className="text-slate-600">Manage your account settings and preferences</p>
        </div>

        {/* Profile Header Card */}
        <div className="card p-6 mb-8 bg-gradient-to-r from-violet-600 to-indigo-600 text-white">
          <div className="flex items-center space-x-6">
            <div className="relative">
              <div className="w-24 h-24 bg-white/20 rounded-full flex items-center justify-center text-2xl font-bold">
                {user?.name?.charAt(0).toUpperCase()}
              </div>
              <button className="absolute -bottom-1 -right-1 w-8 h-8 bg-white text-violet-600 rounded-full flex items-center justify-center hover:bg-slate-100 transition-colors">
                <Camera className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold mb-1">{user?.name}</h2>
              <p className="text-white/80 mb-3">{user?.email}</p>
              <div className="flex items-center space-x-4 text-sm">
                <div className="flex items-center">
                  <Shield className="w-4 h-4 mr-1" />
                  <span>Verified Account</span>
                </div>
                <div className="flex items-center">
                  <Package className="w-4 h-4 mr-1" />
                  <span>Premium Member</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {quickStats.map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="card p-4 text-center"
            >
              <div className={`w-12 h-12 mx-auto mb-3 bg-gradient-to-r ${stat.color} rounded-xl flex items-center justify-center`}>
                <stat.icon className="w-6 h-6 text-white" />
              </div>
              <div className="text-2xl font-bold text-slate-900 mb-1">{stat.value}</div>
              <div className="text-sm text-slate-600">{stat.label}</div>
            </motion.div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          
          {/* Sidebar Navigation */}
          <div className="space-y-2">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full text-left p-4 rounded-xl transition-all group ${
                  activeTab === tab.id
                    ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white shadow-lg'
                    : 'bg-white text-slate-600 hover:bg-slate-50 border border-slate-200'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <tab.icon className={`w-5 h-5 ${
                    activeTab === tab.id ? 'text-white' : 'text-slate-500'
                  }`} />
                  <div>
                    <div className={`font-medium ${
                      activeTab === tab.id ? 'text-white' : 'text-slate-900'
                    }`}>
                      {tab.label}
                    </div>
                    <div className={`text-xs ${
                      activeTab === tab.id ? 'text-white/80' : 'text-slate-500'
                    }`}>
                      {tab.description}
                    </div>
                  </div>
                </div>
              </button>
            ))}
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            <AnimatePresence mode="wait">
              
              {/* Profile Tab */}
              {activeTab === 'profile' && (
                <motion.div
                  key="profile"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="space-y-6"
                >
                  <div className="card p-6">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-xl font-bold text-slate-900">Personal Information</h3>
                      <Edit className="w-5 h-5 text-slate-400" />
                    </div>

                    <form onSubmit={handleProfileSubmit} className="space-y-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <label className="block text-sm font-medium text-slate-700 mb-2">
                            <User className="w-4 h-4 inline mr-1" />
                            Full Name
                          </label>
                          <input
                            type="text"
                            name="name"
                            value={profileData.name}
                            onChange={handleProfileChange}
                            className="input"
                            required
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-slate-700 mb-2">
                            <Mail className="w-4 h-4 inline mr-1" />
                            Email Address
                          </label>
                          <input
                            type="email"
                            name="email"
                            value={profileData.email}
                            onChange={handleProfileChange}
                            className="input"
                            required
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-slate-700 mb-2">
                            <Phone className="w-4 h-4 inline mr-1" />
                            Phone Number
                          </label>
                          <input
                            type="tel"
                            name="phone"
                            value={profileData.phone}
                            onChange={handleProfileChange}
                            className="input"
                            placeholder="+91 98765 43210"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-slate-700 mb-2">Country</label>
                          <select
                            name="address.country"
                            value={profileData.address.country}
                            onChange={handleProfileChange}
                            className="input"
                          >
                            <option value="India">India</option>
                            <option value="USA">USA</option>
                            <option value="UK">UK</option>
                            <option value="Canada">Canada</option>
                          </select>
                        </div>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          <MapPin className="w-4 h-4 inline mr-1" />
                          Street Address
                        </label>
                        <textarea
                          name="address.street"
                          value={profileData.address.street}
                          onChange={handleProfileChange}
                          className="input min-h-[80px]"
                          placeholder="Enter your complete street address"
                        />
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div>
                          <label className="block text-sm font-medium text-slate-700 mb-2">City</label>
                          <input
                            type="text"
                            name="address.city"
                            value={profileData.address.city}
                            onChange={handleProfileChange}
                            className="input"
                            placeholder="City"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-slate-700 mb-2">State</label>
                          <input
                            type="text"
                            name="address.state"
                            value={profileData.address.state}
                            onChange={handleProfileChange}
                            className="input"
                            placeholder="State"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-slate-700 mb-2">Zip Code</label>
                          <input
                            type="text"
                            name="address.zipCode"
                            value={profileData.address.zipCode}
                            onChange={handleProfileChange}
                            className="input"
                            placeholder="Zip Code"
                          />
                        </div>
                      </div>

                      <div className="flex justify-end">
                        <motion.button
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          type="submit"
                          disabled={isLoading}
                          className="btn btn-primary btn-lg disabled:opacity-50"
                        >
                          {isLoading ? (
                            <>
                              <div className="loading-spinner mr-2" />
                              Saving...
                            </>
                          ) : (
                            <>
                              <Save className="w-4 h-4 mr-2" />
                              Save Changes
                            </>
                          )}
                        </motion.button>
                      </div>
                    </form>
                  </div>
                </motion.div>
              )}

              {/* Security Tab */}
              {activeTab === 'security' && (
                <motion.div
                  key="security"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="space-y-6"
                >
                  <div className="card p-6">
                    <h3 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
                      <Lock className="w-5 h-5 mr-2 text-violet-600" />
                      Change Password
                    </h3>

                    <form onSubmit={handlePasswordSubmit} className="space-y-6">
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          Current Password
                        </label>
                        <div className="relative">
                          <input
                            type={showCurrentPassword ? 'text' : 'password'}
                            name="currentPassword"
                            value={passwordData.currentPassword}
                            onChange={handlePasswordChange}
                            className="input pr-12"
                            required
                          />
                          <button
                            type="button"
                            onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-600"
                          >
                            {showCurrentPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                          </button>
                        </div>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          New Password
                        </label>
                        <div className="relative">
                          <input
                            type={showNewPassword ? 'text' : 'password'}
                            name="newPassword"
                            value={passwordData.newPassword}
                            onChange={handlePasswordChange}
                            className="input pr-12"
                            required
                            minLength={6}
                          />
                          <button
                            type="button"
                            onClick={() => setShowNewPassword(!showNewPassword)}
                            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-600"
                          >
                            {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                          </button>
                        </div>
                        <p className="text-xs text-slate-500 mt-1">Password must be at least 6 characters long</p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          Confirm New Password
                        </label>
                        <div className="relative">
                          <input
                            type={showConfirmPassword ? 'text' : 'password'}
                            name="confirmPassword"
                            value={passwordData.confirmPassword}
                            onChange={handlePasswordChange}
                            className="input pr-12"
                            required
                          />
                          <button
                            type="button"
                            onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-600"
                          >
                            {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                          </button>
                        </div>
                      </div>

                      <div className="flex justify-end">
                        <motion.button
                          whileHover={{ scale: 1.02 }}
                          whileTap={{ scale: 0.98 }}
                          type="submit"
                          disabled={isLoading}
                          className="btn btn-primary btn-lg disabled:opacity-50"
                        >
                          {isLoading ? (
                            <>
                              <div className="loading-spinner mr-2" />
                              Updating...
                            </>
                          ) : (
                            <>
                              <Lock className="w-4 h-4 mr-2" />
                              Update Password
                            </>
                          )}
                        </motion.button>
                      </div>
                    </form>
                  </div>

                  {/* Security Settings */}
                  <div className="card p-6">
                    <h3 className="text-xl font-bold text-slate-900 mb-6">Security Settings</h3>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                        <div className="flex items-center space-x-3">
                          <Shield className="w-5 h-5 text-green-600" />
                          <div>
                            <div className="font-medium text-slate-900">Two-Factor Authentication</div>
                            <div className="text-sm text-slate-600">Add an extra layer of security</div>
                          </div>
                        </div>
                        <button className="btn btn-outline btn-sm">Enable</button>
                      </div>
                      
                      <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                        <div className="flex items-center space-x-3">
                          <AlertCircle className="w-5 h-5 text-amber-600" />
                          <div>
                            <div className="font-medium text-slate-900">Login Alerts</div>
                            <div className="text-sm text-slate-600">Get notified of new device logins</div>
                          </div>
                        </div>
                        <button className="btn btn-primary btn-sm">Enabled</button>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* Preferences Tab */}
              {activeTab === 'preferences' && (
                <motion.div
                  key="preferences"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="card p-6"
                >
                  <h3 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
                    <Bell className="w-5 h-5 mr-2 text-violet-600" />
                    Notification Preferences
                  </h3>

                  <div className="space-y-6">
                    {[
                      {
                        key: 'emailNotifications',
                        title: 'Email Notifications',
                        description: 'Receive email updates about your orders and account',
                        icon: Mail
                      },
                      {
                        key: 'smsNotifications',
                        title: 'SMS Notifications',
                        description: 'Get text messages for important updates',
                        icon: Phone
                      },
                      {
                        key: 'orderUpdates',
                        title: 'Order Updates',
                        description: 'Notifications about order status changes',
                        icon: Package
                      },
                      {
                        key: 'promotions',
                        title: 'Promotional Offers',
                        description: 'Special deals and discount notifications',
                        icon: CreditCard
                      },
                      {
                        key: 'newsletter',
                        title: 'Newsletter',
                        description: 'Weekly newsletter with new products and tips',
                        icon: Mail
                      }
                    ].map((pref) => (
                      <div key={pref.key} className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                        <div className="flex items-center space-x-3">
                          <pref.icon className="w-5 h-5 text-slate-600" />
                          <div>
                            <div className="font-medium text-slate-900">{pref.title}</div>
                            <div className="text-sm text-slate-600">{pref.description}</div>
                          </div>
                        </div>
                        <button
                          onClick={() => handlePreferenceChange(pref.key)}
                          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            preferences[pref.key] 
                              ? 'bg-gradient-to-r from-violet-600 to-indigo-600' 
                              : 'bg-slate-300'
                          }`}
                        >
                          <span
                            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                              preferences[pref.key] ? 'translate-x-6' : 'translate-x-1'
                            }`}
                          />
                        </button>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}

              {/* Orders Tab */}
              {activeTab === 'orders' && (
                <motion.div
                  key="orders"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="card p-6"
                >
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-bold text-slate-900 flex items-center">
                      <Package className="w-5 h-5 mr-2 text-violet-600" />
                      Recent Orders
                    </h3>
                    <button className="btn btn-outline btn-sm">View All Orders</button>
                  </div>

                  <div className="text-center py-12">
                    <div className="w-16 h-16 mx-auto mb-4 bg-slate-100 rounded-full flex items-center justify-center">
                      <Package className="w-8 h-8 text-slate-400" />
                    </div>
                    <h4 className="text-lg font-semibold text-slate-900 mb-2">No recent orders</h4>
                    <p className="text-slate-600 mb-6">Your order history will appear here</p>
                    <button className="btn btn-primary btn-md">Start Shopping</button>
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

export default Profile
