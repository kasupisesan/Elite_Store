import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useMutation } from 'react-query'
import {
  CreditCard,
  Truck,
  MapPin,
  Phone,
  User,
  Shield,
  Check,
  Lock,
  Package,
  ArrowRight,
  Edit,
  Sparkles
} from 'lucide-react'
import { useCart } from '../contexts/CartContext'
import { useAuth } from '../contexts/AuthContext'
import { ordersAPI } from '../utils/api'
import toast from 'react-hot-toast'

function Checkout() {
  const [formData, setFormData] = useState({
    shippingAddress: {
      fullName: '',
      address: '',
      city: '',
      postalCode: '',
      country: 'India',
      phone: ''
    },
    paymentMethod: 'cash_on_delivery'
  })
  const [isProcessing, setIsProcessing] = useState(false)
  const [step, setStep] = useState(1) // 1: Address, 2: Payment, 3: Review

  const { items, totalPrice, clearCart } = useCart()
  const { user } = useAuth()
  const hasSavedAddress = !!(user && user.address && user.address.street)
  const [useSavedAddress, setUseSavedAddress] = useState(hasSavedAddress)
  
  // Prefill shipping address from user profile when available or when user selects saved address
  useEffect(() => {
    if (user) {
      setFormData(prev => ({
        ...prev,
        shippingAddress: {
          fullName: user.name || prev.shippingAddress.fullName,
          address: user.address?.street || prev.shippingAddress.address,
          city: user.address?.city || prev.shippingAddress.city,
          postalCode: user.address?.zipCode || prev.shippingAddress.postalCode,
          country: user.address?.country || prev.shippingAddress.country,
          phone: user.phone || prev.shippingAddress.phone
        }
      }))
    }
  }, [user, useSavedAddress])
  const navigate = useNavigate()

  const createOrderMutation = useMutation(ordersAPI.createOrder, {
    onSuccess: (response) => {
      clearCart()
      toast.success('Order placed successfully!')
      navigate(`/orders/${response.data.data._id}`)
    },
    onError: (error) => {
      toast.error(error.response?.data?.message || 'Failed to place order')
      setIsProcessing(false)
    }
  })

  const handleAddressOption = (useSaved) => {
    setUseSavedAddress(useSaved)
    if (useSaved && user) {
      setFormData(prev => ({
        ...prev,
        shippingAddress: {
          fullName: user.name || '',
          address: user.address?.street || '',
          city: user.address?.city || '',
          postalCode: user.address?.zipCode || '',
          country: user.address?.country || 'India',
          phone: user.phone || ''
        }
      }))
    } else if (!useSaved) {
      setFormData(prev => ({
        ...prev,
        shippingAddress: {
          fullName: '',
          address: '',
          city: '',
          postalCode: '',
          country: 'India',
          phone: ''
        }
      }))
    }
  }

  const handleInputChange = (e) => {
    const { name, value } = e.target
    if (name.startsWith('shippingAddress.')) {
      const field = name.split('.')[1]
      setFormData(prev => ({
        ...prev,
        shippingAddress: { ...prev.shippingAddress, [field]: value }
      }))
    } else {
      setFormData(prev => ({ ...prev, [name]: value }))
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setIsProcessing(true)
    createOrderMutation.mutate(formData)
  }

  const shippingCost = totalPrice >= 999 ? 0 : 99
  const finalTotal = totalPrice + shippingCost

  if (!items || items.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="w-24 h-24 mx-auto mb-6 bg-orange-100 rounded-full flex items-center justify-center">
            <Package className="w-12 h-12 text-orange-600" />
          </div>
          <h2 className="text-2xl font-bold text-slate-900 mb-4">Your cart is empty</h2>
          <p className="text-slate-600 mb-6">Add some products to proceed with checkout</p>
          <button
            onClick={() => navigate('/products')}
            className="btn btn-primary btn-lg"
          >
            Start Shopping
          </button>
        </div>
      </div>
    )
  }

  const paymentMethods = [
    {
      id: 'cash_on_delivery',
      name: 'Cash on Delivery',
      description: 'Pay when your order is delivered',
      icon: '💵'
    },
    {
      id: 'credit_card',
      name: 'Credit/Debit Card',
      description: 'Pay securely with your card',
      icon: '💳'
    },
    {
      id: 'upi',
      name: 'UPI Payment',
      description: 'Pay using UPI apps',
      icon: '📱'
    },
    {
      id: 'net_banking',
      name: 'Net Banking',
      description: 'Pay using internet banking',
      icon: '🏦'
    }
  ]

  const steps = [
    { id: 1, name: 'Shipping', icon: Truck },
    { id: 2, name: 'Payment', icon: CreditCard },
    { id: 3, name: 'Review', icon: Check }
  ]

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold gradient-text mb-4">Checkout</h1>

          {/* Progress Steps */}
          <div className="flex items-center justify-between max-w-md mx-auto mb-8">
            {steps.map((stepItem, index) => (
              <div key={stepItem.id} className="flex items-center">
                <div className={`relative flex items-center justify-center w-10 h-10 rounded-full transition-all ${step >= stepItem.id
                    ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white'
                    : 'bg-slate-200 text-slate-500'
                  }`}>
                  {step > stepItem.id ? (
                    <Check className="w-5 h-5" />
                  ) : (
                    <stepItem.icon className="w-5 h-5" />
                  )}
                </div>
                <span className={`ml-2 text-sm font-medium ${step >= stepItem.id ? 'text-violet-600' : 'text-slate-500'
                  }`}>
                  {stepItem.name}
                </span>
                {index < steps.length - 1 && (
                  <div className={`w-8 h-0.5 mx-4 transition-all ${step > stepItem.id ? 'bg-violet-600' : 'bg-slate-200'
                    }`} />
                )}
              </div>
            ))}
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

            {/* Main Content */}
            <div className="lg:col-span-2">

              {/* Step 1: Shipping Address */}
              {step === 1 && (
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="card p-6"
                >
                  <h3 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
                    <MapPin className="w-5 h-5 mr-2 text-violet-600" />
                    Shipping Address
                  </h3>
                  {hasSavedAddress && (
                    <div className="mb-6 space-y-2">
                      <label className="flex items-center gap-2 text-sm font-medium text-slate-700">
                        <input
                          type="radio"
                          name="addressOption"
                          value="saved"
                          checked={useSavedAddress}
                          onChange={() => handleAddressOption(true)}
                        />
                        Use saved address
                      </label>
                      <label className="flex items-center gap-2 text-sm font-medium text-slate-700">
                        <input
                          type="radio"
                          name="addressOption"
                          value="new"
                          checked={!useSavedAddress}
                          onChange={() => handleAddressOption(false)}
                        />
                        Enter new address
                      </label>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        <User className="w-4 h-4 inline mr-1" />
                        Full Name *
                      </label>
                      <input
                        type="text"
                        name="shippingAddress.fullName"
                        value={formData.shippingAddress.fullName}
                        onChange={handleInputChange}
                        className="input" disabled={useSavedAddress}
                        required
                        placeholder="Enter your full name"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        <Phone className="w-4 h-4 inline mr-1" />
                        Phone Number *
                      </label>
                      <input
                        type="tel"
                        name="shippingAddress.phone"
                        value={formData.shippingAddress.phone}
                        onChange={handleInputChange}
                        className="input"
                        required
                        placeholder="Enter your phone number"
                        disabled={useSavedAddress}
                      />
                    </div>
                  </div>

                  <div className="mt-6">
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      <MapPin className="w-4 h-4 inline mr-1" />
                      Street Address *
                    </label>
                    <textarea
                      name="shippingAddress.address"
                      value={formData.shippingAddress.address}
                      onChange={handleInputChange}
                      className="input min-h-[100px]" disabled={useSavedAddress}
                      required
                      placeholder="Enter your complete address"
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">City *</label>
                      <input
                        type="text"
                        name="shippingAddress.city"
                        value={formData.shippingAddress.city}
                        onChange={handleInputChange}
                        className="input" disabled={useSavedAddress}
                        required
                        placeholder="City"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">Postal Code *</label>
                      <input
                        type="text"
                        name="shippingAddress.postalCode"
                        value={formData.shippingAddress.postalCode}
                        onChange={handleInputChange}
                        className="input" disabled={useSavedAddress}
                        required
                        placeholder="Postal Code"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">Country</label>
                      <select
                        name="shippingAddress.country"
                        value={formData.shippingAddress.country}
                        onChange={handleInputChange}
                        className="input" disabled={useSavedAddress}
                      >
                        <option value="India">India</option>
                        <option value="USA">USA</option>
                        <option value="UK">UK</option>
                      </select>
                    </div>
                  </div>

                  <div className="mt-8 flex justify-end">
                    <motion.button
                      type="button"
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => setStep(2)}
                      disabled={!formData.shippingAddress.fullName || !formData.shippingAddress.address || !formData.shippingAddress.city || !formData.shippingAddress.postalCode || !formData.shippingAddress.phone}
                      className="btn btn-primary btn-lg group disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Continue to Payment
                      <ArrowRight className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform" />
                    </motion.button>
                  </div>
                </motion.div>
              )}

              {/* Step 2: Payment Method */}
              {step === 2 && (
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="card p-6"
                >
                  <h3 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
                    <CreditCard className="w-5 h-5 mr-2 text-violet-600" />
                    Payment Method
                  </h3>

                  <div className="space-y-4">
                    {paymentMethods.map((method) => (
                      <label key={method.id} className="block">
                        <input
                          type="radio"
                          name="paymentMethod"
                          value={method.id}
                          checked={formData.paymentMethod === method.id}
                          onChange={handleInputChange}
                          className="sr-only"
                        />
                        <div className={`card p-4 cursor-pointer transition-all hover:shadow-md ${formData.paymentMethod === method.id
                            ? 'ring-2 ring-violet-500 border-violet-200 bg-violet-50'
                            : 'border-slate-200'
                          }`}>
                          <div className="flex items-center">
                            <span className="text-2xl mr-4">{method.icon}</span>
                            <div className="flex-1">
                              <div className="font-semibold text-slate-900">{method.name}</div>
                              <div className="text-sm text-slate-600">{method.description}</div>
                            </div>
                            {formData.paymentMethod === method.id && (
                              <div className="w-6 h-6 bg-violet-600 rounded-full flex items-center justify-center">
                                <Check className="w-4 h-4 text-white" />
                              </div>
                            )}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>

                  <div className="mt-8 flex justify-between">
                    <button
                      type="button"
                      onClick={() => setStep(1)}
                      className="btn btn-outline btn-lg"
                    >
                      Back
                    </button>
                    <motion.button
                      type="button"
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => setStep(3)}
                      className="btn btn-primary btn-lg group"
                    >
                      Review Order
                      <ArrowRight className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform" />
                    </motion.button>
                  </div>
                </motion.div>
              )}

              {/* Step 3: Review Order */}
              {step === 3 && (
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="space-y-6"
                >

                  {/* Shipping Address Review */}
                  <div className="card p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-slate-900 flex items-center">
                        <MapPin className="w-5 h-5 mr-2 text-violet-600" />
                        Shipping Address
                      </h3>
                      <button
                        type="button"
                        onClick={() => setStep(1)}
                        className="text-violet-600 hover:text-violet-700 font-medium text-sm flex items-center"
                      >
                        <Edit className="w-4 h-4 mr-1" />
                        Edit
                      </button>
                    </div>
                    <div className="bg-slate-50 rounded-xl p-4">
                      <p className="font-medium text-slate-900">{formData.shippingAddress.fullName}</p>
                      <p className="text-slate-600 mt-1">{formData.shippingAddress.address}</p>
                      <p className="text-slate-600">
                        {formData.shippingAddress.city}, {formData.shippingAddress.postalCode}
                      </p>
                      <p className="text-slate-600">{formData.shippingAddress.country}</p>
                      <p className="text-slate-600 mt-2">📱 {formData.shippingAddress.phone}</p>
                    </div>
                  </div>

                  {/* Payment Method Review */}
                  <div className="card p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-slate-900 flex items-center">
                        <CreditCard className="w-5 h-5 mr-2 text-violet-600" />
                        Payment Method
                      </h3>
                      <button
                        type="button"
                        onClick={() => setStep(2)}
                        className="text-violet-600 hover:text-violet-700 font-medium text-sm flex items-center"
                      >
                        <Edit className="w-4 h-4 mr-1" />
                        Edit
                      </button>
                    </div>
                    <div className="bg-slate-50 rounded-xl p-4">
                      <p className="font-medium text-slate-900">
                        {paymentMethods.find(m => m.id === formData.paymentMethod)?.name}
                      </p>
                      <p className="text-slate-600 mt-1">
                        {paymentMethods.find(m => m.id === formData.paymentMethod)?.description}
                      </p>
                    </div>
                  </div>

                  {/* Order Items */}
                  <div className="card p-6">
                    <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center">
                      <Package className="w-5 h-5 mr-2 text-violet-600" />
                      Order Items ({items.length})
                    </h3>
                    <div className="space-y-4">
                      {items.map((item) => (
                        <div key={item._id} className="flex items-center gap-4 p-4 bg-slate-50 rounded-xl">
                          <img
                            src={
                              item.product.images?.[0]?.url ||
                              item.product.images?.[0]
                            }
                            alt={item.product.name}
                            className="w-16 h-16 object-cover rounded-lg"
                            onError={(e) => {
                              e.target.src = 'https://images.unsplash.com/photo-1560472355-536de3962603?w=200';
                            }}
                            loading="lazy"
                          />

                          <div className="flex-1">
                            <h4 className="font-medium text-slate-900 line-clamp-1">{item.product.name}</h4>
                            <p className="text-sm text-slate-600">Qty: {item.quantity}</p>
                            <p className="text-lg font-bold gradient-text">
                              ₹{(item.product.price * item.quantity).toLocaleString()}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="flex justify-between">
                    <button
                      type="button"
                      onClick={() => setStep(2)}
                      className="btn btn-outline btn-lg"
                    >
                      Back
                    </button>
                    <motion.button
                      type="submit"
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      disabled={isProcessing}
                      className="btn btn-primary btn-lg group disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isProcessing ? (
                        <>
                          <div className="loading-spinner mr-2" />
                          Processing...
                        </>
                      ) : (
                        <>
                          <Lock className="w-5 h-5 mr-2 group-hover:animate-pulse" />
                          Place Order
                        </>
                      )}
                    </motion.button>
                  </div>
                </motion.div>
              )}
            </div>

            {/* Order Summary Sidebar */}
            <div className="lg:col-span-1">
              <div className="card p-6 sticky top-24 bg-gradient-to-br from-white to-slate-50">
                <h3 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
                  <Sparkles className="w-5 h-5 mr-2 text-violet-600" />
                  Order Summary
                </h3>

                <div className="space-y-4">
                  <div className="flex justify-between text-slate-600">
                    <span>Subtotal ({items.length} items)</span>
                    <span>₹{totalPrice.toLocaleString()}</span>
                  </div>

                  <div className="flex justify-between text-slate-600">
                    <span className="flex items-center">
                      <Truck className="w-4 h-4 mr-1" />
                      Shipping
                    </span>
                    <span className={shippingCost === 0 ? 'text-green-600 font-medium' : ''}>
                      {shippingCost === 0 ? 'FREE' : `₹${shippingCost}`}
                    </span>
                  </div>

                  <div className="border-t border-slate-200 pt-4">
                    <div className="flex justify-between items-center">
                      <span className="text-xl font-bold text-slate-900">Total</span>
                      <span className="text-2xl font-bold gradient-text">
                        ₹{finalTotal.toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Security Features */}
                <div className="mt-6 pt-6 border-t border-slate-200 space-y-3">
                  {[
                    { icon: Shield, text: 'SSL Encrypted' },
                    { icon: Lock, text: 'Secure Payment' },
                    { icon: Check, text: 'Money Back Guarantee' }
                  ].map((feature, index) => (
                    <div key={index} className="flex items-center text-sm text-slate-600">
                      <feature.icon className="w-4 h-4 mr-2 text-green-600" />
                      <span>{feature.text}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}

export default Checkout
