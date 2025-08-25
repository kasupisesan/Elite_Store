import { createContext, useContext, useReducer, useEffect } from 'react'
import { cartAPI } from '../utils/api'
import { useAuth } from './AuthContext'
import toast from 'react-hot-toast'

const CartContext = createContext()

const initialState = {
  items: [],
  totalItems: 0,
  totalPrice: 0,
  loading: false,
}

function cartReducer(state, action) {
  switch (action.type) {
    case 'SET_LOADING':
      return { ...state, loading: action.payload }
    case 'SET_CART':
      return {
        ...state,
        items: action.payload.items || [],
        totalItems: action.payload.totalItems || 0,
        totalPrice: action.payload.totalPrice || 0,
        loading: false,
      }
    case 'CLEAR_CART':
      return {
        ...state,
        items: [],
        totalItems: 0,
        totalPrice: 0,
        loading: false,
      }
    default:
      return state
  }
}

export function CartProvider({ children }) {
  const [state, dispatch] = useReducer(cartReducer, initialState)
  const { isAuthenticated } = useAuth()

  // Fetch cart when user is authenticated
  useEffect(() => {
    if (isAuthenticated) {
      fetchCart()
    } else {
      dispatch({ type: 'CLEAR_CART' })
    }
  }, [isAuthenticated])

  const fetchCart = async () => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true })
      const response = await cartAPI.getCart()
      dispatch({ type: 'SET_CART', payload: response.data.data })
    } catch (error) {
      // Don't log 401 errors as they're expected when not authenticated
      if (error.response?.status !== 401) {
        console.error('Error fetching cart:', error)
      }
      dispatch({ type: 'SET_LOADING', payload: false })
    }
  }

  const addToCart = async (productId, quantity = 1) => {
    if (!isAuthenticated) {
      toast.error('Please login to add items to cart')
      return { success: false, message: 'Not authenticated' }
    }

    try {
      dispatch({ type: 'SET_LOADING', payload: true })
      const response = await cartAPI.addToCart({ productId, quantity })
      
      // Update cart state with the returned cart data
      dispatch({ type: 'SET_CART', payload: response.data.data })
      
      // Show success message from backend or default
      const successMessage = response.data.message || 'Item added to cart'
      toast.success(successMessage)
      
      return { success: true }
    } catch (error) {
      dispatch({ type: 'SET_LOADING', payload: false })
      const message = error.response?.data?.message || 'Failed to add item to cart'
      
      if (error.response?.status === 401) {
        toast.error('Please login to add items to cart')
      } else if (error.response?.status === 400) {
        // Handle stock availability errors
        toast.error(message)
      } else if (error.response?.status === 404) {
        toast.error('Product not found or unavailable')
      } else {
        toast.error(message)
      }
      return { success: false, message }
    }
  }

  const updateCartItem = async (productId, quantity) => {
    if (!isAuthenticated) {
      toast.error('Please login to update cart')
      return { success: false, message: 'Not authenticated' }
    }

    try {
      dispatch({ type: 'SET_LOADING', payload: true })
      const response = await cartAPI.updateCartItem(productId, { quantity })
      
      // Update cart state with the returned cart data
      dispatch({ type: 'SET_CART', payload: response.data.data })
      
      // Show success message from backend
      const successMessage = response.data.message || 'Cart updated'
      toast.success(successMessage)
      
      return { success: true }
    } catch (error) {
      dispatch({ type: 'SET_LOADING', payload: false })
      const message = error.response?.data?.message || 'Failed to update cart'
      
      if (error.response?.status === 401) {
        toast.error('Please login to update cart')
      } else if (error.response?.status === 400) {
        // Handle stock availability errors
        toast.error(message)
      } else if (error.response?.status === 404) {
        toast.error('Product not found or cart item not found')
      } else {
        toast.error(message)
      }
      return { success: false, message }
    }
  }

  const removeFromCart = async (productId) => {
    if (!isAuthenticated) {
      toast.error('Please login to remove items from cart')
      return { success: false, message: 'Not authenticated' }
    }

    try {
      dispatch({ type: 'SET_LOADING', payload: true })
      const response = await cartAPI.removeFromCart(productId)
      
      // Update cart state with the returned cart data
      dispatch({ type: 'SET_CART', payload: response.data.data })
      
      // Show success message from backend
      const successMessage = response.data.message || 'Item removed from cart'
      toast.success(successMessage)
      
      return { success: true }
    } catch (error) {
      dispatch({ type: 'SET_LOADING', payload: false })
      const message = error.response?.data?.message || 'Failed to remove item'
      
      if (error.response?.status === 401) {
        toast.error('Please login to remove items from cart')
      } else if (error.response?.status === 404) {
        toast.error('Cart not found or item not in cart')
      } else {
        toast.error(message)
      }
      return { success: false, message }
    }
  }

  const clearCart = async () => {
    if (!isAuthenticated) {
      toast.error('Please login to clear cart')
      return { success: false, message: 'Not authenticated' }
    }

    try {
      dispatch({ type: 'SET_LOADING', payload: true })
      const response = await cartAPI.clearCart()
      
      // Update cart state with the returned empty cart data
      dispatch({ type: 'SET_CART', payload: response.data.data })
      
      // Show success message from backend
      const successMessage = response.data.message || 'Cart cleared'
      toast.success(successMessage)
      
      return { success: true }
    } catch (error) {
      dispatch({ type: 'SET_LOADING', payload: false })
      const message = error.response?.data?.message || 'Failed to clear cart'
      
      if (error.response?.status === 401) {
        toast.error('Please login to clear cart')
      } else if (error.response?.status === 404) {
        toast.error('Cart not found')
      } else {
        toast.error(message)
      }
      return { success: false, message }
    }
  }

  const value = {
    ...state,
    addToCart,
    updateCartItem,
    removeFromCart,
    clearCart,
    fetchCart,
  }

  return <CartContext.Provider value={value}>{children}</CartContext.Provider>
}

export function useCart() {
  const context = useContext(CartContext)
  if (!context) {
    throw new Error('useCart must be used within a CartProvider')
  }
  return context
}
