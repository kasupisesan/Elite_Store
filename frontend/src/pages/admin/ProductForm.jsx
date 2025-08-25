import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { useForm } from 'react-hook-form'
import { 
  ArrowLeft, 
  Upload, 
  X, 
  Save, 
  Package,
  Image as ImageIcon,
  DollarSign,
  Hash,
  FileText,
  Tag,
  Star,
  AlertCircle,
  Check
} from 'lucide-react'
import { productsAPI } from '../../utils/api'
import toast from 'react-hot-toast'

function ProductForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const isEditing = Boolean(id)
  const [selectedImages, setSelectedImages] = useState([])
  const [imageFiles, setImageFiles] = useState([])
  const [dragActive, setDragActive] = useState(false)

  const { 
    register, 
    handleSubmit, 
    setValue, 
    watch, 
    formState: { errors, isSubmitting } 
  } = useForm({
    defaultValues: {
      name: '',
      description: '',
      price: '',
      discount: 0,
      category: '',
      stockQuantity: '',
      specifications: '',
      features: '',
      brand: ''
    }
  })

  const watchedFields = watch()

  // Fetch product data if editing
  const { data: product, isLoading } = useQuery(
    ['product', id],
    () => productsAPI.getProduct(id),
    {
      enabled: isEditing,
      onSuccess: (response) => {
        const productData = response.data.data
        setValue('name', productData.name)
        setValue('description', productData.description)
        setValue('price', productData.price)
        setValue('discount', productData.discount || 0)
        setValue('category', productData.category)
        setValue('stockQuantity', productData.stockQuantity)
        setValue('brand', productData.brand || '')
        setValue('specifications', Array.isArray(productData.specifications) 
          ? productData.specifications.join('\n') 
          : Object.values(productData.specifications || {}).join('\n')
        )
        setValue('features', productData.features?.join('\n') || '')
        setSelectedImages(productData.images?.map(img => ({ url: img, isExisting: true })) || [])
      }
    }
  )

  const createProductMutation = useMutation(
    productsAPI.createProduct,
    {
      onSuccess: () => {
        queryClient.invalidateQueries('adminProducts')
        toast.success('Product created successfully!')
        navigate('/admin/products')
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to create product')
      }
    }
  )

  const updateProductMutation = useMutation(
    ({ id, data }) => productsAPI.updateProduct(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('adminProducts')
        queryClient.invalidateQueries(['product', id])
        toast.success('Product updated successfully!')
        navigate('/admin/products')
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to update product')
      }
    }
  )

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    const files = Array.from(e.dataTransfer.files).filter(file => file.type.startsWith('image/'))
    if (files.length > 0) {
      handleImageChange({ target: { files } })
    }
  }

  const handleImageChange = (e) => {
    const files = Array.from(e.target.files || e.target)
    if (selectedImages.length + files.length > 5) {
      toast.error('Maximum 5 images allowed')
      return
    }

    setImageFiles(prev => [...prev, ...files])
    
    files.forEach(file => {
      const reader = new FileReader()
      reader.onload = (e) => {
        setSelectedImages(prev => [...prev, { 
          url: e.target.result, 
          isNew: true,
          file: file
        }])
      }
      reader.readAsDataURL(file)
    })
  }

  const removeImage = (index) => {
    setSelectedImages(prev => prev.filter((_, i) => i !== index))
    setImageFiles(prev => prev.filter((_, i) => i !== index))
  }

  const onSubmit = async (data) => {
    const payload = {
      name: data.name.trim(),
      description: data.description.trim(),
      price: Number(data.price),
      discount: Number(data.discount) || 0,
      category: data.category,
      stockQuantity: Number(data.stockQuantity),
      brand: data.brand?.trim() || undefined
    }

    // Parse features
    if (data.features) {
      payload.features = data.features.split('\n').filter(f => f.trim()).map(f => f.trim())
    }

    // Parse specifications
    if (data.specifications) {
      const lines = data.specifications.split('\n').filter(l => l.trim())
      const specsObj = {}
      lines.forEach((line, idx) => {
        const parts = line.split(':')
        if (parts.length >= 2) {
          const key = parts[0].trim()
          const value = parts.slice(1).join(':').trim()
          specsObj[key] = value
        } else {
          specsObj[`spec${idx + 1}`] = line.trim()
        }
      })
      payload.specifications = specsObj
    }

    if (isEditing) {
      updateProductMutation.mutate({ id, data: payload })
    } else {
      createProductMutation.mutate(payload, {
        onSuccess: (created) => {
          const newId = created.data.data._id
          if (imageFiles.length > 0) {
            const imgForm = new FormData()
            imageFiles.forEach(file => imgForm.append('images', file))
            productsAPI.uploadProductImages(newId, imgForm).finally(() => {
              queryClient.invalidateQueries('adminProducts')
              navigate('/admin/products')
            })
          }
        }
      })
    }
  }

  const categories = [
    { label: '⚡ Electronics', value: 'electronics' },
    { label: '👕 Fashion', value: 'clothing' },
    { label: '📚 Books', value: 'books' },
    { label: '🏠 Home & Garden', value: 'home' },
    { label: '🏃 Sports & Fitness', value: 'sports' },
    { label: '💄 Beauty & Personal Care', value: 'beauty' },
    { label: '🧸 Toys & Games', value: 'toys' },
    { label: '🚗 Automotive', value: 'automotive' },
    { label: '📦 Other', value: 'other' }
  ]

  if (isEditing && isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="loading-spinner mx-auto mb-4" />
          <p className="text-slate-600">Loading product data...</p>
        </div>
      </div>
    )
  }

  const isFormValid = watchedFields.name && watchedFields.price && watchedFields.category && watchedFields.stockQuantity

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center space-x-4"
          >
            <Link
              to="/admin/products"
              className="w-10 h-10 rounded-xl bg-white border border-slate-200 flex items-center justify-center hover:bg-slate-50 transition-colors group"
            >
              <ArrowLeft className="w-5 h-5 text-slate-600 group-hover:-translate-x-0.5 transition-transform" />
            </Link>
            <div>
              <h1 className="text-3xl font-bold gradient-text">
                {isEditing ? 'Edit Product' : 'Add New Product'}
              </h1>
              <p className="text-slate-600 mt-1">
                {isEditing ? 'Update product information' : 'Create a new product for your store'}
              </p>
            </div>
          </motion.div>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-8">
          
          {/* Basic Information */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="card p-6"
          >
            <h2 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
              <Package className="w-5 h-5 mr-2 text-violet-600" />
              Basic Information
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Product Name *
                </label>
                <input
                  {...register('name', { required: 'Product name is required' })}
                  className={`input ${errors.name ? 'input-error' : ''}`}
                  placeholder="Enter product name"
                />
                {errors.name && (
                  <p className="mt-1 text-sm text-red-600 flex items-center">
                    <AlertCircle className="w-4 h-4 mr-1" />
                    {errors.name.message}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Category *
                </label>
                <select
                  {...register('category', { required: 'Category is required' })}
                  className={`input ${errors.category ? 'input-error' : ''}`}
                >
                  <option value="">Select a category</option>
                  {categories.map(category => (
                    <option key={category.value} value={category.value}>
                      {category.label}
                    </option>
                  ))}
                </select>
                {errors.category && (
                  <p className="mt-1 text-sm text-red-600 flex items-center">
                    <AlertCircle className="w-4 h-4 mr-1" />
                    {errors.category.message}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Brand
                </label>
                <input
                  {...register('brand')}
                  className="input"
                  placeholder="Enter brand name"
                />
              </div>

              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Description
                </label>
                <textarea
                  {...register('description')}
                  className="input min-h-[120px]"
                  placeholder="Describe your product..."
                />
              </div>
            </div>
          </motion.div>

          {/* Pricing & Inventory */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="card p-6"
          >
            <h2 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
              <DollarSign className="w-5 h-5 mr-2 text-violet-600" />
              Pricing & Inventory
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Price (₹) *
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  {...register('price', { required: 'Price is required', min: 0 })}
                  className={`input ${errors.price ? 'input-error' : ''}`}
                  placeholder="0.00"
                />
                {errors.price && (
                  <p className="mt-1 text-sm text-red-600 flex items-center">
                    <AlertCircle className="w-4 h-4 mr-1" />
                    {errors.price.message}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Discount (%)
                </label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  {...register('discount')}
                  className="input"
                  placeholder="0"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Stock Quantity *
                </label>
                <input
                  type="number"
                  min="0"
                  {...register('stockQuantity', { required: 'Stock quantity is required', min: 0 })}
                  className={`input ${errors.stockQuantity ? 'input-error' : ''}`}
                  placeholder="0"
                />
                {errors.stockQuantity && (
                  <p className="mt-1 text-sm text-red-600 flex items-center">
                    <AlertCircle className="w-4 h-4 mr-1" />
                    {errors.stockQuantity.message}
                  </p>
                )}
              </div>
            </div>

            {/* Price Preview */}
            {watchedFields.price && (
              <div className="mt-4 p-4 bg-gradient-to-r from-green-50 to-emerald-50 rounded-xl">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-green-700">Price Preview:</span>
                  <div className="flex items-center space-x-2">
                    {watchedFields.discount > 0 && (
                      <span className="text-lg text-slate-500 line-through">
                        ₹{Number(watchedFields.price).toLocaleString()}
                      </span>
                    )}
                    <span className="text-2xl font-bold text-green-600">
                      ₹{(Number(watchedFields.price) * (1 - Number(watchedFields.discount || 0) / 100)).toLocaleString()}
                    </span>
                    {watchedFields.discount > 0 && (
                      <span className="badge bg-red-500 text-white">
                        -{watchedFields.discount}%
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}
          </motion.div>

          {/* Product Images */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="card p-6"
          >
            <h2 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
              <ImageIcon className="w-5 h-5 mr-2 text-violet-600" />
              Product Images
              <span className="ml-2 text-sm font-normal text-slate-500">
                (Maximum 5 images)
              </span>
            </h2>

            {/* Image Upload Area */}
            <div
              className={`relative border-2 border-dashed rounded-2xl p-8 text-center transition-all ${
                dragActive 
                  ? 'border-violet-400 bg-violet-50' 
                  : 'border-slate-300 hover:border-slate-400'
              }`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
            >
              <input
                type="file"
                multiple
                accept="image/*"
                onChange={handleImageChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                disabled={selectedImages.length >= 5}
              />
              <ImageIcon className="w-12 h-12 mx-auto mb-4 text-slate-400" />
              <h3 className="text-lg font-semibold text-slate-900 mb-2">
                {selectedImages.length >= 5 ? 'Maximum images reached' : 'Upload Product Images'}
              </h3>
              <p className="text-slate-600 mb-4">
                {selectedImages.length >= 5 
                  ? 'Remove some images to add new ones'
                  : 'Drag and drop images here, or click to select files'
                }
              </p>
              {selectedImages.length < 5 && (
                <button
                  type="button"
                  className="btn btn-outline btn-md"
                  onClick={() => document.querySelector('input[type="file"]').click()}
                >
                  <Upload className="w-4 h-4 mr-2" />
                  Choose Images
                </button>
              )}
            </div>

            {/* Image Preview Grid */}
            {selectedImages.length > 0 && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-6">
                {selectedImages.map((image, index) => (
                  <div key={index} className="relative group">
                    <img
                      src={image.url}
                      alt={`Preview ${index + 1}`}
                      className="w-full h-24 object-cover rounded-xl border-2 border-slate-200"
                    />
                    <button
                      type="button"
                      onClick={() => removeImage(index)}
                      className="absolute -top-2 -right-2 w-6 h-6 bg-red-500 text-white rounded-full opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center hover:bg-red-600"
                    >
                      <X className="w-4 h-4" />
                    </button>
                    {index === 0 && (
                      <div className="absolute bottom-1 left-1 bg-violet-600 text-white text-xs px-2 py-1 rounded">
                        Main
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </motion.div>

          {/* Additional Details */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="card p-6"
          >
            <h2 className="text-xl font-bold text-slate-900 mb-6 flex items-center">
              <FileText className="w-5 h-5 mr-2 text-violet-600" />
              Additional Details
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Features
                  <span className="text-xs text-slate-500 ml-1">(One per line)</span>
                </label>
                <textarea
                  {...register('features')}
                  className="input min-h-[120px]"
                  placeholder={`High-quality materials\nDurable construction\nEasy to use\nLightweight design`}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-2">
                  Specifications
                  <span className="text-xs text-slate-500 ml-1">(Key: Value format)</span>
                </label>
                <textarea
                  {...register('specifications')}
                  className="input min-h-[120px]"
                  placeholder={`Weight: 500g\nDimensions: 30x20x10 cm\nMaterial: Premium plastic\nColor: Available in multiple colors`}
                />
              </div>
            </div>
          </motion.div>

          {/* Form Actions */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="flex flex-col sm:flex-row gap-4 justify-end"
          >
            <Link
              to="/admin/products"
              className="btn btn-outline btn-lg"
            >
              Cancel
            </Link>
            <button
              type="submit"
              disabled={!isFormValid || isSubmitting || createProductMutation.isLoading || updateProductMutation.isLoading}
              className="btn btn-primary btn-lg disabled:opacity-50 group"
            >
              {isSubmitting || createProductMutation.isLoading || updateProductMutation.isLoading ? (
                <>
                  <div className="loading-spinner mr-2" />
                  {isEditing ? 'Updating...' : 'Creating...'}
                </>
              ) : (
                <>
                  <Save className="w-5 h-5 mr-2 group-hover:animate-pulse" />
                  {isEditing ? 'Update Product' : 'Create Product'}
                </>
              )}
            </button>
          </motion.div>

          {/* Form Validation Status */}
          {!isFormValid && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="card p-4 bg-amber-50 border-amber-200"
            >
              <div className="flex items-center text-amber-800">
                <AlertCircle className="w-5 h-5 mr-2" />
                <span className="text-sm font-medium">
                  Please fill in all required fields: Name, Category, Price, and Stock Quantity
                </span>
              </div>
            </motion.div>
          )}
        </form>
      </div>
    </div>
  )
}

export default ProductForm
