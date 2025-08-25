import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { 
  Search, 
  Filter, 
  Eye, 
  Users, 
  Shield, 
  ShieldCheck, 
  Mail, 
  Calendar, 
  AlertCircle,
  Crown,
  User,
  Phone,
  MapPin,
  MoreVertical,
  Ban,
  CheckCircle
} from 'lucide-react'
import { usersAPI } from '../../utils/api'
import toast from 'react-hot-toast'

function AdminUsers() {
  const [searchTerm, setSearchTerm] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [showRoleModal, setShowRoleModal] = useState(false)
  const [selectedUser, setSelectedUser] = useState(null)
  const [newRole, setNewRole] = useState('')

  const queryClient = useQueryClient()

  const { data: usersData, isLoading } = useQuery(
    ['adminUsers', currentPage, searchTerm, roleFilter],
    () => usersAPI.getAllUsers({ 
      page: currentPage, 
      limit: 10, 
      search: searchTerm, 
      role: roleFilter 
    }),
    { keepPreviousData: true }
  )

  const updateRoleMutation = useMutation(
    ({ userId, role }) => usersAPI.updateUserRole(userId, role),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('adminUsers')
        toast.success('User role updated successfully')
        setShowRoleModal(false)
        setSelectedUser(null)
        setNewRole('')
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to update user role')
      }
    }
  )

  const handleRoleUpdate = (user) => {
    setSelectedUser(user)
    setNewRole(user.role)
    setShowRoleModal(true)
  }

  const confirmRoleUpdate = () => {
    if (selectedUser && newRole) {
      updateRoleMutation.mutate({ userId: selectedUser._id, role: newRole })
    }
  }

  const getRoleIcon = (role) => {
    return role === 'admin' ? Crown : Shield
  }

  const getRoleColor = (role) => {
    return role === 'admin' ? 'from-purple-500 to-violet-600' : 'from-blue-500 to-cyan-600'
  }

  const getRoleBadgeColor = (role) => {
    return role === 'admin' ? 'badge-warning' : 'badge-info'
  }

  const roles = [
    { value: 'user', label: 'User', icon: Shield, description: 'Standard user permissions' },
    { value: 'admin', label: 'Admin', icon: Crown, description: 'Full system access' }
  ]

  const users = usersData?.data?.data || []
  const pagination = usersData?.data?.pagination || {}

  const totalUsers = pagination.total || 0
  const adminCount = users.filter(user => user.role === 'admin').length
  const userCount = users.filter(user => user.role === 'user').length

  return (
    <div className="min-h-screen py-8 bg-gradient-to-br from-slate-50 to-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Header */}
        <div className="mb-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <h1 className="text-3xl font-bold gradient-text mb-2">User Management</h1>
            <p className="text-slate-600">Manage user accounts and permissions</p>
          </motion.div>
        </div>

        {/* Stats Cards */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8"
        >
          {[
            { 
              title: 'Total Users', 
              value: totalUsers, 
              icon: Users, 
              color: 'from-blue-500 to-cyan-600',
              bgColor: 'bg-blue-50',
              textColor: 'text-blue-700'
            },
            { 
              title: 'Administrators', 
              value: adminCount, 
              icon: Crown, 
              color: 'from-purple-500 to-violet-600',
              bgColor: 'bg-purple-50',
              textColor: 'text-purple-700'
            },
            { 
              title: 'Regular Users', 
              value: userCount, 
              icon: User, 
              color: 'from-green-500 to-emerald-600',
              bgColor: 'bg-green-50',
              textColor: 'text-green-700'
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
                  <p className="text-3xl font-bold text-slate-900">{stat.value}</p>
                </div>
              </div>
              <div className={`absolute bottom-0 right-0 w-16 h-16 bg-gradient-to-br ${stat.color} opacity-10 rounded-full transform translate-x-6 translate-y-6`} />
            </motion.div>
          ))}
        </motion.div>

        {/* Role Filter Tabs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mb-6"
        >
          <div className="flex flex-wrap gap-2">
            {[
              { key: '', label: 'All Users', count: totalUsers },
              { key: 'user', label: 'Users', count: userCount },
              { key: 'admin', label: 'Admins', count: adminCount }
            ].map((role) => (
              <button
                key={role.key}
                onClick={() => {
                  setRoleFilter(role.key)
                  setCurrentPage(1)
                }}
                className={`px-4 py-2 rounded-xl text-sm font-medium transition-all ${
                  roleFilter === role.key
                    ? 'bg-gradient-to-r from-violet-600 to-indigo-600 text-white shadow-lg'
                    : 'bg-white text-slate-600 hover:bg-slate-50 border border-slate-200'
                }`}
              >
                {role.label}
                {role.count > 0 && (
                  <span className={`ml-2 px-2 py-0.5 rounded-full text-xs ${
                    roleFilter === role.key
                      ? 'bg-white/20 text-white'
                      : 'bg-slate-100 text-slate-600'
                  }`}>
                    {role.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </motion.div>

        {/* Search */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="card p-6 mb-6"
        >
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search users by name, email, or ID..."
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
                Export Users
              </button>
            </div>
          </div>
        </motion.div>

        {/* Users Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="card overflow-hidden"
        >
          {isLoading ? (
            <div className="p-8 text-center">
              <div className="loading-spinner mx-auto mb-4" />
              <p className="text-slate-600">Loading users...</p>
            </div>
          ) : users.length === 0 ? (
            <div className="p-8 text-center">
              <Users className="w-16 h-16 mx-auto mb-4 text-slate-400" />
              <h3 className="text-lg font-semibold text-slate-900 mb-2">No users found</h3>
              <p className="text-slate-600">Try adjusting your search or filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      User
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Role
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Contact
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Joined
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
                    {users.map((user, index) => {
                      const RoleIcon = getRoleIcon(user.role)
                      return (
                        <motion.tr
                          key={user._id}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -20 }}
                          transition={{ delay: index * 0.05 }}
                          className="hover:bg-slate-50 transition-colors"
                        >
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center space-x-4">
                              <div className={`w-10 h-10 rounded-full bg-gradient-to-br ${getRoleColor(user.role)} flex items-center justify-center`}>
                                <span className="text-white font-semibold text-sm">
                                  {user.name?.charAt(0)?.toUpperCase() || 'U'}
                                </span>
                              </div>
                              <div>
                                <div className="text-sm font-medium text-slate-900">
                                  {user.name || 'Unknown User'}
                                </div>
                                <div className="text-sm text-slate-500">
                                  ID: {user._id.slice(-8)}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`badge ${getRoleBadgeColor(user.role)} flex items-center`}>
                              <RoleIcon className="w-3 h-3 mr-1" />
                              {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="space-y-1">
                              <div className="flex items-center text-sm text-slate-900">
                                <Mail className="w-3 h-3 mr-2 text-slate-400" />
                                {user.email || 'No email'}
                              </div>
                              {user.phone && (
                                <div className="flex items-center text-sm text-slate-600">
                                  <Phone className="w-3 h-3 mr-2 text-slate-400" />
                                  {user.phone}
                                </div>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center text-sm text-slate-900">
                              <Calendar className="w-4 h-4 mr-2 text-slate-400" />
                              {new Date(user.createdAt).toLocaleDateString()}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className="badge badge-success">
                              <CheckCircle className="w-3 h-3 mr-1" />
                              Active
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <div className="flex items-center space-x-2">
                              <button
                                onClick={() => handleRoleUpdate(user)}
                                className="btn btn-outline btn-sm"
                              >
                                Change Role
                              </button>
                              <button className="btn btn-ghost btn-sm p-2">
                                <MoreVertical className="w-4 h-4" />
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

        {/* Role Update Modal */}
        <AnimatePresence>
          {showRoleModal && selectedUser && (
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
                <h3 className="text-lg font-bold text-slate-900 mb-4">Update User Role</h3>
                
                <div className="mb-6">
                  <div className="flex items-center space-x-3 mb-4 p-3 bg-slate-50 rounded-xl">
                    <div className={`w-10 h-10 rounded-full bg-gradient-to-br ${getRoleColor(selectedUser.role)} flex items-center justify-center`}>
                      <span className="text-white font-semibold text-sm">
                        {selectedUser.name?.charAt(0)?.toUpperCase() || 'U'}
                      </span>
                    </div>
                    <div>
                      <p className="font-medium text-slate-900">{selectedUser.name}</p>
                      <p className="text-sm text-slate-600">{selectedUser.email}</p>
                    </div>
                  </div>
                  
                  <label className="block text-sm font-medium text-slate-700 mb-3">
                    Select New Role
                  </label>
                  <div className="space-y-2">
                    {roles.map(role => (
                      <label key={role.value} className="block">
                        <input
                          type="radio"
                          name="role"
                          value={role.value}
                          checked={newRole === role.value}
                          onChange={(e) => setNewRole(e.target.value)}
                          className="sr-only"
                        />
                        <div className={`p-3 rounded-xl border-2 cursor-pointer transition-all ${
                          newRole === role.value
                            ? 'border-violet-500 bg-violet-50'
                            : 'border-slate-200 hover:border-slate-300'
                        }`}>
                          <div className="flex items-center space-x-3">
                            <role.icon className={`w-5 h-5 ${
                              newRole === role.value ? 'text-violet-600' : 'text-slate-600'
                            }`} />
                            <div>
                              <div className={`font-medium ${
                                newRole === role.value ? 'text-violet-900' : 'text-slate-900'
                              }`}>
                                {role.label}
                              </div>
                              <div className="text-sm text-slate-600">
                                {role.description}
                              </div>
                            </div>
                            {newRole === role.value && (
                              <CheckCircle className="w-5 h-5 text-violet-600 ml-auto" />
                            )}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
                
                <div className="flex space-x-3">
                  <button
                    onClick={() => setShowRoleModal(false)}
                    className="flex-1 btn btn-outline btn-md"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmRoleUpdate}
                    disabled={updateRoleMutation.isLoading || newRole === selectedUser.role}
                    className="flex-1 btn btn-primary btn-md disabled:opacity-50"
                  >
                    {updateRoleMutation.isLoading ? (
                      <>
                        <div className="loading-spinner mr-2" />
                        Updating...
                      </>
                    ) : (
                      'Update Role'
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

export default AdminUsers
