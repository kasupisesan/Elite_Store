# E-commerce Website

A full-stack e-commerce application built with Node.js, MongoDB, React, and Tailwind CSS.

## Features

### Frontend (React + Vite + Tailwind CSS)
- **Authentication**: User registration, login, logout with JWT tokens
- **Product Management**: Browse products with search, filtering, and pagination
- **Shopping Cart**: Add/remove items, update quantities, persistent cart
- **Order Management**: Place orders, view order history, track status
- **User Profile**: Update profile information and change password
- **Admin Dashboard**: Complete admin panel for managing products, orders, and users
- **Responsive Design**: Mobile-first design with smooth animations

### Backend (Node.js + Express + MongoDB)
- **RESTful API**: Well-structured API endpoints with proper HTTP methods
- **Authentication & Authorization**: JWT-based auth with role-based access control
- **Data Validation**: Comprehensive input validation using Zod schemas
- **File Upload**: Image upload integration with Cloudinary
- **Email Notifications**: Order confirmation emails via Nodemailer
- **Security**: Rate limiting, CORS, helmet, and other security middlewares
- **Database**: MongoDB with Mongoose ODM for data modeling

## Tech Stack

### Frontend
- **React 18** - UI library
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Utility-first CSS framework
- **React Router** - Client-side routing
- **React Query** - Data fetching and caching
- **React Hook Form** - Form handling
- **Framer Motion** - Animations
- **Axios** - HTTP client
- **React Hot Toast** - Notifications

### Backend
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MongoDB** - NoSQL database
- **Mongoose** - MongoDB ODM
- **JWT** - Authentication tokens
- **Zod** - Schema validation
- **Cloudinary** - Image storage
- **Nodemailer** - Email service
- **bcryptjs** - Password hashing

## Project Structure

```
E-commerce website/
├── backend/
│   ├── controllers/     # Route handlers
│   ├── middleware/      # Custom middleware
│   ├── models/         # Database models
│   ├── routes/         # API routes
│   ├── utils/          # Utility functions
│   ├── .env.example    # Environment variables template
│   ├── package.json    # Backend dependencies
│   └── server.js       # Main server file
├── frontend/
│   ├── src/
│   │   ├── components/ # Reusable components
│   │   ├── contexts/   # React contexts
│   │   ├── pages/      # Page components
│   │   ├── utils/      # Utility functions
│   │   ├── App.jsx     # Main app component
│   │   └── main.jsx    # Entry point
│   ├── index.html      # HTML template
│   ├── package.json    # Frontend dependencies
│   └── vite.config.js  # Vite configuration
└── README.md
```

## Installation & Setup

### Prerequisites
- Node.js (v16 or higher)
- MongoDB (local or cloud)
- Cloudinary account (for image uploads)
- Email service (Gmail, SendGrid, etc.)

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Install dependencies:
```bash
npm install
```

3. Create environment file:
```bash
cp .env.example .env
```

4. Configure environment variables in `.env`:
```env
NODE_ENV=development
PORT=7777
MONGO_URI=mongodb://localhost:27017/ecommerce
MONGO_URI_PROD=your_production_mongodb_uri
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRE=30d
CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret
EMAIL_FROM=your_email@example.com
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
FRONTEND_URL=http://localhost:5173
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

5. Start the backend server:
```bash
npm run dev
```

The backend will run on `http://localhost:7777`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Create environment file (optional):
```bash
# Create .env file if you need to override the API URL
VITE_API_URL=http://localhost:7777/api
```

4. Start the development server:
```bash
npm run dev
```

The frontend will run on `http://localhost:5173`

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/profile` - Get user profile
- `PUT /api/auth/profile` - Update user profile
- `PUT /api/auth/change-password` - Change password

### Products
- `GET /api/products` - Get all products (with filters)
- `GET /api/products/:id` - Get single product
- `POST /api/products` - Create product (Admin)
- `PUT /api/products/:id` - Update product (Admin)
- `DELETE /api/products/:id` - Delete product (Admin)
- `POST /api/products/:id/reviews` - Add product review

### Cart
- `GET /api/cart` - Get user cart
- `POST /api/cart/add` - Add item to cart
- `PUT /api/cart/update` - Update cart item
- `DELETE /api/cart/remove/:productId` - Remove item from cart
- `DELETE /api/cart/clear` - Clear entire cart

### Orders
- `GET /api/orders` - Get user orders / all orders (Admin)
- `GET /api/orders/:id` - Get single order
- `POST /api/orders` - Create new order
- `PUT /api/orders/:id/cancel` - Cancel order
- `PUT /api/orders/:id/status` - Update order status (Admin)
- `GET /api/orders/stats/overview` - Get order statistics (Admin)

### Users (Admin only)
- `GET /api/users` - Get all users
- `GET /api/users/:id` - Get single user
- `PUT /api/users/:id/role` - Update user role
- `DELETE /api/users/:id` - Delete user

## Features Overview

### User Features
- **Registration & Login**: Secure authentication with JWT tokens
- **Product Browsing**: Search, filter, and sort products
- **Shopping Cart**: Persistent cart with quantity management
- **Order Placement**: Secure checkout with address and payment info
- **Order Tracking**: View order history and current status
- **Profile Management**: Update personal information and password
- **Product Reviews**: Rate and review purchased products

### Admin Features
- **Dashboard**: Overview of sales, orders, and key metrics
- **Product Management**: Add, edit, delete products with image uploads
- **Order Management**: View all orders and update status
- **User Management**: View users and manage roles
- **Analytics**: Basic sales and order statistics

## Security Features
- JWT-based authentication
- Password hashing with bcrypt
- Input validation with Zod schemas
- Rate limiting to prevent abuse
- CORS configuration
- Helmet for security headers
- Role-based access control

## Deployment

### Backend Deployment
1. Set up MongoDB Atlas or your preferred MongoDB hosting
2. Configure production environment variables
3. Deploy to platforms like Heroku, Railway, or DigitalOcean
4. Ensure CORS is configured for your frontend domain

### Frontend Deployment
1. Build the production version:
```bash
npm run build
```
2. Deploy the `dist` folder to platforms like Netlify, Vercel, or Surge
3. Configure environment variables for production API URL

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support or questions, please open an issue in the repository or contact the development team.
