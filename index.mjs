import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Create Express app
const app = express();
app.use(express.json()); // Middleware to parse JSON

// MongoDB connection (replace with your connection string)
await mongoose.connect('mongodb://localhost:27017/jwt-example', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// User Schema and Model
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: { type: String, default: 'user' }  // Default role is 'user'
});

const User = mongoose.model('User', userSchema);

// Secret key for JWT
const JWT_SECRET = 'mySecretKey';

// Middleware to check if a user is authenticated
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Access denied, no token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;  // Save the decoded user data to req
        next();
    } catch (err) {
        return res.status(400).json({ error: 'Invalid token.' });
    }
};

// Middleware to check for specific roles
const roleMiddleware = (requiredRole) => {
    return (req, res, next) => {
        if (req.user.role !== requiredRole) {
            return res.status(403).json({ error: 'Access denied, insufficient permissions.' });
        }
        next();
    };
};

// Route: Register new user
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({ username, password: hashedPassword, role });

    try {
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ error: 'Error registering user' });
    }
});

// Route: Login user and generate JWT
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).json({ error: 'User not found' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(400).json({ error: 'Invalid password' });
    }

    // Generate JWT token including the user's role
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Route: General protected route (any logged-in user)
app.get('/dashboard', authMiddleware, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}, this is your dashboard!` });
});

// Route: Admin-only route
app.get('/admin', authMiddleware, roleMiddleware('admin'), (req, res) => {
    res.json({ message: `Welcome ${req.user.username}, you have admin access.` });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
