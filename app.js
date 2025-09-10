require('dotenv').config({ path: './.env' });
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const { sendCouponNotification, sendCouponRequestNotification } = require('./whatsapp');

const app = express();
const PORT = process.env.PORT || 3000;

const multer = require('multer'); // Add this line

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files
app.set('view engine', 'ejs'); // Set EJS as the templating engine
app.set('views', path.join(__dirname, 'views')); // Set views directory

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET, // Using environment variable
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' } // Set to true if using HTTPS in production
}));

app.set('trust proxy', 1);

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = path.join(__dirname, 'public', 'uploads', 'profile_pics');
        // Ensure the directory exists
        require('fs').mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        cb(null, req.session.userId + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// Database setup for PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

// Function to create users table if it doesn't exist
const createUsersTable = async () => {
    const queryText = `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        dob TEXT NOT NULL,
        city TEXT NOT NULL,
        contact TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_winner INTEGER DEFAULT 0,
        winner_position TEXT DEFAULT NULL,
        status TEXT DEFAULT 'Active',
        profile_pic TEXT DEFAULT NULL,
        coupon_code TEXT,
        has_spun BOOLEAN DEFAULT false,
        spin_prize INTEGER
    )`;
    try {
        await pool.query(queryText);
        console.log('Users table is ready.');
        // Add has_spun column if it doesn't exist
        await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS has_spun BOOLEAN DEFAULT false');
        // Add spin_prize column if it doesn't exist
        await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS spin_prize INTEGER');
        // Add coupon_code column if it doesn't exist
        await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS coupon_code TEXT');
    } catch (err) {
        console.error('Error creating users table:', err.stack);
    }
};

// Call the function to ensure the table exists when the app starts
createUsersTable();


// Prize Definitions
const prizes = [
    { position: '1st', name: 'Bike', image: '/images/prizes/1_Prize_Bike.jpeg' },
    { position: '2nd', name: 'Smart Mobile', image: '/images/prizes/2_Prize_Smart_Mobile.jpeg' },
    { position: '3rd', name: 'Gold Coin', image: '/images/prizes/3_Prize_Gold_Coin.jpeg' },
    { position: '4th-10th', name: 'Gift Card', image: '/images/prizes/4_to_10_Prize_Gift_Card.jpeg' }
];

// Helper function to generate a random alphanumeric string of a given length
function generateRandomAlphanumericString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// Routes
app.get('/', (req, res) => {
    res.render('index', { title: 'Welcome to DREAMURLIFEWITHME', prizes: prizes });
});

// User Registration GET route
app.get('/register', (req, res) => {
    res.render('register', { message: null });
});

// User Registration POST route
app.post('/register', async (req, res) => {
    const { name, dob, city, contact, email, userId, password, confirmPassword } = req.body;

    if (!name || !dob || !city || !contact || !email || !userId || !password || !confirmPassword) {
        return res.render('register', { message: 'All fields are required.' });
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.render('register', { message: 'Invalid email format.' });
    }
    if (!/^\d{10}$/.test(contact)) {
        return res.render('register', { message: 'Contact number must be 10 digits.' });
    }
    if (!/^[a-zA-Z0-9]{6,15}$/.test(userId)) {
        return res.render('register', { message: 'User ID must be 6-15 alphanumeric characters.' });
    }
    if (password.length < 6) {
        return res.render('register', { message: 'Password must be at least 6 characters long.' });
    }
    if (password !== confirmPassword) {
        return res.render('register', { message: 'Passwords do not match.' });
    }

    try {
        const totalUsersResult = await pool.query('SELECT COUNT(*) FROM users');
        const totalUsers = parseInt(totalUsersResult.rows[0].count, 10);

        if (totalUsers >= 20) {
            return res.render('register', { message: 'Sorry, we are not accepting new registrations at this time.' });
        }

        let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            return res.render('register', { message: 'Email already registered.' });
        }

        result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (result.rows.length > 0) {
            return res.render('register', { message: 'User ID already taken.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query('INSERT INTO users (id, name, dob, city, contact, email, password) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [userId, name, dob, city, contact, email, hashedPassword]);

        res.render('registration_success', { userId: userId, rawPassword: password });

    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { message: 'An unexpected error occurred.' });
    }
});

// Upload Photo GET route
app.get('/upload-photo', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('upload_photo', { message: null });
});

// Upload Photo POST route
app.post('/upload-photo', upload.single('profilePic'), async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    if (!req.file) {
        return res.render('upload_photo', { message: 'Please select an image to upload.' });
    }
    const profilePicPath = '/uploads/profile_pics/' + req.file.filename;
    try {
        await pool.query('UPDATE users SET profile_pic = $1 WHERE id = $2', [profilePicPath, req.session.userId]);
        req.session.user.profile_pic = profilePicPath;
        res.render('upload_photo', { message: 'Photo uploaded successfully!', success: true });
    } catch (error) {
        console.error('Photo upload error:', error);
        res.render('upload_photo', { message: 'An unexpected error occurred.' });
    }
});

// User Login GET route
app.get('/login', (req, res) => {
    res.render('login', { message: null });
});

// User Login POST route
app.post('/login', async (req, res) => {
    const { userId, password } = req.body;
    if (!userId || !password) {
        return res.render('login', { message: 'Please enter both User ID and Password.' });
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];
        if (!user) {
            return res.render('login', { message: 'Invalid User ID or Password.' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
            req.session.userId = user.id;
            req.session.user = user;
            res.redirect('/dashboard');
        } else {
            res.render('login', { message: 'Invalid User ID or Password.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { message: 'An unexpected error occurred.' });
    }
});

// User Dashboard
app.get('/dashboard', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    try {
        // Fetch the latest user data from the database
        const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
        const user = userResult.rows[0];
        req.session.user = user; // Update the session with the latest data

        const totalUsersResult = await pool.query('SELECT COUNT(*)::int AS totalUsers FROM users');
        const totalUsers = totalUsersResult.rows[0].totalusers;
        const activeUsersResult = await pool.query('SELECT COUNT(*)::int AS activeUsers FROM users WHERE status = $1', ['Active']);
        const activeUsers = activeUsersResult.rows[0].activeusers;
        res.render('dashboard', {
            user: user, // Pass the fresh user object to the template
            message: null,
            prizes: prizes,
            totalUsers: totalUsers,
            activeUsers: activeUsers
        });
    } catch (error) {
        console.error('Error loading dashboard:', error);
        res.render('dashboard', { user: req.session.user, message: 'Error loading dashboard.', prizes: prizes, totalUsers: 0, activeUsers: 0 });
    }
});

// Coupon Request route
app.post('/request-coupon', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'You must be logged in.' });
    }

    try {
        // Send notification to admin
        sendCouponRequestNotification(req.session.user);
        res.json({ message: 'Your request has been sent to the admin. You will see your coupon here once it is generated.' });
    } catch (error) {
        console.error('Coupon request error:', error);
        res.status(500).json({ message: 'An unexpected error occurred.' });
    }
});

// Edit Profile GET route
app.get('/edit-profile', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('edit_profile', { user: req.session.user, message: null });
});

// Edit Profile POST route
app.post('/edit-profile', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    const { name, dob, city, contact, email, newPassword, confirmNewPassword } = req.body;
    const currentUserId = req.session.userId;
    if (!name || !dob || !city || !contact || !email) {
        return res.render('edit_profile', { user: req.session.user, message: 'All fields except new password are required.' });
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.render('edit_profile', { user: req.session.user, message: 'Invalid email format.' });
    }
    if (!/^\d{10}$/.test(contact)) {
        return res.render('edit_profile', { user: req.session.user, message: 'Contact number must be 10 digits.' });
    }
    let hashedPassword = req.session.user.password;
    if (newPassword) {
        if (newPassword.length < 6) {
            return res.render('edit_profile', { user: req.session.user, message: 'New password must be at least 6 characters long.' });
        }
        if (newPassword !== confirmNewPassword) {
            return res.render('edit_profile', { user: req.session.user, message: 'New passwords do not match.' });
        }
        hashedPassword = await bcrypt.hash(newPassword, 10);
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1 AND id != $2', [email, currentUserId]);
        if (result.rows.length > 0) {
            return res.render('edit_profile', { user: req.session.user, message: 'Email already taken by another user.' });
        }
        await pool.query('UPDATE users SET name = $1, dob = $2, city = $3, contact = $4, email = $5, password = $6 WHERE id = $7',
            [name, dob, city, contact, email, hashedPassword, currentUserId]);
        req.session.user = { ...req.session.user, name, dob, city, contact, email, password: hashedPassword };
        res.render('edit_profile', { user: req.session.user, message: 'Profile updated successfully!' });
    } catch (error) {
        console.error('Edit profile error:', error);
        res.render('edit_profile', { user: req.session.user, message: 'An unexpected error occurred.' });
    }
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.redirect('/dashboard');
        }
        res.redirect('/login');
    });
});

// Forgot Password GET route
app.get('/forgot-password', (req, res) => {
    res.render('forgot_password', { message: null });
});

// Forgot Password POST route
app.post('/forgot-password', async (req, res) => {
    const { contact } = req.body;
    if (!contact) {
        return res.render('forgot_password', { message: 'Please enter your contact number.' });
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE contact = $1', [contact]);
        const user = result.rows[0];
        if (!user) {
            return res.render('forgot_password', { message: 'No user found with that contact number.' });
        }
        const newTempPassword = generateRandomAlphanumericString(8);
        const hashedNewPassword = await bcrypt.hash(newTempPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, user.id]);
        res.render('forgot_password_success', { newPassword: newTempPassword });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.render('forgot_password', { message: 'An unexpected error occurred.' });
    }
});

// Spin the wheel route
app.post('/spin', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'You must be logged in to spin.' });
    }

    try {
        const result = await pool.query('SELECT has_spun, spin_prize FROM users WHERE id = $1', [req.session.userId]);
        const user = result.rows[0];

        if (user.has_spun) {
            return res.status(400).json({ message: 'You have already spun the wheel.', prize: user.spin_prize });
        }

        // Weighted prize generation
        const prizes = [
            { prize: 10, weight: 50 },
            { prize: 20, weight: 30 },
            { prize: 50, weight: 19 },
            { prize: 1000, weight: 1 }
        ];

        const totalWeight = prizes.reduce((sum, p) => sum + p.weight, 0);
        let random = Math.random() * totalWeight;
        let selectedPrize = 0;

        for (const prize of prizes) {
            if (random < prize.weight) {
                selectedPrize = prize.prize;
                break;
            }
            random -= prize.weight;
        }

        await pool.query('UPDATE users SET has_spun = true, spin_prize = $1 WHERE id = $2', [selectedPrize, req.session.userId]);
        req.session.user.has_spun = true;
        req.session.user.spin_prize = selectedPrize;

        res.json({ prize: selectedPrize });

    } catch (error) {
        console.error('Spin error:', error);
        res.status(500).json({ message: 'An unexpected error occurred.' });
    }
});

// Admin Login GET route
app.get('/admin/login', (req, res) => {
    res.render('admin_login', { message: null });
});

// Admin Login POST route
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        res.redirect('/admin/dashboard');
    } else {
        res.render('admin_login', { message: 'Invalid Admin Username or Password.' });
    }
});

// Admin Dashboard
app.get('/admin/dashboard', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/admin/login');
    }
    try {
        console.log('Admin is authenticated. Fetching dashboard data...'); // ADD THIS LINE
        const totalUsersResult = await pool.query('SELECT COUNT(*)::int AS totalUsers FROM users');
        const totalUsers = totalUsersResult.rows[0].totalusers;
        const activeUsersResult = await pool.query('SELECT COUNT(*)::int AS activeUsers FROM users WHERE status = $1', ['Active']);
        const activeUsers = activeUsersResult.rows[0].activeusers;
        const usersResult = await pool.query('SELECT * FROM users');
        const users = usersResult.rows;
        console.log('Dashboard data fetched. Rendering page...'); // ADD THIS LINE
        res.render('admin_dashboard', {
            users: users,
            message: null,
            prizes: prizes,
            winners: [],
            totalUsers: totalUsers,
            activeUsers: activeUsers
        });
    } catch (error) {
        console.error('Error loading admin dashboard:', error);
        res.render('admin_dashboard', { users: [], message: 'Error loading users.', prizes: prizes, winners: [], totalUsers: 0, activeUsers: 0 });
    }
});

// Admin Toggle User Status
app.post('/admin/toggle-status/:id', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/admin/login');
    }
    const userId = req.params.id;
    try {
        const result = await pool.query('SELECT status FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];
        const newStatus = user.status === 'Active' ? 'Deactivated' : 'Active';
        await pool.query('UPDATE users SET status = $1 WHERE id = $2', [newStatus, userId]);
        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error updating user status:', error);
        res.redirect('/admin/dashboard');
    }
});

// Admin Delete User
app.post('/admin/delete-user/:id', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/admin/login');
    }
    const userId = req.params.id;
    try {
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.redirect('/admin/dashboard');
    }
});

// Admin Generate Coupon
app.post('/admin/generate-coupon/:id', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/admin/login');
    }
    const userId = req.params.id;
    try {
        const couponCode = 'DREAM' + uuidv4().split('-')[0].toUpperCase();
        await pool.query('UPDATE users SET coupon_code = $1 WHERE id = $2', [couponCode, userId]);
        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error generating coupon:', error);
        res.redirect('/admin/dashboard');
    }
});


// Admin Logout route
app.post('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying admin session:', err);
            return res.redirect('/admin/dashboard');
        }
        res.redirect('/admin/login');
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});