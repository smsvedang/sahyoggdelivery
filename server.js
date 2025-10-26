// --- Sahyog Medical Delivery Backend (server.js) - v5 (Full Admin Features) ---

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const webpush = require('web-push');

const app = express();
app.use(cors());
app.use(express.json());

// --- 1. Environment Variables ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;

if (!MONGO_URI || !JWT_SECRET || !VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    console.error('FATAL ERROR: Environment Variables are not set.');
    process.exit(1);
}

// --- 2. MongoDB Connect ---
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB से जुड़ गए!'))
    .catch(err => console.error('MongoDB से जुड़ने में गड़बड़ी:', err));

// --- 3. Web Push Setup ---
webpush.setVapidDetails('mailto:admin@sahyog.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// --- 4. Schemas (Updated) ---

// 4.1. User Schema (Updated)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Username
    password: { type: String, required: true },
    phone: { type: String }, // New
    role: { type: String, enum: ['admin', 'delivery'], required: true },
    isActive: { type: Boolean, default: true }, // New for Activate/Deactivate
    pushSubscription: { type: Object }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// 4.2. Delivery Schema (No changes needed from v3)
const deliverySchema = new mongoose.Schema({
    customerName: String,
    customerAddress: String,
    customerPhone: String,
    trackingId: { type: String, unique: true, required: true },
    otp: String,
    paymentMethod: { type: String, enum: ['COD', 'Prepaid'], default: 'Prepaid' },
    billAmount: { type: Number, default: 0 },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    statusUpdates: [{
        status: String,
        timestamp: { type: Date, default: Date.now }
    }],
    codPaymentStatus: { // Added in v3
        type: String,
        enum: ['Pending', 'Paid - Cash', 'Paid - Online', 'Not Applicable'], // Added Not Applicable
        default: 'Pending'
    }
}, { timestamps: true });

deliverySchema.virtual('currentStatus').get(function() {
    if (this.statusUpdates.length === 0) return 'Pending';
    // Return last non-cancelled status, or Cancelled if it's the very last
    const lastUpdate = this.statusUpdates[this.statusUpdates.length - 1];
     if (lastUpdate.status === 'Cancelled') return 'Cancelled';

    // Find the latest status that isn't 'Cancelled'
    for (let i = this.statusUpdates.length - 1; i >= 0; i--) {
        if (this.statusUpdates[i].status !== 'Cancelled') {
            return this.statusUpdates[i].status;
        }
    }
    return 'Pending'; // Should not happen if booked
});
deliverySchema.set('toJSON', { virtuals: true });
const Delivery = mongoose.model('Delivery', deliverySchema);


// --- 5. Auth APIs (Updated) ---
// 5.1. Login (Updated: Check isActive)
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() }); // Case-insensitive
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Check if user is active
        if (!user.isActive) {
            return res.status(403).json({ message: 'User account is deactivated' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid password' });
        }
        const token = jwt.sign(
            { userId: user._id, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '3d' }
        );
        res.json({ message: 'Login successful!', token, name: user.name, role: user.role });
    } catch (error) {
        console.error("Login Error:", error); // Log the actual error
        res.status(500).json({ message: 'Server error during login' });
    }
});
// 5.2. Auth Middleware (No changes)
const auth = (roles = []) => { /* ... (same as before) ... */ };


// --- 6. HTML Page Routes (No changes) ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
// ... (rest are same) ...
app.get('/service-worker.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.sendFile(path.join(__dirname, 'service-worker.js'));
});


// --- 7. Admin API Routes (Major Updates) ---

// 7.1. Book Courier (Updated: Set codPaymentStatus correctly)
app.post('/book', auth(['admin']), async (req, res) => {
    try {
        const { name, address, phone, paymentMethod, billAmount, assignedTo } = req.body;
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const trackingId = 'SAHYOG-' + Date.now().toString().slice(-6);

        const newDelivery = new Delivery({
            customerName: name,
            customerAddress: address,
            customerPhone: phone,
            trackingId: trackingId,
            otp: otp,
            paymentMethod: paymentMethod,
            billAmount: billAmount,
            assignedTo: assignedTo || null,
            statusUpdates: [{ status: 'Booked' }],
            // --- (Updated) Set status based on payment method ---
            codPaymentStatus: (paymentMethod === 'Prepaid') ? 'Not Applicable' : 'Pending'
        });
        await newDelivery.save();
        
        if (assignedTo) { /* ... (push notification logic same) ... */ }
        
        res.json({ message: 'कूरियर बुक हो गया!', trackingId: trackingId, otp: otp });
    } catch (error) { /* ... (error handling same) ... */ }
});

// 7.2. Get All Deliveries (Updated: Return more fields)
app.get('/admin/deliveries', auth(['admin']), async (req, res) => {
    try {
        const deliveries = await Delivery.find()
            .populate('assignedTo', 'name email isActive') // Get more user details
            .sort({ createdAt: -1 });
        res.json(deliveries);
    } catch (error) { res.status(500).json({ message: 'Error fetching deliveries' }); }
});

// 7.3. Get All Users (Admin + Delivery Boys) (New)
app.get('/admin/users', auth(['admin']), async (req, res) => {
    try {
        const users = await User.find({}, '-password').sort({ role: 1, name: 1 }); // Exclude password
        res.json(users);
    } catch (error) { res.status(500).json({ message: 'Error fetching users' }); }
});

// 7.4. Create User (Admin/Delivery Boy) (Updated)
app.post('/admin/create-user', auth(['admin']), async (req, res) => {
    try {
        const { name, email, password, phone, role } = req.body; // Added phone, role
        if (!name || !email || !password || !role) return res.status(400).json({ message: 'Name, Email, Password, Role required' });
        if (!['admin', 'delivery'].includes(role)) return res.status(400).json({ message: 'Invalid role' });

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(409).json({ message: 'Email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email: email.toLowerCase(), password: hashedPassword, phone, role });
        await newUser.save();
        res.status(201).json({ message: `${role} user created!`, user: { name: newUser.name, email: newUser.email, role: newUser.role } });
    } catch (error) { res.status(500).json({ message: 'Server error', error }); }
});

// 7.5. Update User Details (New)
app.put('/admin/user/:userId', auth(['admin']), async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, phone, role } = req.body; // Password updated separately
        if (!name || !email || !role) return res.status(400).json({ message: 'Name, Email, Role required' });

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        // Prevent changing own role if only one admin left (optional safeguard)
        // if (user.role === 'admin' && req.user.userId === userId && role !== 'admin') {
        //     const adminCount = await User.countDocuments({ role: 'admin', isActive: true });
        //     if (adminCount <= 1) return res.status(400).json({ message: 'Cannot change role of the last active admin.' });
        // }

        user.name = name;
        user.email = email.toLowerCase();
        user.phone = phone;
        user.role = role;
        await user.save();
        res.json({ message: 'User updated successfully' });
    } catch (error) { res.status(500).json({ message: 'Server error', error }); }
});

// 7.6. Update User Password (New)
app.patch('/admin/user/:userId/password', auth(['admin']), async (req, res) => {
     try {
        const { userId } = req.params;
        const { password } = req.body;
        if (!password) return res.status(400).json({ message: 'New password required' });

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(userId, { password: hashedPassword });
        res.json({ message: 'Password updated successfully' });
    } catch (error) { res.status(500).json({ message: 'Server error', error }); }
});

// 7.7. Toggle User Active Status (New)
app.patch('/admin/user/:userId/toggle-active', auth(['admin']), async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found' });

        // Prevent deactivating self if only one admin left (optional safeguard)
        // if (user.role === 'admin' && req.user.userId === userId && user.isActive) {
        //     const adminCount = await User.countDocuments({ role: 'admin', isActive: true });
        //     if (adminCount <= 1) return res.status(400).json({ message: 'Cannot deactivate the last active admin.' });
        // }

        user.isActive = !user.isActive;
        await user.save();
        res.json({ message: `User ${user.isActive ? 'activated' : 'deactivated'}` });
    } catch (error) { res.status(500).json({ message: 'Server error', error }); }
});


// 7.8. Cancel Delivery (New)
app.patch('/admin/delivery/:deliveryId/cancel', auth(['admin']), async (req, res) => {
    try {
        const { deliveryId } = req.params;
        const delivery = await Delivery.findById(deliveryId);
        if (!delivery) return res.status(404).json({ message: 'Delivery not found' });

        // Add 'Cancelled' status only if not already delivered or cancelled
        if (!['Delivered', 'Cancelled'].includes(delivery.currentStatus)) {
            delivery.statusUpdates.push({ status: 'Cancelled' });
            delivery.codPaymentStatus = 'Not Applicable'; // Or keep as is? Decide.
            await delivery.save();
            res.json({ message: 'Delivery cancelled' });
        } else {
            res.status(400).json({ message: 'Delivery already completed or cancelled' });
        }
    } catch (error) { res.status(500).json({ message: 'Server error', error }); }
});

// 7.9. Delete Delivery (New)
app.delete('/admin/delivery/:deliveryId', auth(['admin']), async (req, res) => {
    try {
        const { deliveryId } = req.params;
        const result = await Delivery.findByIdAndDelete(deliveryId);
        if (!result) return res.status(404).json({ message: 'Delivery not found' });
        res.json({ message: 'Delivery deleted successfully' });
    } catch (error) { res.status(500).json({ message: 'Server error', error }); }
});


// --- 8. Delivery Boy API Routes (Updated) ---

// 8.1. Get Assigned Deliveries (No change)
app.get('/delivery/my-deliveries', auth(['delivery']), async (req, res) => { /* ... (same as before) ... */ });

// 8.2. Update Status (Scan QR -> Picked Up / Out for Delivery) (Updated)
app.post('/delivery/update-status', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });
        if (!delivery) return res.status(404).json({ message: 'Tracking ID not found or not assigned' });

        let nextStatus;
        switch (delivery.currentStatus) {
            case 'Booked':
                nextStatus = 'Picked Up';
                break;
            case 'Picked Up':
                 nextStatus = 'Out for Delivery';
                 break;
            default:
                // If already Out for Delivery or later, do nothing or return message
                 return res.status(400).json({ message: `Delivery is already ${delivery.currentStatus}` });
        }
        
        delivery.statusUpdates.push({ status: nextStatus });
        await delivery.save();
        res.json({ trackingId: delivery.trackingId, status: nextStatus });

    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// 8.3. Complete Delivery (OTP) (Updated: Check 'Out for Delivery' status)
app.post('/delivery/complete', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId, otp, paymentReceivedMethod } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });

        if (!delivery) return res.status(404).json({ message: 'Tracking ID not found or not assigned' });
        // --- (Updated) Must be 'Out for Delivery' to complete ---
        if (delivery.currentStatus !== 'Out for Delivery') {
            return res.status(400).json({ message: `Cannot complete. Status is ${delivery.currentStatus}. Scan again if needed.` });
        }
        // ----------------------------------------------------
        if (delivery.otp !== otp) return res.status(400).json({ message: 'Invalid OTP!' });

        if (delivery.paymentMethod === 'COD') {
            if (!paymentReceivedMethod) return res.status(400).json({ message: 'Please select payment (Cash or Online)' });
            delivery.codPaymentStatus = (paymentReceivedMethod === 'cash') ? 'Paid - Cash' : 'Paid - Online';
        } else {
             delivery.codPaymentStatus = 'Not Applicable';
        }
        
        delivery.statusUpdates.push({ status: 'Delivered' });
        await delivery.save();
        res.json({ trackingId: delivery.trackingId, status: 'Delivered' });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// 8.4. Subscribe to Push (No change)
app.post('/subscribe', auth(['delivery']), async (req, res) => { /* ... (same as before) ... */ });

// --- 9. Public API Routes (No changes) ---
app.get('/track/:trackingId', async (req, res) => { /* ... (same as before) ... */ });
app.get('/vapid-public-key', (req, res) => res.send(VAPID_PUBLIC_KEY));

// --- 10. Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`सर्वर ${PORT} पर चल रहा है`));

// --- 11. Create Admin User (one-time) ---
async function createAdminUser() { /* ... (same as before) ... */ }
setTimeout(createAdminUser, 3000);