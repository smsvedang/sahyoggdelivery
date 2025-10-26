// --- Sahyog Medical Delivery Backend (server.js) - v6.1 (Admin->Manager Workflow) ---

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

// --- 4. Schemas ---

// 4.1. User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // Username
    password: { type: String, required: true },
    phone: { type: String },
    role: { type: String, enum: ['admin', 'manager', 'delivery'], required: true },
    isActive: { type: Boolean, default: true },
    pushSubscription: { type: Object },
    createdByManager: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// 4.2. Delivery Schema
const deliverySchema = new mongoose.Schema({
    customerName: String,
    customerAddress: String,
    customerPhone: String,
    trackingId: { type: String, unique: true, required: true },
    otp: String,
    paymentMethod: { type: String, enum: ['COD', 'Prepaid'], default: 'Prepaid' },
    billAmount: { type: Number, default: 0 },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Delivery Boy ID
    assignedByManager: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Manager ID
    assignedBoyDetails: { name: String, phone: String },
    statusUpdates: [{ status: String, timestamp: { type: Date, default: Date.now } }],
    codPaymentStatus: { type: String, enum: ['Pending', 'Paid - Cash', 'Paid - Online', 'Not Applicable'], default: 'Pending' }
}, { timestamps: true });

deliverySchema.virtual('currentStatus').get(function() {
    if (this.statusUpdates.length === 0) return 'Pending';
    const lastUpdate = this.statusUpdates[this.statusUpdates.length - 1];
     if (lastUpdate.status === 'Cancelled') return 'Cancelled';
    for (let i = this.statusUpdates.length - 1; i >= 0; i--) {
        if (this.statusUpdates[i].status !== 'Cancelled') {
            return this.statusUpdates[i].status;
        }
    }
    return 'Pending';
});
deliverySchema.set('toJSON', { virtuals: true });
const Delivery = mongoose.model('Delivery', deliverySchema);

// --- 5. Auth APIs ---

// 5.1. Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (!user.isActive) return res.status(403).json({ message: 'User account is deactivated' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid password' });
        const token = jwt.sign({ userId: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '3d' });
        res.json({ message: 'Login successful!', token, name: user.name, role: user.role });
    } catch (error) {
         console.error("Login Error:", error);
         res.status(500).json({ message: 'Server error during login' });
    }
});

// 5.2. Auth Middleware
const auth = (roles = []) => {
    return (req, res, next) => {
        try {
            const token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            if (roles.length > 0 && !roles.includes(decoded.role)) {
                return res.status(403).json({ message: 'Forbidden: Insufficient role' });
            }
            next();
        } catch (error) {
            res.status(401).json({ message: 'Authentication failed: Invalid token' });
        }
    };
};

// --- 6. HTML Page Routes ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/track', (req, res) => res.sendFile(path.join(__dirname, 'track.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/delivery', (req, res) => res.sendFile(path.join(__dirname, 'delivery.html')));
app.get('/manager', (req, res) => res.sendFile(path.join(__dirname, 'manager.html')));
app.get('/service-worker.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.sendFile(path.join(__dirname, 'service-worker.js'));
});

// --- 7. Admin API Routes ---

// 7.1. Book Courier (Assigns to Manager)
app.post('/book', auth(['admin']), async (req, res) => {
    try {
        const { name, address, phone, paymentMethod, billAmount, managerId } = req.body; // Expect managerId
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const trackingId = 'SAHYOG-' + Date.now().toString().slice(-6);

        const newDelivery = new Delivery({
            customerName: name, customerAddress: address, customerPhone: phone,
            trackingId: trackingId, otp: otp,
            paymentMethod: paymentMethod, billAmount: billAmount,
            assignedTo: null, // Boy not assigned yet
            assignedByManager: managerId || null, // Store the manager it's assigned to
            assignedBoyDetails: null,
            statusUpdates: [{ status: 'Booked' }],
            codPaymentStatus: (paymentMethod === 'Prepaid') ? 'Not Applicable' : 'Pending'
        });
        await newDelivery.save();
        res.json({ message: 'कूरियर बुक हो गया!', trackingId: trackingId, otp: otp });
    } catch (error) {
         console.error("Booking Error:", error);
         res.status(500).json({ message: 'Booking failed', error: error.message });
    }
});

// 7.2. Get All Deliveries
app.get('/admin/deliveries', auth(['admin']), async (req, res) => {
    try {
        const deliveries = await Delivery.find()
            .populate('assignedByManager', 'name') // Populate Manager Name
            .populate('assignedTo', 'name email isActive') // Populate Boy Name
            .sort({ createdAt: -1 });
        res.json(deliveries);
    } catch (error) {
         console.error("Fetch Deliveries Error:", error);
         res.status(500).json({ message: 'Error fetching deliveries' });
    }
});

// 7.3. Get All Users
app.get('/admin/users', auth(['admin']), async (req, res) => {
    try {
        const users = await User.find({}, '-password')
                          .populate('createdByManager', 'name')
                          .sort({ role: 1, name: 1 });
        res.json(users);
    } catch (error) {
        console.error("Fetch Users Error:", error);
        res.status(500).json({ message: 'Error fetching users' });
    }
});

// 7.4. Create User
app.post('/admin/create-user', auth(['admin']), async (req, res) => {
    try {
        const { name, email, password, phone, role } = req.body;
        if (!name || !email || !password || !role) return res.status(400).json({ message: 'Name, Email, Password, Role required' });
        if (!['admin', 'manager', 'delivery'].includes(role)) return res.status(400).json({ message: 'Invalid role' });
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(409).json({ message: 'Email already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email: email.toLowerCase(), password: hashedPassword, phone, role, createdByManager: null });
        await newUser.save();
        res.status(201).json({ message: `${role} user created!`, user: { _id: newUser._id, name: newUser.name, email: newUser.email, role: newUser.role } });
    } catch (error) {
         console.error("Create User Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 7.5. Update User Details
app.put('/admin/user/:userId', auth(['admin']), async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, phone, role } = req.body;
        if (!name || !email || !role) return res.status(400).json({ message: 'Name, Email, Role required' });
        if (!['admin', 'manager', 'delivery'].includes(role)) return res.status(400).json({ message: 'Invalid role' });
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found' });
        user.name = name; user.email = email.toLowerCase(); user.phone = phone; user.role = role;
        await user.save();
        res.json({ message: 'User updated successfully' });
    } catch (error) {
         console.error("Update User Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 7.6. Update User Password
app.patch('/admin/user/:userId/password', auth(['admin']), async (req, res) => {
     try {
        const { userId } = req.params;
        const { password } = req.body;
        if (!password || password.length < 6) return res.status(400).json({ message: 'New password required (min 6 chars)' });
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(userId, { password: hashedPassword });
        res.json({ message: 'Password updated successfully' });
    } catch (error) {
         console.error("Update Password Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 7.7. Toggle User Active Status
app.patch('/admin/user/:userId/toggle-active', auth(['admin']), async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found' });
        user.isActive = !user.isActive;
        await user.save();
        res.json({ message: `User ${user.isActive ? 'activated' : 'deactivated'}` });
    } catch (error) {
         console.error("Toggle Active Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 7.8. Cancel Delivery
app.patch('/admin/delivery/:deliveryId/cancel', auth(['admin']), async (req, res) => {
    try {
        const { deliveryId } = req.params;
        const delivery = await Delivery.findById(deliveryId);
        if (!delivery) return res.status(404).json({ message: 'Delivery not found' });
        if (!['Delivered', 'Cancelled'].includes(delivery.currentStatus)) {
            delivery.statusUpdates.push({ status: 'Cancelled' });
            delivery.codPaymentStatus = 'Not Applicable';
            await delivery.save();
            res.json({ message: 'Delivery cancelled' });
        } else {
            res.status(400).json({ message: 'Delivery already completed or cancelled' });
        }
    } catch (error) {
         console.error("Cancel Delivery Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 7.9. Delete Delivery
app.delete('/admin/delivery/:deliveryId', auth(['admin']), async (req, res) => {
    try {
        const { deliveryId } = req.params;
        const result = await Delivery.findByIdAndDelete(deliveryId);
        if (!result) return res.status(404).json({ message: 'Delivery not found' });
        res.json({ message: 'Delivery deleted successfully' });
    } catch (error) {
         console.error("Delete Delivery Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// --- 8. Manager API Routes ---

// 8.1. Manager: Get Pickups assigned TO THIS MANAGER
app.get('/manager/assigned-pickups', auth(['manager']), async (req, res) => {
    try {
        const deliveries = await Delivery.find({
            assignedByManager: req.user.userId, // Assigned to this manager by Admin
            assignedTo: null,                   // Not yet assigned to a boy
            'statusUpdates.status': 'Booked'    // Only if still 'Booked'
        }).sort({ createdAt: 1 });
        res.json(deliveries);
    } catch (error) {
         console.error("Fetch Assigned Pickups Error:", error);
         res.status(500).json({ message: 'Error fetching assigned pickups' });
    }
});

// 8.2. Manager: Get Delivery Boys created by this Manager
app.get('/manager/my-boys', auth(['manager']), async (req, res) => {
    try {
        const users = await User.find({ role: 'delivery', createdByManager: req.user.userId }, 'name email _id isActive phone');
        res.json(users);
    } catch (error) {
         console.error("Fetch My Boys Error:", error);
         res.status(500).json({ message: 'Error fetching delivery boys' });
    }
});

// 8.3. Manager: Create Delivery Boy linked to this Manager
app.post('/manager/create-delivery-boy', auth(['manager']), async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'Name, Email, Password required' });
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(409).json({ message: 'Email already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email: email.toLowerCase(), password: hashedPassword, phone, role: 'delivery', createdByManager: req.user.userId });
        await newUser.save();
        res.status(201).json({ message: 'Delivery boy created!', user: { _id: newUser._id, name: newUser.name, email: newUser.email } });
    } catch (error) {
         console.error("Manager Create Boy Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 8.4. Manager: Assign Delivery to one of their Boys
app.patch('/manager/assign-delivery/:deliveryId', auth(['manager']), async (req, res) => {
    try {
        const { deliveryId } = req.params;
        const { assignedBoyId } = req.body;
        if (!assignedBoyId) return res.status(400).json({ message: 'Delivery Boy ID is required' });

        const delivery = await Delivery.findById(deliveryId);
        if (!delivery) return res.status(404).json({ message: 'Delivery not found' });
        // Ensure it was assigned to this manager and not yet assigned to a boy
        if (!delivery.assignedByManager || delivery.assignedByManager.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'Delivery not assigned to you' });
        }
        if (delivery.assignedTo) return res.status(400).json({ message: 'Delivery already assigned to a boy' });

        const boy = await User.findOne({ _id: assignedBoyId, role: 'delivery', createdByManager: req.user.userId });
        if (!boy) return res.status(404).json({ message: 'Delivery boy not found or does not belong to you' });
        if (!boy.isActive) return res.status(400).json({ message: 'Cannot assign to inactive delivery boy' });

        delivery.assignedTo = boy._id;
        // assignedByManager remains the same
        delivery.assignedBoyDetails = { name: boy.name, phone: boy.phone };
        delivery.statusUpdates.push({ status: 'Boy Assigned' });
        await delivery.save();

        if (boy.pushSubscription) {
            const payload = JSON.stringify({ title: 'New Delivery Assigned!', body: `Order ${delivery.trackingId} for ${delivery.customerName}` });
            webpush.sendNotification(boy.pushSubscription, payload).catch(err => console.error("Push error during assignment:", err));
        }

        res.json({ message: 'Delivery assigned successfully', delivery });
    } catch (error) {
         console.error("Assign Delivery Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// --- 9. Delivery Boy API Routes ---

// 9.1. Get Assigned Deliveries (Pagination)
app.get('/delivery/my-deliveries', auth(['delivery']), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 5;
        const skip = (page - 1) * limit;
        const deliveries = await Delivery.find({ assignedTo: req.user.userId, 'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] } })
            .sort({ createdAt: 1 }).skip(skip).limit(limit);
        const totalDeliveries = await Delivery.countDocuments({ assignedTo: req.user.userId, 'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] } });
        res.json({ deliveries, currentPage: page, totalPages: Math.ceil(totalDeliveries / limit), totalDeliveries });
    } catch (error) {
         console.error("Fetch Assigned Error:", error);
         res.status(500).json({ message: 'Error fetching assigned deliveries' });
    }
});

// 9.2. Update Status (Scan/Manual)
app.post('/delivery/update-status', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });
        if (!delivery) return res.status(404).json({ message: 'Tracking ID not found or not assigned' });
        let nextStatus;
        switch (delivery.currentStatus) {
            case 'Boy Assigned': nextStatus = 'Picked Up'; break;
            case 'Booked': nextStatus = 'Picked Up'; break; // Allow pickup even if manager missed assigning step
            case 'Picked Up': nextStatus = 'Out for Delivery'; break;
            default: return res.status(400).json({ message: `Delivery is already ${delivery.currentStatus}` });
        }
        delivery.statusUpdates.push({ status: nextStatus });
        await delivery.save();
        res.json({ trackingId: delivery.trackingId, status: nextStatus });
    } catch (error) {
         console.error("Update Status Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 9.3. Complete Delivery (OTP)
app.post('/delivery/complete', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId, otp, paymentReceivedMethod } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });
        if (!delivery) return res.status(404).json({ message: 'Tracking ID not found or not assigned' });
        if (delivery.currentStatus !== 'Out for Delivery') return res.status(400).json({ message: `Cannot complete. Status is ${delivery.currentStatus}.` });
        if (delivery.otp !== otp) return res.status(400).json({ message: 'Invalid OTP!' });
        if (delivery.paymentMethod === 'COD') {
            if (!paymentReceivedMethod) return res.status(400).json({ message: 'Please select payment (Cash or Online)' });
            delivery.codPaymentStatus = (paymentReceivedMethod === 'cash') ? 'Paid - Cash' : 'Paid - Online';
        } else { delivery.codPaymentStatus = 'Not Applicable'; }
        delivery.statusUpdates.push({ status: 'Delivered' });
        await delivery.save();
        res.json({ trackingId: delivery.trackingId, status: 'Delivered' });
    } catch (error) {
         console.error("Complete Delivery Error:", error);
         res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 9.4. Subscribe to Push
app.post('/subscribe', auth(['delivery']), async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.userId, { pushSubscription: req.body });
        res.status(201).json({ message: 'Subscription saved' });
    } catch (error) {
         console.error("Subscribe Error:", error);
         res.status(500).json({ message: 'Failed to save subscription' });
    }
});

// --- 10. Public API Routes ---

// 10.1. Track
app.get('/track/:trackingId', async (req, res) => {
    try {
        const delivery = await Delivery.findOne({ trackingId: req.params.trackingId })
                                       .populate('assignedTo', 'name phone'); // Try populating boy
        if (!delivery) return res.status(404).json({ message: 'यह ट्रैकिंग ID नहीं मिला' });
        let boyDetails = delivery.assignedBoyDetails; // Use stored details by default
        if (delivery.assignedTo && delivery.assignedTo.name) { // Overwrite if population worked
             boyDetails = { name: delivery.assignedTo.name, phone: delivery.assignedTo.phone };
        }
        res.json({
            trackingId: delivery.trackingId, customerName: delivery.customerName, statusUpdates: delivery.statusUpdates,
            paymentMethod: delivery.paymentMethod, billAmount: delivery.billAmount, currentStatus: delivery.currentStatus,
            assignedBoyDetails: boyDetails
        });
    } catch (error) {
         console.error("Track Error:", error);
         res.status(500).json({ message: 'Tracking lookup failed' });
    }
});
// 10.2. Get VAPID Key
app.get('/vapid-public-key', (req, res) => res.send(VAPID_PUBLIC_KEY));

// --- 11. Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`सर्वर ${PORT} पर चल रहा है`));

// --- 12. Create Admin User (one-time) ---
async function createAdminUser() {
    try {
        const adminEmail = 'sahyogmns';
        const adminPass = 'passsahyogmns';
        let admin = await User.findOne({ email: adminEmail });
        if (!admin) {
            const hashedPassword = await bcrypt.hash(adminPass, 12);
            admin = new User({ name: 'Sahyog Admin', email: adminEmail, password: hashedPassword, role: 'admin', isActive: true });
            await admin.save();
            console.log('--- ADMIN USER CREATED ---');
            console.log(`Username: ${adminEmail}`);
            console.log(`Password: ${adminPass}`);
            console.log('---------------------------');
        } else {
            if (!admin.isActive) { admin.isActive = true; await admin.save(); console.log(`Admin user ${adminEmail} reactivated.`); }
            else { console.log('Admin user already exists and is active.'); }
        }
    } catch (error) { console.error('Error during initial admin user setup:', error); }
}
setTimeout(createAdminUser, 5000); // Increased delay