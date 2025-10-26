// --- Sahyog Medical Delivery Backend (server.js) - v3 (QR/Address Fix) ---

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

// --- 4. Schemas (डेटाबेस डिज़ाइन) ---

// 4.1. User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'delivery'], required: true },
    pushSubscription: { type: Object }
});
const User = mongoose.model('User', userSchema);

// 4.2. Delivery Schema (अपडेटेड)
const deliverySchema = new mongoose.Schema({
    customerName: String,
    customerAddress: String, // (यह हमेशा से यहाँ था, बस लेबल से हटा दिया था)
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
    // --- (नया फ़ील्ड) ---
    codPaymentStatus: {
        type: String,
        enum: ['Pending', 'Paid - Cash', 'Paid - Online'],
        default: 'Pending'
    }
}, { timestamps: true });

deliverySchema.virtual('currentStatus').get(function() {
    if (this.statusUpdates.length === 0) return 'Pending';
    return this.statusUpdates[this.statusUpdates.length - 1].status;
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
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid password' });
        const token = jwt.sign({ userId: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '3d' });
        res.json({ message: 'Login successful!', token, name: user.name, role: user.role });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});
// 5.2. Auth Middleware
const auth = (roles = []) => {
    return (req, res, next) => {
        try {
            const token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            if (roles.length > 0 && !roles.includes(decoded.role)) {
                return res.status(403).json({ message: 'Forbidden' });
            }
            next();
        } catch (error) { res.status(401).json({ message: 'Auth failed' }); }
    };
};

// --- 6. HTML Page Routes ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/track', (req, res) => res.sendFile(path.join(__dirname, 'track.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/delivery', (req, res) => res.sendFile(path.join(__dirname, 'delivery.html')));
app.get('/service-worker.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.sendFile(path.join(__dirname, 'service-worker.js'));
});

// --- 7. Admin API Routes ---
// 7.1. Book Courier (अपडेटेड: QR स्ट्रिंग हटा दी गई)
app.post('/book', auth(['admin']), async (req, res) => {
    try {
        const { name, address, phone, paymentMethod, billAmount, assignedTo } = req.body;
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const trackingId = 'SAHYOG-' + Date.now().toString().slice(-6);

        // --- UPI QR कोड स्ट्रिंग यहाँ से हटा दी गई है ---

        const newDelivery = new Delivery({
            customerName: name,
            customerAddress: address, // पता यहाँ सेव हो रहा है
            customerPhone: phone,
            trackingId: trackingId,
            otp: otp,
            paymentMethod: paymentMethod,
            billAmount: billAmount,
            assignedTo: assignedTo || null,
            statusUpdates: [{ status: 'Booked' }],
            codPaymentStatus: (paymentMethod === 'Prepaid') ? 'Paid - Online' : 'Pending'
        });
        await newDelivery.save();
        
        if (assignedTo) {
            const user = await User.findById(assignedTo);
            if (user && user.pushSubscription) {
                const payload = JSON.stringify({ title: 'New Delivery Assigned!', body: `Order ${trackingId} for ${name}` });
                webpush.sendNotification(user.pushSubscription, payload).catch(err => console.error("Push error", err));
            }
        }
        
        // --- रिस्पांस से QR स्ट्रिंग हटा दी गई ---
        res.json({
            message: 'कूरियर बुक हो गया!',
            trackingId: trackingId,
            otp: otp 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'कुछ गड़बड़ी हुई', error });
    }
});
// 7.2. Get All Deliveries
app.get('/admin/deliveries', auth(['admin']), async (req, res) => {
    try {
        const deliveries = await Delivery.find().populate('assignedTo', 'name').sort({ createdAt: -1 });
        res.json(deliveries);
    } catch (error) { res.status(500).json({ message: 'Error fetching deliveries' }); }
});
// 7.3. Get All Delivery Boys
app.get('/admin/delivery-boys', auth(['admin']), async (req, res) => {
    try {
        const users = await User.find({ role: 'delivery' }, 'name email _id');
        res.json(users);
    } catch (error) { res.status(500).json({ message: 'Error fetching users' }); }
});
// 7.4. Create Delivery Boy
app.post('/admin/create-delivery-boy', auth(['admin']), async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields are required' });
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(409).json({ message: 'Email already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email: email.toLowerCase(), password: hashedPassword, role: 'delivery' });
        await newUser.save();
        res.status(201).json({ message: 'Delivery boy created!', user: { name: newUser.name, email: newUser.email } });
    } catch (error) { res.status(500).json({ message: 'Server error', error }); }
});

// --- 8. Delivery Boy API Routes ---
// 8.1. Get Assigned Deliveries
app.get('/delivery/my-deliveries', auth(['delivery']), async (req, res) => {
    try {
        const deliveries = await Delivery.find({
            assignedTo: req.user.userId,
            'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] }
        }).sort({ createdAt: 1 });
        res.json(deliveries);
    } catch (error) { res.status(500).json({ message: 'Error fetching deliveries' }); }
});
// 8.2. Start Delivery (Scan)
app.post('/delivery/start', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });
        if (!delivery) return res.status(404).json({ message: 'Tracking ID not found or not assigned' });
        
        // चेक करें कि यह पहले से 'Out for Delivery' तो नहीं है
        if (delivery.currentStatus === 'Out for Delivery') {
             return res.status(400).json({ message: 'Already Out for Delivery' });
        }
        
        delivery.statusUpdates.push({ status: 'Out for Delivery' });
        await delivery.save();
        res.json({ trackingId: delivery.trackingId, status: 'Out for Delivery' });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});
// 8.3. Complete Delivery (OTP) (अपडेटेड)
app.post('/delivery/complete', auth(['delivery']), async (req, res) => {
    try {
        // --- (नया) पेमेंट मेथड को req.body से लें ---
        const { trackingId, otp, paymentReceivedMethod } = req.body;
        
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });
        if (!delivery) return res.status(404).json({ message: 'Tracking ID not found or not assigned' });
        if (delivery.currentStatus !== 'Out for Delivery') {
            return res.status(400).json({ message: 'Must be Out for Delivery first' });
        }
        if (delivery.otp !== otp) return res.status(400).json({ message: 'Invalid OTP!' });

        // --- (नया) पेमेंट स्टेटस अपडेट करें ---
        if (delivery.paymentMethod === 'COD') {
            if (!paymentReceivedMethod) {
                return res.status(400).json({ message: 'Please select payment (Cash or Online)' });
            }
            delivery.codPaymentStatus = (paymentReceivedMethod === 'cash') ? 'Paid - Cash' : 'Paid - Online';
        }
        
        delivery.statusUpdates.push({ status: 'Delivered' });
        await delivery.save();
        res.json({ trackingId: delivery.trackingId, status: 'Delivered' });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});
// 8.4. Subscribe to Push
app.post('/subscribe', auth(['delivery']), async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.userId, { pushSubscription: req.body });
        res.status(201).json({ message: 'Subscription saved' });
    } catch (error) { res.status(500).json({ message: 'Failed to save' }); }
});

// --- 9. Public API Routes ---
// 9.1. Track (अपडेटेड: पेमेंट की जानकारी भेजने के लिए)
app.get('/track/:trackingId', async (req, res) => {
    try {
        const delivery = await Delivery.findOne({ trackingId: req.params.trackingId });
        if (!delivery) return res.status(404).json({ message: 'यह ट्रैकिंग ID नहीं मिला' });
        
        res.json({
            trackingId: delivery.trackingId,
            customerName: delivery.customerName,
            statusUpdates: delivery.statusUpdates,
            // --- (नया) यह delivery.html को चाहिए ---
            paymentMethod: delivery.paymentMethod,
            billAmount: delivery.billAmount,
            currentStatus: delivery.currentStatus
        });
    } catch (error) { res.status(500).json({ message: 'कुछ गड़बड़ी हुई', error }); }
});
// 9.2. Get VAPID Key
app.get('/vapid-public-key', (req, res) => res.send(VAPID_PUBLIC_KEY));

// --- 10. Start Server ---
const PORT = process.env.PORT || 3000; 
app.listen(PORT, () => console.log(`सर्वर ${PORT} पर चल रहा है`));

// 11. Create Admin User (वन-टाइम)
async function createAdminUser() {
    try {
        const adminEmail = 'sahyogmns';
        const adminPass = 'passsahyogmns';
        let admin = await User.findOne({ email: adminEmail });
        if (!admin) {
            const hashedPassword = await bcrypt.hash(adminPass, 12);
            admin = new User({ name: 'Sahyog Admin', email: adminEmail, password: hashedPassword, role: 'admin' });
            await admin.save();
            console.log('--- ADMIN USER CREATED ---', `User: ${adminEmail}`, `Pass: ${adminPass}`);
        } else { console.log('Admin user already exists.'); }
    } catch (error) { console.error('Error creating admin user:', error); }
}
setTimeout(createAdminUser, 3000);