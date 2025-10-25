// --- Sahyog Medical Delivery Backend (server.js) - MAJOR UPGRADE v2 ---

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs'); // पासवर्ड हैश करने के लिए
const jwt = require('jsonwebtoken'); // लॉगिन टोकन के लिए
const webpush = require('web-push'); // पुश नोटिफ़िकेशन के लिए

const app = express();
app.use(cors());
app.use(express.json());

// --- 1. Environment Variables से सीक्रेट्स लोड करें ---
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;

if (!MONGO_URI || !JWT_SECRET || !VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    console.error('FATAL ERROR: Environment Variables are not set.');
    process.exit(1); // सर्वर को बंद कर दें
}

// --- 2. MongoDB से कनेक्ट करें ---
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB से जुड़ गए!'))
    .catch(err => console.error('MongoDB से जुड़ने में गड़बड़ी:', err));

// --- 3. Web Push को सेटअप करें ---
webpush.setVapidDetails(
  'mailto:sahyogvedang@zohomail.in',
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

// --- 4. नया डेटाबेस डिज़ाइन (Schemas) ---

// 4.1. यूज़र (Admin/Delivery Boy) का Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true }, // यह 'username' की तरह काम करेगा
    password: { type: String, required: true },
    role: { 
        type: String, 
        enum: ['admin', 'delivery'], 
        required: true 
    },
    pushSubscription: { type: Object } // डिलीवरी बॉय के Push Notification के लिए
});

const User = mongoose.model('User', userSchema);

// 4.2. अपडेटेड डिलीवरी का Schema
const deliverySchema = new mongoose.Schema({
    customerName: String,
    customerAddress: String,
    customerPhone: String,
    trackingId: { type: String, unique: true, required: true },
    otp: String,
    paymentMethod: {
        type: String,
        enum: ['COD', 'Prepaid'],
        default: 'Prepaid'
    },
    billAmount: {
        type: Number,
        default: 0
    },
    assignedTo: { // किस डिलीवरी बॉय को असाइन किया
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    statusUpdates: [ // स्टेटस की पूरी हिस्ट्री
        {
            status: String,
            timestamp: { type: Date, default: Date.now }
        }
    ]
}, { timestamps: true }); // 'createdAt' भी सेव होगा

// यह फंक्शन current status को आसानी से पाने में मदद करेगा
deliverySchema.virtual('currentStatus').get(function() {
    if (this.statusUpdates.length === 0) return 'Pending';
    return this.statusUpdates[this.statusUpdates.length - 1].status;
});
deliverySchema.set('toJSON', { virtuals: true }); // ताकि JSON में 'currentStatus' दिखे

const Delivery = mongoose.model('Delivery', deliverySchema);


// --- 5. Authentication (Login/Register) API ---

// 5.1. लॉगिन API (Admin/Delivery Boy)
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() }); // केस-इन्सेंसिटिव
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
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
        res.status(500).json({ message: 'Server error' });
    }
});

// 5.2. (ज़रूरी) Auth Middleware (हर सुरक्षित API के लिए)
const auth = (roles = []) => {
    return (req, res, next) => {
        try {
            const token = req.headers.authorization.split(' ')[1]; // "Bearer TOKEN"
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded; // { userId, role, name }

            if (roles.length > 0 && !roles.includes(decoded.role)) {
                return res.status(403).json({ message: 'Forbidden: Insufficient role' });
            }
            next();
        } catch (error) {
            res.status(401).json({ message: 'Authentication failed: Invalid token' });
        }
    };
};


// --- 6. HTML पेजों को सर्व करना (Render के लिए ज़रूरी) ---

// (index.html, track.html, login.html पब्लिक हैं)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/track', (req, res) => res.sendFile(path.join(__dirname, 'track.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));

// (admin.html, delivery.html भी पब्लिकली सर्व होंगी,
// लेकिन उनके अंदर का JavaScript लॉगिन चेक करेगा)
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/delivery', (req, res) => res.sendFile(path.join(__dirname, 'delivery.html')));
app.get('/service-worker.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.sendFile(path.join(__dirname, 'service-worker.js'));
});

// --- 7. मुख्य API Routes (Admin) ---

// 7.1. एडमिन: कूरियर बुक करने के लिए (सुरक्षित)
app.post('/book', auth(['admin']), async (req, res) => {
    try {
        const { name, address, phone, paymentMethod, billAmount, assignedTo } = req.body;

        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const trackingId = 'SAHYOG-' + Date.now().toString().slice(-6);

        // --- UPI QR कोड स्ट्रिंग बनाएँ (Label पर प्रिंट होगा) ---
        let upiQrString = null;
        if (paymentMethod === 'COD' && billAmount > 0) {
            const upiID = 'mab.037325040420024@axisbank';
            const merchantName = 'Sahyog Medical'.replace(/ /g, '%20');
            upiQrString = `upi://pay?pa=${upiID}&pn=${merchantName}&am=${billAmount}&cu=INR&tn=Order-${trackingId}`;
        }

        const newDelivery = new Delivery({
            customerName: name,
            customerAddress: address,
            customerPhone: phone,
            trackingId: trackingId,
            otp: otp,
            paymentMethod: paymentMethod,
            billAmount: billAmount,
            assignedTo: assignedTo || null,
            statusUpdates: [{ status: 'Booked' }] // पहला स्टेटस
        });

        await newDelivery.save();
        
        // --- पुश नोटिफ़िकेशन भेजें (अगर डिलीवरी बॉय असाइन है) ---
        if (assignedTo) {
            const user = await User.findById(assignedTo);
            if (user && user.pushSubscription) {
                const payload = JSON.stringify({
                    title: 'New Delivery Assigned!',
                    body: `Order ${trackingId} for ${name} is assigned to you.`
                });
                webpush.sendNotification(user.pushSubscription, payload)
                    .catch(err => console.error("Error sending push notification", err));
            }
        }
        
        res.json({
            message: 'कूरियर बुक हो गया!',
            trackingId: trackingId,
            otp: otp,
            upiQrString: upiQrString // QR बनाने के लिए इसे वापस भेजें
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'कुछ गड़बड़ी हुई', error });
    }
});

// 7.2. एडमिन: सभी डिलीवरी देखने के लिए (सुरक्षित)
app.get('/admin/deliveries', auth(['admin']), async (req, res) => {
    try {
        const deliveries = await Delivery.find()
            .populate('assignedTo', 'name') // Delivery boy का नाम भी साथ लाएँ
            .sort({ createdAt: -1 }); // सबसे नई पहले
        res.json(deliveries);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching deliveries' });
    }
});

// 7.3. एडमिन: सभी डिलीवरी बॉय देखने के लिए (सुरक्षित)
app.get('/admin/delivery-boys', auth(['admin']), async (req, res) => {
    try {
        const users = await User.find({ role: 'delivery' }, 'name email _id'); // सिर्फ नाम, ईमेल और ID
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users' });
    }
});

// 7.4. एडमिन: नया डिलीवरी बॉय बनाने के लिए (सुरक्षित)
app.post('/admin/create-delivery-boy', auth(['admin']), async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(409).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            role: 'delivery'
        });
        await newUser.save();
        res.status(201).json({ message: 'Delivery boy created successfully!', user: { name: newUser.name, email: newUser.email } });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});


// --- 8. मुख्य API Routes (Delivery Boy) ---

// 8.1. डिलीवरी बॉय: उसे असाइन की गई डिलीवरी (सुरक्षित)
app.get('/delivery/my-deliveries', auth(['delivery']), async (req, res) => {
    try {
        const deliveries = await Delivery.find({
            assignedTo: req.user.userId,
            'statusUpdates.status': { $nin: ['Delivered', 'Cancelled'] } // जो डिलीवर नहीं हुई हैं
        }).sort({ createdAt: 1 });
        
        res.json(deliveries);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching deliveries' });
    }
});

// 8.2. डिलीवरी बॉय: स्टेटस अपडेट करना (Scan QR)
app.post('/delivery/start', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });

        if (!delivery) {
            return res.status(404).json({ message: 'Tracking ID not found or not assigned to you' });
        }
        
        delivery.statusUpdates.push({ status: 'Out for Delivery' });
        await delivery.save();
        
        res.json({ trackingId: delivery.trackingId, status: 'Out for Delivery' });

    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 8.3. डिलीवरी बॉय: डिलीवरी कंप्लीट करना (Verify OTP)
app.post('/delivery/complete', auth(['delivery']), async (req, res) => {
    try {
        const { trackingId, otp } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId, assignedTo: req.user.userId });

        if (!delivery) {
            return res.status(404).json({ message: 'Tracking ID not found or not assigned to you' });
        }
        
        if (delivery.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP!' });
        }

        delivery.statusUpdates.push({ status: 'Delivered' });
        await delivery.save();
        
        res.json({ trackingId: delivery.trackingId, status: 'Delivered' });

    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 8.4. डिलीवरी बॉय: पुश नोटिफ़िकेशन सब्सक्राइब करना (सुरक्षित)
app.post('/subscribe', auth(['delivery']), async (req, res) => {
    const subscription = req.body;
    try {
        await User.findByIdAndUpdate(req.user.userId, { pushSubscription: subscription });
        res.status(201).json({ message: 'Subscription saved' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to save subscription' });
    }
});

// --- 9. मुख्य API Routes (Public) ---

// 9.1. पब्लिक: कूरियर ट्रैक करने के लिए
app.get('/track/:trackingId', async (req, res) => {
    try {
        const delivery = await Delivery.findOne({ trackingId: req.params.trackingId });

        if (!delivery) {
            return res.status(404).json({ message: 'यह ट्रैकिंग ID नहीं मिला' });
        }
        
        res.json({
            trackingId: delivery.trackingId,
            customerName: delivery.customerName,
            statusUpdates: delivery.statusUpdates // पूरा हिस्ट्री ऐरे
        });

    } catch (error) {
        res.status(500).json({ message: 'कुछ गड़बड़ी हुई', error });
    }
});

// 9.2. VAPID Public Key भेजने के लिए (ताकि delivery.html इसे ले सके)
app.get('/vapid-public-key', (req, res) => {
    res.send(VAPID_PUBLIC_KEY);
});


// --- 10. सर्वर शुरू करें ---
const PORT = process.env.PORT || 3000; 
app.listen(PORT, () => {
    console.log(`सर्वर ${PORT} पर चल रहा है`);
});

// --- ज़रूरी: एडमिन बनाने के लिए एक बार चलने वाला कोड ---
async function createAdminUser() {
    try {
        const adminEmail = 'sahyogmns'; // आपका यूज़रनेम
        const adminPass = 'passsahyogmns'; // आपका पासवर्ड

        let admin = await User.findOne({ email: adminEmail });
        if (!admin) {
            const hashedPassword = await bcrypt.hash(adminPass, 12);
            admin = new User({
                name: 'Sahyog Admin',
                email: adminEmail,
                password: hashedPassword,
                role: 'admin'
            });
            await admin.save();
            console.log('--- ADMIN USER CREATED ---');
            console.log(`Username: ${adminEmail}`);
            console.log(`Password: ${adminPass}`);
            console.log('---------------------------');
        } else {
            console.log('Admin user already exists.');
        }
    } catch (error) {
        console.error('Error creating admin user:', error);
    }
}

// सर्वर शुरू होने के 3 सेकंड बाद यह फंक्शन चलाएँ
setTimeout(createAdminUser, 3000);