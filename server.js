// --- Sahyog Medical Delivery Backend (server.js) - FINAL ---

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path'); // HTML पेजों के लिए ज़रूरी

const app = express();
app.use(cors());
app.use(express.json());

// --- 1. MongoDB से कनेक्ट करें ---
// Render (aur Vercel) के Environment Variable से URI को सुरक्षित रूप से पढ़ें
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    console.error('MongoDB Connection String (MONGO_URI) is not defined in Environment Variables.');
    process.exit(1); // सर्वर को बंद कर दें अगर URI नहीं मिली
}

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB से जुड़ गए!'))
    .catch(err => console.error('MongoDB से जुड़ने में गड़बड़ी:', err));

// --- 2. कूरियर का "Schema" (ढाँचा) बनाएँ ---
const deliverySchema = new mongoose.Schema({
    customerName: String,
    customerAddress: String,
    customerPhone: String,
    trackingId: { type: String, unique: true, required: true },
    otp: String,
    status: {
        type: String,
        default: 'Booked' // (Booked, Out for Delivery, Delivered)
    },
    bookedAt: { type: Date, default: Date.now }
});

const Delivery = mongoose.model('Delivery', deliverySchema);

// --- 3. HTML पेजों को सर्व (Serve) करने के लिए (Render के लिए ज़रूरी) ---

// 3.1 होमपेज (index.html) के लिए
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 3.2 एडमिन (admin.html) के लिए
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// 3.3 ट्रैकिंग (track.html) के लिए
app.get('/track', (req, res) => {
    res.sendFile(path.join(__dirname, 'track.html'));
});

// 3.4 डिलीवरी (delivery.html) के लिए
app.get('/delivery', (req, res) => {
    res.sendFile(path.join(__dirname, 'delivery.html'));
});

// --- 4. API Routes (यहाँ से असली लॉजिक शुरू होता है) ---

// 4.1 कूरियर बुक करने के लिए API
app.post('/book', async (req, res) => {
    try {
        const { name, address, phone } = req.body;

        // 4-डिजिट का OTP बनाएँ
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        
        // यूनिक ट्रैकिंग ID बनाएँ
        const trackingId = 'SAHYOG-' + Date.now().toString().slice(-6);

        const newDelivery = new Delivery({
            customerName: name,
            customerAddress: address,
            customerPhone: phone,
            trackingId: trackingId,
            otp: otp,
            status: 'Booked'
        });

        await newDelivery.save();
        
        console.log('नया कूरियर बुक हुआ:', trackingId);
        // एडमिन को OTP और Tracking ID वापस भेजें
        res.json({
            message: 'कूरियर बुक हो गया!',
            trackingId: trackingId,
            otp: otp
        });

    } catch (error) {
        res.status(500).json({ message: 'कुछ गड़बड़ी हुई', error });
    }
});

// 4.2 कूरियर ट्रैक करने के लिए API
app.get('/track/:trackingId', async (req, res) => {
    try {
        const delivery = await Delivery.findOne({ trackingId: req.params.trackingId });

        if (!delivery) {
            return res.status(404).json({ message: 'यह ट्रैकिंग ID नहीं मिला' });
        }
        
        // कस्टमर को सिर्फ ज़रूरी जानकारी भेजें
        res.json({
            trackingId: delivery.trackingId,
            status: delivery.status,
            customerName: delivery.customerName,
            bookedAt: delivery.bookedAt
        });

    } catch (error) {
        res.status(500).json({ message: 'कुछ गड़बड़ी हुई', error });
    }
});

// 4.3 सभी "Booked" deliveries पाने के लिए API (Delivery Boy के लिए)
app.get('/deliveries/booked', async (req, res) => {
    try {
        const deliveries = await Delivery.find({ status: 'Booked' }).sort({ bookedAt: 1 });
        res.json(deliveries);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching deliveries' });
    }
});

// 4.4 Delivery Start करने के लिए API (Scan QR)
app.post('/delivery/start', async (req, res) => {
    try {
        const { trackingId } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId });

        if (!delivery) {
            return res.status(404).json({ message: 'Tracking ID not found' });
        }

        if (delivery.status !== 'Booked') {
            return res.status(400).json({ message: `Delivery is already ${delivery.status}` });
        }

        delivery.status = 'Out for Delivery';
        await delivery.save();
        
        console.log(`Status Updated: ${trackingId} -> Out for Delivery`);
        res.json({ trackingId: delivery.trackingId, status: delivery.status });

    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// 4.5 Delivery Complete करने के लिए API (Verify OTP)
app.post('/delivery/complete', async (req, res) => {
    try {
        const { trackingId, otp } = req.body;
        const delivery = await Delivery.findOne({ trackingId: trackingId });

        if (!delivery) {
            return res.status(404).json({ message: 'Tracking ID not found' });
        }

        if (delivery.status !== 'Out for Delivery') {
            return res.status(400).json({ message: `Delivery must be 'Out for Delivery' first. Current: ${delivery.status}` });
        }

        if (delivery.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP!' });
        }

        // OTP is correct!
        delivery.status = 'Delivered';
        await delivery.save();
        
        console.log(`Status Updated: ${trackingId} -> Delivered`);
        res.json({ trackingId: delivery.trackingId, status: delivery.status });

    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


// --- 5. सर्वर शुरू करें (Render के लिए अपडेटेड) ---
// Render humein batata hai ki kaun sa PORT use karna hai
// 'process.env.PORT' Render ka port hota hai, aur 3000 humara local fallback
const PORT = process.env.PORT || 3000; 

app.listen(PORT, () => {
    console.log(`सर्वर ${PORT} पर चल रहा है`);
});
