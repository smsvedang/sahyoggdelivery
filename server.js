// --- Sahyog Medical Delivery Backend (server.js) ---

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors()); 
app.use(express.json()); 

// --- 1. MongoDB Connection (Same as before) ---
const MONGO_URI = 'mongodb+srv://vedangsoni:sonivedang@sahyogdelivery.irbiwg9.mongodb.net/sahyogMedicalDB?retryWrites=true&w=majority';
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB से जुड़ गए!'))
    .catch(err => console.error('MongoDB से जुड़ने में गड़बड़ी:', err));

// --- 2. Schema (Same as before) ---
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

// --- 3. /book API (Same as before) ---
app.post('/book', async (req, res) => {
    try {
        const { name, address, phone } = req.body;
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
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
        res.json({
            message: 'कूरियर बुक हो गया!',
            trackingId: trackingId,
            otp: otp
        });

    } catch (error) {
        res.status(500).json({ message: 'कुछ गड़बड़ी हुई', error });
    }
});

// --- 4. /track API (Same as before) ---
app.get('/track/:trackingId', async (req, res) => {
    try {
        const delivery = await Delivery.findOne({ trackingId: req.params.trackingId });

        if (!delivery) {
            return res.status(404).json({ message: 'यह ट्रैकिंग ID नहीं मिला' });
        }
        
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

// --- (STEP 2) 5. NEW API: Get all "Booked" deliveries ---
app.get('/deliveries/booked', async (req, res) => {
    try {
        const deliveries = await Delivery.find({ status: 'Booked' }).sort({ bookedAt: 1 });
        res.json(deliveries);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching deliveries' });
    }
});

// --- (STEP 2) 6. NEW API: Start Delivery (Scan QR) ---
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

// --- (STEP 2) 7. NEW API: Complete Delivery (Verify OTP) ---
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

// --- 8. Start Server (Same as before) ---
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`सर्वर http://localhost:${PORT} पर चल रहा है`);
});