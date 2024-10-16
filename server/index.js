const express = require('express');
const { MongoClient } = require('mongodb');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jsdom = require('jsdom');
const { JSDOM } = jsdom;
const DOMPurify = require('dompurify');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Konfigurasi CORS untuk Vercel
const corsOptions = {
    origin: [
        'https://your-frontend-domain.vercel.app', // Ganti dengan domain frontend Vercel Anda
        'http://localhost:3000', // Untuk development
        'http://localhost:5000'
    ],
    methods: ['GET', 'POST'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// Rate limiting middleware
const postLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Terlalu banyak permintaan POST dari IP ini, coba lagi nanti."
});

const getLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: "Terlalu banyak permintaan GET dari IP ini, coba lagi nanti."
});

// MongoDB connection
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to MongoDB Atlas');
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    }
}

// Error handling untuk koneksi MongoDB
process.on('SIGINT', async () => {
    try {
        await client.close();
        console.log('MongoDB connection closed.');
        process.exit(0);
    } catch (err) {
        console.error('Error closing MongoDB connection:', err);
        process.exit(1);
    }
});

// Routes
app.post('/api/feedback', postLimiter, async (req, res) => {
    try {
        const { type, feedback } = req.body;

        const window = (new JSDOM('')).window;
        const purify = DOMPurify(window);
        const cleanFeedback = purify.sanitize(feedback);

        const collection = client.db('feedbackDB').collection('feedbacks');
        const result = await collection.insertOne({
            type,
            feedback: cleanFeedback,
            createdAt: new Date()
        });

        res.status(201).json({
            success: true,
            message: 'Feedback saved successfully',
            id: result.insertedId
        });
    } catch (error) {
        console.error('Error saving feedback:', error);
        res.status(500).json({
            success: false,
            message: 'Error saving feedback',
            error: error.message
        });
    }
});

app.get('/api/feedback', getLimiter, async (req, res) => {
    try {
        const collection = client.db('feedbackDB').collection('feedbacks');
        const feedbacks = await collection.find()
            .sort({ createdAt: -1 })
            .limit(20)
            .toArray();

        res.json({
            success: true,
            data: feedbacks
        });
    } catch (error) {
        console.error('Error retrieving feedback:', error);
        res.status(500).json({
            success: false,
            message: 'Error retrieving feedback',
            error: error.message
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date() });
});

// Connect to MongoDB when server starts
connectToDatabase().then(() => {
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
}).catch((error) => {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
});

module.exports = app;