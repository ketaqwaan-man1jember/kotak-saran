const express = require('express');
const { MongoClient } = require('mongodb');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jsdom = require('jsdom');
const { JSDOM } = jsdom;
const DOMPurify = require('dompurify');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Security Configuration
const SECURITY_CONFIG = {
    rateLimits: {
        post: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 5
        },
        get: {
            windowMs: 5 * 60 * 1000, // 5 minutes
            max: 10
        }
    },
    cors: {
        whitelist: [
            'https://kotaksaran-ketaqwaanman1jember.vercel.app',
            'http://localhost:3000'
        ]
    },
    mongodb: {
        maxPoolSize: 50,
        wtimeoutMS: 2500,
        maxIdleTimeMS: 10000
    }
};

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", ...SECURITY_CONFIG.cors.whitelist]
        }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Enhanced CORS configuration
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || SECURITY_CONFIG.cors.whitelist.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST'],
    credentials: true,
    optionsSuccessStatus: 200,
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Range', 'X-Content-Range']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(xss()); // Prevent XSS attacks
app.use(hpp()); // Prevent HTTP Parameter Pollution

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || uuidv4(),
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 // 1 hour
    }
}));

// Enhanced Rate Limiters
const createRateLimiter = (config) => rateLimit({
    windowMs: config.windowMs,
    max: config.max,
    message: { 
        status: 'error',
        message: 'Too many requests, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

const postLimiter = createRateLimiter(SECURITY_CONFIG.rateLimits.post);
const getLimiter = createRateLimiter(SECURITY_CONFIG.rateLimits.get);

// MongoDB connection with enhanced security
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
    maxPoolSize: SECURITY_CONFIG.mongodb.maxPoolSize,
    wtimeoutMS: SECURITY_CONFIG.mongodb.wtimeoutMS,
    maxIdleTimeMS: SECURITY_CONFIG.mongodb.maxIdleTimeMS,
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    ssl: true,
    sslValidate: true
});

// Input validation middleware
const validateFeedbackInput = (req, res, next) => {
    const { type, feedback } = req.body;
    
    if (!type || !feedback) {
        return res.status(400).json({
            success: false,
            message: 'Type and feedback are required'
        });
    }

    const validTypes = ['kritik', 'saran', 'apresiasi'];
    if (!validTypes.includes(type)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid feedback type'
        });
    }

    if (typeof feedback !== 'string' || 
        feedback.length < 5 || 
        feedback.length > 500) {
        return res.status(400).json({
            success: false,
            message: 'Feedback must be between 5 and 500 characters'
        });
    }

    next();
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
    console.error(err.stack);
    
    if (err.name === 'MongoError') {
        return res.status(503).json({
            success: false,
            message: 'Database error occurred'
        });
    }

    res.status(err.status || 500).json({
        success: false,
        message: process.env.NODE_ENV === 'production' 
            ? 'Internal server error' 
            : err.message
    });
};

// Enhanced routes with security
app.post('/api/feedback', postLimiter, validateFeedbackInput, async (req, res, next) => {
    try {
        const { type, feedback } = req.body;

        // Enhanced sanitization
        const window = (new JSDOM('', {
            features: {
                FetchExternalResources: false,
                ProcessExternalResources: false
            }
        })).window;
        
        const purify = DOMPurify(window);
        const cleanFeedback = purify.sanitize(feedback, {
            ALLOWED_TAGS: [], // No HTML tags allowed
            ALLOWED_ATTR: [] // No attributes allowed
        });

        const collection = client.db('feedbackDB').collection('feedbacks');
        const result = await collection.insertOne({
            type,
            feedback: cleanFeedback,
            createdAt: new Date(),
            ip: req.ip, // Store IP for monitoring
            userAgent: req.get('user-agent')
        });

        res.status(201).json({
            success: true,
            message: 'Feedback saved successfully',
            id: result.insertedId
        });
    } catch (error) {
        next(error);
    }
});

app.get('/api/feedback', getLimiter, async (req, res, next) => {
    try {
        const collection = client.db('feedbackDB').collection('feedbacks');
        const feedbacks = await collection.find(
            {}, 
            { 
                projection: { 
                    ip: 0, 
                    userAgent: 0 
                } 
            }
        )
        .sort({ createdAt: -1 })
        .limit(10)
        .toArray();

        res.json({
            success: true,
            data: feedbacks
        });
    } catch (error) {
        next(error);
    }
});

// Enhanced health check
app.get('/api/health', async (req, res) => {
    try {
        await client.db('admin').command({ ping: 1 });
        res.json({ 
            status: 'OK', 
            timestamp: new Date(),
            environment: process.env.NODE_ENV
        });
    } catch (error) {
        res.status(503).json({ 
            status: 'ERROR',
            message: 'Database connection failed'
        });
    }
});

app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    await client.close();
    process.exit(0);
});

// Connect and start server
const startServer = async () => {
    try {
        await client.connect();
        console.log('Connected to MongoDB Atlas');
        
        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } catch (error) {
        console.error('Failed to connect to MongoDB:', error);
        process.exit(1);
    }
};

startServer();

module.exports = app;