require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
const Joi = require('joi');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const path = require('path');

const saltRounds = 12;
const app = express();
const port = process.env.PORT || 3000;
const expireSession = 60 * 60 * 1000; // 1 hour

const requireEnvVars = [
    'MONGODB_USER',
    'MONGODB_PASSWORD',
    'MONGODB_HOST',
    'MONGODB_DATABASE',
    'MONGODB_SESSION_SECRET',
    'NODE_SESSION_SECRET'
];

requireEnvVars.forEach(varName => {
    if (!process.env[varName]) {
        console.error(`Environment variable ${varName} is not set.`);
        process.exit(1);
    }
});

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const mongoUri = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`;

const client = new MongoClient(mongoUri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

let db, userCollection;

async function connectToDBAndStartServer() {
    try {
        await client.connect();
        db = client.db(mongodb_database);
        userCollection = db.collection('users');
        console.log('Connected to MongoDB');

        // Middleware
        const mongoStore = MongoStore.create({
            mongoUrl: mongoUri,
            crypto: {
                secret: mongodb_session_secret
            }
        });

        app.use(session({
            secret: node_session_secret,
            store: mongoStore,
            resave: false,
            saveUninitialized: false,
            cookie: { maxAge: expireSession }
        }));

        app.use(express.urlencoded({ extended: false }));
        app.use(express.static(path.join(__dirname, 'public')));

        app.use((req, res, next) => {
            res.locals.isAuthenticated = req.session.isAuthenticated;
            res.locals.currentUser = req.session.user;
            next();
        });

        const requireAuth = (req, res, next) => {
            if (!req.session.isAuthenticated) {
                return res.redirect('/login?error=' + encodeURIComponent('Log in to view this page.'));
            }
            next();
        };

        const requireNoAuth = (req, res, next) => {
            if (req.session.isAuthenticated) {
                console.log('User already authenticated.');
                return res.redirect('/members');
            }
            next();
        };

        //Admin privileges
        const requireAdmin = (req, res, next) => {

            if (!req.session.isAuthenticated) {
                console.log('DEBUG: Not authenticated, redirecting to login.');
                return res.redirect('/login?error=' + encodeURIComponent('Please log in to view this page.'));
            }

            if (!req.session.user || !req.session.user.user_type) {
                console.error('ERROR: User session object or user_type is missing!', req.session);
                return res.status(403).render('error', {
                    pageTitle: "Session Error",
                    message: "Your session data seems to be corrupted. Please log in again.",
                    errorCode: 403,
                    isAuthenticated: req.session.isAuthenticated,
                    currentUser: req.session.user
                });
            }

            if (req.session.user.user_type !== 'admin') {
                console.log('DEBUG: User is not admin. Rendering 403 page.');

                return res.status(403).render('error', {
                    pageTitle: "Access Denied",
                    message: "You do not have permission to view this page.",
                    errorCode: 403,
                    isAuthenticated: req.session.isAuthenticated,
                    currentUser: req.session.user
                });
            }
            next();
        };

        app.get('/', (req, res) => {
            res.render('home', {
                pageTitle: "Welcome",
                query: req.query
            });
        });

        app.get('/signup', requireNoAuth, (req, res) => {
            res.render('signup', {
                pageTitle: "Sign Up",
                error: req.query.error,
                formData: {}
            });
        });

        app.post('/signupSubmit', requireNoAuth, async (req, res) => {
            const { name, email, password } = req.body;

            const schema = Joi.object({
                name: Joi.string().alphanum().max(20).required(),
                email: Joi.string().email().required(),
                password: Joi.string().min(3).max(20).required()
            });

            const validationResult = schema.validate({ name, email, password });

            if (validationResult.error) {
                return res.redirect(`/signup?error=${encodeURIComponent(validationResult.error.details[0].message)}`);
            }

            try {
                const existingUser = await userCollection.findOne({ email: email });
                if (existingUser) {
                    return res.redirect(`/signup?error=${encodeURIComponent('Email already registered. Please log in.')}`);
                }

                const hashedPassword = await bcrypt.hash(password, saltRounds);
                const newUser = {
                    name: name,
                    email: email.toLowerCase(),
                    password: hashedPassword,
                    user_type: 'user'
                };
                const result = await userCollection.insertOne(newUser);
                console.log("User created:", result.insertedId);

                req.session.isAuthenticated = true;
                req.session.user = {
                    id: result.insertedId,
                    name: newUser.name,
                    email: newUser.email,
                    user_type: newUser.user_type
                };
                res.redirect('/members');
            } catch (err) {
                console.error("Signup error:", err);
                res.status(403).render('error', {
                    pageTitle: "Signup Error",
                    message: "An internal server error occurred during signup. Please try again later.",
					errorCode: 403,
                });
            }
        });

        app.get('/login', requireNoAuth, (req, res) => {
            res.render('login', {
                pageTitle: "Log In",
                error: req.query.error
            });
        });

        app.post('/loginSubmit', requireNoAuth, async (req, res) => {
            const { email, password } = req.body;

            const schema = Joi.object({
                email: Joi.string().email().required(),
                password: Joi.string().max(20).required()
            });

            const validationResult = schema.validate({ email, password });

            if (validationResult.error) {
                return res.redirect(`/login?error=${encodeURIComponent(validationResult.error.details[0].message)}`);
            }

            try {
                const user = await userCollection.findOne({ email: email.toLowerCase() });

                if (user && await bcrypt.compare(password, user.password)) {
                    req.session.isAuthenticated = true;
                    req.session.user = {
                        id: user._id,
                        name: user.name,
                        email: user.email,
                        user_type: user.user_type
                    };
                    res.redirect('/members');
                } else {
                    console.log(`Login failed for email: ${email}`);
                    res.redirect(`/login?error=${encodeURIComponent('Invalid email or password.')}`);
                }
            } catch (err) {
                console.error('Login database/bcrypt error: ', err);
                res.status(403).render('error', {
                    pageTitle: "Login Error",
                    message: "An internal server error occurred during login. Please try again later.",
					errorCode: 403,
                    isAuthenticated: req.session.isAuthenticated,
                    name: req.session.name
                });
            }
        });


        //Admin routes
        app.get('/admin', requireAdmin, async (req, res) => {
            try {
                const users = await userCollection.find({}).toArray();
                res.render('admin', {
                    pageTitle: 'Admin Panel',
                    users: users,
                    messages: req.query
                });
            } catch (err) {
                console.error('Admin page error: ', err);
                res.status(403).render('error', {
                    pageTitle: 'Admin error',
					errorCode: 403,
                    message: 'Not able to load admin data',
                    isAuthenticated: req.session.isAuthenticated,
                    name: req.session.name
                });
            }
        });

        app.post('/admin/promote/:userId', requireAdmin, async (req, res) => {
            const userId = req.params.userId;
            try {
                if (!ObjectId.isValid(userId)) {
                    return res.redirect('/admin?error=' + encodeURIComponent('Invalid user ID.'));
                }
                await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "admin" } });
                res.redirect('/admin?success=' + encodeURIComponent('User promoted to admin.'));
            } catch (err) {
                console.error("Promote user error:", err);
                res.redirect('/admin?error=' + encodeURIComponent('Error promoting user.'));
            }
        });

        app.post('/admin/demote/:userId', requireAdmin, async (req, res) => {
            const userId = req.params.userId;
            try {
                if (!ObjectId.isValid(userId)) {
                    return res.redirect('/admin?error=' + encodeURIComponent('Invalid user ID.'));
                }
                await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "user" } });
                res.redirect('/admin?success=' + encodeURIComponent('User demoted to user.'));
            } catch (err) {
                console.error("Demote user error:", err);
                res.redirect('/admin?error=' + encodeURIComponent('Error demoting user.'));
            }
        });


        app.get('/members', requireAuth, (req, res) => {
            const images = ['fluffy.gif', 'socks.gif', 'chapperson.webp', 'hydreigon.webp', 'samar.webp', 'ryder.webp'];
            const shuffledImages = images.sort(() => Math.random() - 0.5);
            res.render('members', {
                pageTitle: "Members Area",
                imageUrls: shuffledImages,
                isAuthenticated: req.session.isAuthenticated
            });
        });

        app.get('/logout', (req, res) => {
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying session: ', err);
                    return res.redirect('/?error=' + encodeURIComponent('Logout attempt failed.'));
                }
                res.redirect('/?message=' + encodeURIComponent('Successfully logged out!'));
            });
        });

        app.use((req, res, next) => {
            res.status(404).render('404', {
                pageTitle: "Page Not Found",
                isAuthenticated: req.session.isAuthenticated,
                name: req.session.name
            });
        });

        app.use((err, req, res, next) => {
            console.error("Unhandled error:", err.stack);
            res.status(403).render('error', {
                pageTitle: "Server Error",
				errorCode: 403,
                message: "Something went wrong on our end. Please try again later.",
                isAuthenticated: req.session.isAuthenticated,
                name: req.session.name
            });
        });

        app.listen(port, () => {
            console.log(`Node application listening on port ${port}`);
        });

    } catch (dbConnectErr) {
        console.error("Failed to connect to MongoDB Atlas. Server not started.", dbConnectErr);
        process.exit(1);
    }
}

connectToDBAndStartServer();