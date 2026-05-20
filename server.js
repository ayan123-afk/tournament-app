const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();

// Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL || 'https://fbevazliilbxpbqzgocw.supabase.co',
    process.env.SUPABASE_PUBLISHABLE_KEY || 'sb_publishable_NPku8BMDnmwyFHoKY3oqvw_sE_4kgr0'
);

// Middleware
app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Multer setup for memory storage (Vercel compatible)
const upload = multer({ 
    storage: multer.memoryStorage(),
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb('Error: Images Only!');
        }
    }
});

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'phantom-ff-league-jwt-secret-key-2026', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'phantom-ff-league-jwt-secret-key-2026', (err, admin) => {
        if (err || admin.role !== 'admin') {
            return res.status(403).json({ error: 'Invalid admin token' });
        }
        req.admin = admin;
        next();
    });
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        const { data: existingUser } = await supabase
            .from('users')
            .select('*')
            .or(`email.eq.${email},username.eq.${username}`)
            .single();
            
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const { data, error } = await supabase
            .from('users')
            .insert([{
                username,
                email,
                password_hash: hashedPassword
            }])
            .select();
            
        if (error) throw error;
        
        const token = jwt.sign(
            { id: data[0].id, username, email },
            process.env.JWT_SECRET || 'phantom-ff-league-jwt-secret-key-2026',
            { expiresIn: '24h' }
        );
        
        res.json({ token, user: data[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();
            
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET || 'phantom-ff-league-jwt-secret-key-2026',
            { expiresIn: '24h' }
        );
        
        const { password_hash, ...userData } = user;
        res.json({ token, user: userData });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Tournament Routes
app.get('/api/tournaments', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('tournaments')
            .select('*')
            .order('created_at', { ascending: false });
            
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/tournaments/join', authenticateToken, async (req, res) => {
    try {
        const { tournamentId } = req.body;
        const userId = req.user.id;
        
        const { data: existing } = await supabase
            .from('tournament_registrations')
            .select('*')
            .eq('tournament_id', tournamentId)
            .eq('user_id', userId)
            .single();
            
        if (existing) {
            return res.status(400).json({ error: 'Already registered' });
        }
        
        const { data, error } = await supabase
            .from('tournament_registrations')
            .insert([{
                tournament_id: tournamentId,
                user_id: userId
            }])
            .select();
            
        if (error) throw error;
        
        res.json(data[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Leaderboard Routes
app.get('/api/leaderboard', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('leaderboard')
            .select(`
                *,
                users:user_id (username, avatar_url)
            `)
            .order('points', { ascending: false })
            .limit(100);
            
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Wallet Routes
app.get('/api/wallet', authenticateToken, async (req, res) => {
    try {
        const { data: user } = await supabase
            .from('users')
            .select('coins')
            .eq('id', req.user.id)
            .single();
            
        const { data: transactions } = await supabase
            .from('transactions')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false })
            .limit(50);
            
        res.json({
            balance: user.coins,
            transactions
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/wallet/add-coins', authenticateToken, upload.single('screenshot'), async (req, res) => {
    try {
        const { amount, transactionId } = req.body;
        const userId = req.user.id;
        
        let screenshotUrl = null;
        if (req.file) {
            const fileName = `screenshots/${userId}/${Date.now()}-${req.file.originalname}`;
            
            const { data: uploadData, error: uploadError } = await supabase.storage
                .from('payment-screenshots')
                .upload(fileName, req.file.buffer, {
                    contentType: req.file.mimetype
                });
                
            if (!uploadError) {
                const { data: { publicUrl } } = supabase.storage
                    .from('payment-screenshots')
                    .getPublicUrl(fileName);
                screenshotUrl = publicUrl;
            }
        }
        
        const { data, error } = await supabase
            .from('wallet_requests')
            .insert([{
                user_id: userId,
                amount: parseFloat(amount),
                transaction_id: transactionId,
                screenshot_url: screenshotUrl,
                status: 'pending'
            }])
            .select();
            
        if (error) throw error;
        
        res.json({ 
            success: true, 
            message: 'Payment request submitted. Waiting for admin approval.',
            request: data[0]
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin Auth Routes
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (email === 'ayan@admin.com' && password === 'ayan7505') {
            const token = jwt.sign(
                { id: 'admin-1', email: email, role: 'admin' },
                process.env.JWT_SECRET || 'phantom-ff-league-jwt-secret-key-2026',
                { expiresIn: '8h' }
            );
            
            res.json({ 
                token, 
                admin: { id: 'admin-1', email: email, role: 'admin' } 
            });
        } else {
            res.status(401).json({ error: 'Invalid admin credentials' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin Routes
app.get('/api/admin/wallet-requests', authenticateAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wallet_requests')
            .select(`
                *,
                users:user_id (username, email)
            `)
            .order('created_at', { ascending: false });
            
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/wallet-requests/:id/approve', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const { data: request } = await supabase
            .from('wallet_requests')
            .select('*')
            .eq('id', id)
            .single();
            
        if (!request) {
            return res.status(404).json({ error: 'Request not found' });
        }
        
        await supabase
            .from('wallet_requests')
            .update({ 
                status: 'approved',
                updated_at: new Date()
            })
            .eq('id', id);
        
        const { data: user } = await supabase
            .from('users')
            .select('coins')
            .eq('id', request.user_id)
            .single();
            
        const newBalance = parseFloat(user.coins) + parseFloat(request.amount);
        
        await supabase
            .from('users')
            .update({ coins: newBalance })
            .eq('id', request.user_id);
            
        await supabase
            .from('transactions')
            .insert([{
                user_id: request.user_id,
                type: 'deposit',
                amount: request.amount,
                description: 'Wallet top-up approved',
                status: 'completed'
            }]);
            
        await supabase
            .from('notifications')
            .insert([{
                user_id: request.user_id,
                title: 'Payment Approved',
                message: `Your wallet top-up of ${request.amount} coins has been approved.`,
                type: 'success'
            }]);
            
        res.json({ success: true, message: 'Payment approved successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/wallet-requests/:id/reject', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        
        await supabase
            .from('wallet_requests')
            .update({ 
                status: 'rejected',
                admin_note: reason,
                updated_at: new Date()
            })
            .eq('id', id);
        
        res.json({ success: true, message: 'Payment rejected' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .order('created_at', { ascending: false });
            
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin-login', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-login.html'));
});

// Export for Vercel
module.exports = app;
