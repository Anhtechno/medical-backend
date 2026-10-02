const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { JWT_SECRET } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiters');

// 6. API XÁC THỰC
router.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const { username, password, departmentKey } = req.body;
        // BẢO MẬT: không nhận 'role' từ client — luôn tạo tài khoản với quyền 'user' mặc định.
        // Việc tạo tài khoản 'admin'/'technician' chỉ được thực hiện qua các route đã có middleware isAdmin.
        if (!username || !password) return res.status(400).json({ message: "Vui lòng nhập đủ tên đăng nhập và mật khẩu." });
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ username, password: hashedPassword, role: 'user', departmentKey });
        await newUser.save();
        res.status(201).json({ message: "Đăng ký tài khoản thành công!" });
    } catch (error) { res.status(500).json({ message: "Lỗi server khi đăng ký." }); }
});

router.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });
        const token = jwt.sign({ userId: user._id, username: user.username, role: user.role, departmentKey: user.departmentKey }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ message: "Đăng nhập thành công!", token });
    } catch (error) { res.status(500).json({ message: "Lỗi server khi đăng nhập." }); }
});

module.exports = router;
