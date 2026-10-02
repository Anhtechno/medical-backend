const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { authenticateToken, isAdmin } = require('../middleware/auth');

// 10.7. API QUẢN LÝ NGƯỜI DÙNG
router.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find({ role: 'user' }).select('-password').sort({ username: 1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách người dùng.' });
    }
});

router.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { username, password, departmentKey } = req.body;
        if (!username || !password || !departmentKey) {
            return res.status(400).json({ message: "Vui lòng nhập đủ Tên đăng nhập, Mật khẩu và Khoa." });
        }
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({
            username,
            password: hashedPassword,
            role: 'user',
            departmentKey
        });
        await newUser.save();
        const userToReturn = newUser.toObject();
        delete userToReturn.password;
        res.status(201).json(userToReturn);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi tạo người dùng.' });
    }
});

router.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { departmentKey, password } = req.body;
        const updateData = { departmentKey };

        if (password && password.length > 0) {
            updateData.password = await bcrypt.hash(password, 12);
        }

        const updatedUser = await User.findByIdAndUpdate(id, updateData, { new: true }).select('-password');
        if (!updatedUser) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
        }
        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi cập nhật người dùng.' });
    }
});

router.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
        }
        res.json({ message: 'Xóa người dùng thành công.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa người dùng.' });
    }
});

module.exports = router;
