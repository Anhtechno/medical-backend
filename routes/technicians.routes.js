const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { authenticateToken, isAdmin } = require('../middleware/auth');
const { upload, cloudinary } = require('../config/upload');

// --- API MỚI: TẠO TÀI KHOẢN KỸ SƯ (CÓ UPLOAD AVATAR) ---
router.post('/api/technicians', authenticateToken, isAdmin, upload.single('avatar'), async (req, res) => {
    try {
        const { username, password, fullName } = req.body;
        if (!username || !password || !fullName) {
            return res.status(400).json({ message: "Vui lòng nhập đủ: Tên đăng nhập, Mật khẩu, Họ tên." });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });

        let avatarUrl = null;
        // Xử lý upload ảnh nếu có
        if (req.file) {
            const uploadResult = await new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream(
                    { folder: 'avatars', resource_type: 'image' },
                    (error, result) => { if (error) reject(error); else resolve(result); }
                );
                uploadStream.end(req.file.buffer);
            });
            avatarUrl = uploadResult.secure_url;
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newTech = new User({
            username,
            password: hashedPassword,
            role: 'technician',
            fullName,
            avatar: avatarUrl
        });
        await newTech.save();
        const techToReturn = newTech.toObject();
        delete techToReturn.password;
        res.status(201).json(techToReturn);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi tạo kỹ sư.' });
    }
});

// --- API MỚI: LẤY DANH SÁCH KỸ SƯ (ĐỂ ADMIN CHỌN) ---
router.get('/api/technicians', authenticateToken, async (req, res) => {
    try {
        // Chỉ lấy role technician, trả về id, username, fullName, avatar
        const techs = await User.find({ role: 'technician' }).select('_id username fullName avatar');
        res.json(techs);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi lấy danh sách kỹ sư.' });
    }
});

module.exports = router;
