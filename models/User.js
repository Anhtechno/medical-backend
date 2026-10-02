const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    // Thêm role 'technician'
    role: { type: String, required: true, enum: ['admin', 'user', 'technician'], default: 'user' },
    departmentKey: { type: String }, // Dùng cho User khoa phòng
    fullName: { type: String }, // Tên hiển thị (Dành cho Kỹ sư)
    avatar: { type: String } // Link ảnh đại diện (Dành cho Kỹ sư)
}, { timestamps: true });
const User = mongoose.models.User || mongoose.model('User', userSchema);

module.exports = User;
