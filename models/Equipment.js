const mongoose = require('mongoose');

const equipmentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    serial: { type: String, required: true, unique: true },
    manufacturer: String, accessories: String, year: String, status: String,
    description: String, image: String, department: { type: String, required: true },
    
    dailyUsage: { type: Number, default: 0, min: 0, max: 24 },
    lastLogDate: { type: String, default: '' }, // Lưu ngày cập nhật cuối (dạng YYYY-MM-DD)
    usageHistory: [{ // Mảng lưu lịch sử dùng để tính báo cáo
        date: String, // YYYY-MM-DD
        hours: Number
    }]
});
const Equipment = mongoose.models.Equipment || mongoose.model('Equipment', equipmentSchema);

module.exports = Equipment;
