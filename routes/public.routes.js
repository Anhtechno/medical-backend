const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const Incident = require('../models/Incident');
const departments = require('../data/departments');

// 10.9. PUBLIC APIS FOR QR CODE REPORTING (TÍNH NĂNG MỚI)
// =================================================================

// API công khai để lấy thông tin cơ bản của thiết bị bằng serial
// API công khai để lấy thông tin CHI TIẾT của thiết bị
router.get('/api/public/equipment-details/:serial', async (req, res) => {
    try {
        const { serial } = req.params;
        // Lấy nhiều trường hơn để hiển thị công khai
        const equipment = await Equipment.findOne({ serial: serial }, 'name serial department manufacturer year status'); 
        if (!equipment) {
            return res.status(404).json({ message: 'Không tìm thấy thiết bị với số serial này.' });
        }
        // Trả về tên khoa thay vì mã khoa
        const equipmentWithDeptName = {
            ...equipment.toObject(),
            departmentName: departments[equipment.department] || 'Không xác định'
        };
        res.json(equipmentWithDeptName);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

// API công khai để người dùng báo hỏng từ QR code
router.post('/api/public/incidents', async (req, res) => {
    try {
        const { equipmentSerial, problemDescription, reporterName } = req.body; // Thêm reporterName
        if (!equipmentSerial || !problemDescription || !reporterName) {
            return res.status(400).json({ message: "Vui lòng cung cấp đủ thông tin sự cố và tên người báo hỏng." });
        }
        const equipment = await Equipment.findOne({ serial: equipmentSerial });
        if (!equipment) {
            return res.status(404).json({ message: "Thiết bị không tồn tại trong hệ thống." });
        }

        const newIncident = new Incident({
            equipmentId: equipment._id,
            equipmentName: equipment.name,
            serial: equipment.serial,
            departmentKey: equipment.department,
            problemDescription: problemDescription,
            reportedBy: reporterName // Sử dụng tên người báo hỏng
        });

        await newIncident.save();
        res.status(201).json({ message: "Báo cáo sự cố đã được gửi thành công!" });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi tạo báo cáo sự cố' });
    }
});

module.exports = router;
