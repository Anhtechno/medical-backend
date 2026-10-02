const express = require('express');
const router = express.Router();
const Incident = require('../models/Incident');
const Equipment = require('../models/Equipment');
const User = require('../models/User');
const { authenticateToken, isAdmin } = require('../middleware/auth');
const { sendNotificationEmail } = require('../config/email');

router.post('/api/incidents', authenticateToken, async (req, res) => {
    try {
        const { equipmentSerial, problemDescription } = req.body;
        if (!equipmentSerial || !problemDescription) { return res.status(400).json({ message: "Vui lòng cung cấp đủ thông tin sự cố." }); }
        const equipment = await Equipment.findOne({ serial: equipmentSerial });
        if (!equipment) { return res.status(404).json({ message: "Không tìm thấy thiết bị được báo cáo." }); }
        if(req.user.role === 'user' && req.user.departmentKey !== equipment.department) { return res.status(403).json({ message: "Không có quyền báo cáo cho thiết bị này." }); }
        const newIncident = new Incident({
            equipmentId: equipment._id,
            equipmentName: equipment.name,
            serial: equipment.serial,
            departmentKey: equipment.department,
            problemDescription: problemDescription,
            reportedBy: req.user.username
        });
        await newIncident.save();
        // --- ĐOẠN CODE THÊM MỚI: GỬI MAIL THÔNG BÁO ---
        
        // 1. Tìm email của tất cả Admin
        const admins = await User.find({ role: 'admin' }).select('email');
        const adminEmails = admins.map(u => u.email).filter(e => e); // Lọc email rỗng

        if (adminEmails.length > 0) {
            const emailSubject = `[BÁO ĐỘNG] Máy ${newIncident.equipmentName} gặp sự cố!`;
            const emailContent = `
                <h3>Thông báo sự cố mới</h3>
                <p><b>Thiết bị:</b> ${newIncident.equipmentName}</p>
                <p><b>Khoa phòng:</b> ${newIncident.departmentKey}</p>
                <p><b>Người báo:</b> ${req.user.fullName}</p>
                <p><b>Mô tả lỗi:</b> <span style="color:red">${newIncident.problemDescription}</span></p>
                <hr>
                <p>Vui lòng đăng nhập hệ thống để xử lý.</p>
            `;
            
            // Gửi cho tất cả admin
            adminEmails.forEach(email => {
                sendNotificationEmail(email, emailSubject, emailContent);
            });
        }
        // ------------------------------------------------

        res.json({ message: 'Đã báo cáo sự cố và gửi thông báo!' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi tạo báo cáo sự cố.' });
    }
});
router.get('/api/incidents', authenticateToken, async (req, res) => {
    try {
        let query = {};
        
        // 1. Nếu là User (Khoa): Chỉ thấy của khoa mình
        if (req.user.role === 'user') {
            query.departmentKey = req.user.departmentKey;
        }
        // 2. Nếu là Technician (Kỹ sư): Chỉ thấy việc ĐƯỢC GIAO cho mình
        else if (req.user.role === 'technician') {
            query.assignedTo = req.user.userId; // userId lấy từ token
        }
        // 3. Nếu là Admin: Thấy hết (query rỗng)

        const incidents = await Incident.find(query)
            .populate('assignedTo', 'fullName avatar') // Lấy thêm thông tin kỹ sư để hiển thị
            .sort({ createdAt: -1 });
            
        res.json(incidents);
    } catch (error) {
        console.error("Lỗi lấy danh sách sự cố:", error);
        res.status(500).json({ message: 'Lỗi server.' });
    }
});
router.put('/api/incidents/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, notes } = req.body;
        
        // Kiểm tra quyền: Chỉ Admin hoặc Kỹ sư được giao việc mới được update
        const incident = await Incident.findById(id);
        if (!incident) return res.status(404).json({ message: "Không tìm thấy sự cố." });

        if (req.user.role === 'technician' && incident.assignedTo?.toString() !== req.user.userId) {
             return res.status(403).json({ message: "Bạn không được giao xử lý sự cố này." });
        }

        const updateData = { status, notes };
        
        // Nếu chuyển sang hoàn thành thì thêm thời gian
        if (status === 'resolved') {
            updateData.resolvedAt = new Date();
        }
        
        // Admin xem là đã đọc
        if (req.user.role === 'admin') {
            updateData.isRead = true;
        }

        const updatedIncident = await Incident.findByIdAndUpdate(id, updateData, { new: true });
        res.json(updatedIncident);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi cập nhật sự cố.' });
    }
});
router.get('/api/incidents/unread/count', authenticateToken, isAdmin, async (req, res) => {
    try {
        const count = await Incident.countDocuments({ isRead: false });
        res.json({ count });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi đếm sự cố' });
    }
});
router.get('/api/incidents/unread', authenticateToken, isAdmin, async (req, res) => {
    try {
        const incidents = await Incident.find({ isRead: false }).sort({ createdAt: -1 }).limit(5);
        res.json(incidents);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách sự cố chưa đọc' });
    }
});
router.delete('/api/incidents/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedIncident = await Incident.findByIdAndDelete(id);
        if (!deletedIncident) {
            return res.status(404).json({ message: 'Không tìm thấy báo cáo sự cố.' });
        }
        res.json({ message: 'Xóa báo cáo sự cố thành công.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa báo cáo sự cố.' });
    }
});
// --- API MỚI: PHÂN CÔNG SỰ CỐ (ASSIGN) ---
router.put('/api/incidents/assign/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { assignedToId, notes } = req.body; // ID của kỹ sư được chọn và ghi chú

        const updateData = {
            status: 'in_progress',
            assignedTo: assignedToId,
            assignedByName: req.user.username, // Lưu tên admin đã giao việc
            notes: notes // Ghi chú của Admin (Kỹ sư trưởng)
        };

        const incident = await Incident.findByIdAndUpdate(id, updateData, { new: true });
        if (!incident) return res.status(404).json({ message: "Không tìm thấy sự cố." });
        
        res.json(incident);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi phân công.' });
    }
});

module.exports = router;
