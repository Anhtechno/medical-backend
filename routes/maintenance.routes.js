const express = require('express');
const router = express.Router();
const Maintenance = require('../models/Maintenance');
const Equipment = require('../models/Equipment');
const { authenticateToken, isAdmin } = require('../middleware/auth');

// 10. API QUẢN LÝ BẢO TRÌ
router.post('/api/maintenance', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { equipmentSerial, scheduleDate, notes, type } = req.body;
        if (!equipmentSerial || !scheduleDate) {
            return res.status(400).json({ message: "Vui lòng cung cấp đủ Serial thiết bị và ngày dự kiến." });
        }
        const equipment = await Equipment.findOne({ serial: equipmentSerial });
        if (!equipment) {
            return res.status(404).json({ message: "Không tìm thấy thiết bị để lên lịch bảo trì." });
        }
        const newMaintenance = new Maintenance({
            equipmentId: equipment._id,
            equipmentName: equipment.name,
            serial: equipment.serial,
            departmentKey: equipment.department,
            scheduleDate,
            notes,
            type,
            createdBy: req.user.username
        });
        await newMaintenance.save();
        await Equipment.findOneAndUpdate({ serial: equipmentSerial }, { status: 'maintenance' });
        res.status(201).json(newMaintenance);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi tạo lịch bảo trì' });
    }
});

router.get('/api/maintenance', authenticateToken, async (req, res) => {
    try {
        let query = {};
        if (req.user.role === 'user') {
            query.departmentKey = req.user.departmentKey;
        }
        const maintenanceSchedules = await Maintenance.find(query).sort({ scheduleDate: -1 });
        res.json(maintenanceSchedules);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách bảo trì' });
    }
});

router.get('/api/maintenance/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const maintenance = await Maintenance.findById(req.params.id);
        if (!maintenance) {
            return res.status(404).json({ message: 'Không tìm thấy lịch bảo trì.' });
        }
        res.json(maintenance);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy chi tiết bảo trì' });
    }
});

router.put('/api/maintenance/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, completionDate, technician, notes, cost, type } = req.body;
        const updatedMaintenance = await Maintenance.findByIdAndUpdate(id, {
            status, completionDate, technician, notes, cost, type
        }, { new: true });
        if (!updatedMaintenance) return res.status(404).json({ message: "Không tìm thấy lịch bảo trì." });
        if (status === 'completed' || status === 'canceled') {
            const relatedEquipment = await Equipment.findById(updatedMaintenance.equipmentId);
            if (relatedEquipment && relatedEquipment.status === 'maintenance') {
                 await Equipment.findByIdAndUpdate(updatedMaintenance.equipmentId, { status: 'active' });
            }
        }
        res.json(updatedMaintenance);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi cập nhật lịch bảo trì' });
    }
});

router.delete('/api/maintenance/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedMaintenance = await Maintenance.findByIdAndDelete(id);
        if (!deletedMaintenance) return res.status(404).json({ message: "Không tìm thấy lịch bảo trì." });
        res.json({ message: "Xóa lịch bảo trì thành công." });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa lịch bảo trì' });
    }
});

module.exports = router;
