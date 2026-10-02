const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const UsageLog = require('../models/UsageLog');
const { authenticateToken, isAdmin } = require('../middleware/auth');

// 10.10. API CHO NHẬT KÝ SỬ DỤNG (TÍNH NĂNG MỚI)
// =================================================================

// API để khoa/phòng tạo một nhật ký sử dụng mới
router.post('/api/logs', authenticateToken, async (req, res) => {
    try {
        const { equipmentId, status, notes } = req.body;
        if (!equipmentId || !status) {
            return res.status(400).json({ message: "Thiếu thông tin thiết bị hoặc trạng thái." });
        }

        const equipment = await Equipment.findById(equipmentId);
        if (!equipment) {
            return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        }

        const newLog = new UsageLog({
            equipmentId: equipment._id,
            equipmentName: equipment.name,
            serial: equipment.serial,
            departmentKey: req.user.departmentKey, // Lấy từ token của người dùng đang đăng nhập
            loggedBy: req.user.username, // Lấy từ token của người dùng đang đăng nhập
            status,
            notes
        });

        await newLog.save();
        res.status(201).json({ message: "Ghi nhật ký thành công!", log: newLog });

    } catch (error) {
        console.error("Lỗi khi tạo nhật ký sử dụng:", error);
        res.status(500).json({ message: 'Lỗi server khi tạo nhật ký.' });
    }
});

// API để admin xem lịch sử nhật ký của một thiết bị cụ thể
router.get('/api/logs/equipment/:equipmentId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { equipmentId } = req.params;
        const logs = await UsageLog.find({ equipmentId: equipmentId }).sort({ createdAt: -1 });
        res.json(logs);
    } catch (error) {
        console.error("Lỗi khi lấy lịch sử nhật ký:", error);
        res.status(500).json({ message: 'Lỗi server khi lấy lịch sử nhật ký.' });
    }
});
// =================================================================
// 10.13. API GHI NHẬT KÝ HÀNG LOẠT (TÍNH NĂNG MỚI)
// =================================================================
router.post('/api/logs/bulk', authenticateToken, async (req, res) => {
    try {
        const { status, notes, excludeIds = [] } = req.body; // Thêm `excludeIds` để nhận danh sách loại trừ
        const { departmentKey, username } = req.user;

        if (!status) {
            return res.status(400).json({ message: "Thiếu thông tin trạng thái." });
        }

        // 1. Xác định tuần hiện tại
        const now = new Date();
        const dayOfWeek = now.getDay();
        const diff = now.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1);
        const startOfWeek = new Date(now.setDate(diff));
        startOfWeek.setHours(0, 0, 0, 0);

        // 2. Lấy ID của tất cả thiết bị trong khoa
        const allEquipmentInDept = await Equipment.find({ department: departmentKey }).select('_id');
        const allEquipmentIds = allEquipmentInDept.map(eq => eq._id.toString());

        // 3. Lấy ID của các thiết bị đã được ghi nhật ký trong tuần này
        const loggedThisWeek = await UsageLog.find({
            departmentKey: departmentKey,
            createdAt: { $gte: startOfWeek }
        }).select('equipmentId');
        const loggedEquipmentIds = loggedThisWeek.map(log => log.equipmentId.toString());

        // 4. Lọc ra danh sách các thiết bị CHƯA được ghi nhật ký VÀ KHÔNG NẰM TRONG DANH SÁCH LOẠI TRỪ
        const unloggedEquipmentIds = allEquipmentIds.filter(id => 
            !loggedEquipmentIds.includes(id) && !excludeIds.includes(id)
        );

        if (unloggedEquipmentIds.length === 0) {
            return res.status(200).json({ message: "Không có thiết bị nào phù hợp để ghi nhật ký hàng loạt.", count: 0 });
        }

        // 5. Lấy thông tin chi tiết của các thiết bị cần ghi nhật ký
        const equipmentsToLog = await Equipment.find({ '_id': { $in: unloggedEquipmentIds } });

        // 6. Chuẩn bị dữ liệu để ghi hàng loạt
        const logsToInsert = equipmentsToLog.map(eq => ({
            equipmentId: eq._id, equipmentName: eq.name, serial: eq.serial,
            departmentKey: departmentKey, loggedBy: username, status: status, notes: notes
        }));
        
        // 7. Thực hiện ghi hàng loạt
        await UsageLog.insertMany(logsToInsert);

        res.status(201).json({ 
            message: `Đã ghi nhật ký hàng loạt thành công cho ${logsToInsert.length} thiết bị.`,
            count: logsToInsert.length 
        });

    } catch (error) {
        console.error("Lỗi khi ghi nhật ký hàng loạt:", error);
        res.status(500).json({ message: 'Lỗi server khi ghi nhật ký hàng loạt.' });
    }
});

module.exports = router;
