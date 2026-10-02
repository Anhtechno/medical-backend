const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const Incident = require('../models/Incident');
const Maintenance = require('../models/Maintenance');
const UsageLog = require('../models/UsageLog');
const departments = require('../data/departments');
const { authenticateToken, isAdmin } = require('../middleware/auth');

// 8. API QUẢN LÝ THIẾT BỊ
router.get('/api/departments', authenticateToken, (req, res) => {
    // Cho phép cả Admin VÀ Technician lấy full danh sách khoa
    if (req.user.role === 'admin' || req.user.role === 'technician') return res.json(departments); 
    
    // ... phần dưới giữ nguyên ...
    const userDept = {};
    if (req.user.departmentKey && departments[req.user.departmentKey]) {
        userDept[req.user.departmentKey] = departments[req.user.departmentKey];
    }
    res.json(userDept);
});

// --- SỬA ĐOẠN NÀY ---
router.get('/api/equipment/:deptKey', authenticateToken, async (req, res) => {
    try {
        const { deptKey } = req.params;
        if (req.user.role === 'user' && req.user.departmentKey !== deptKey) {
            return res.status(403).json({ message: "Không có quyền xem dữ liệu của khoa này." });
        }
        
        // --- LOGIC MỚI: TÍNH TOÁN NGÀY HÔM NAY ---
        const todayStr = new Date().toISOString().split('T')[0]; // Lấy ngày YYYY-MM-DD
        
        const now = new Date();
        const dayOfWeek = now.getDay();
        const diff = now.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1);
        const startOfWeek = new Date(now.setDate(diff));
        startOfWeek.setHours(0, 0, 0, 0);

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const status = req.query.status;
        const skip = (page - 1) * limit;
        
        const query = { department: deptKey };
        if (status && status !== 'all') query.status = status;

        const [equipmentsRaw, totalItems, statsResult, loggedThisWeek] = await Promise.all([
            Equipment.find(query).sort({ name: 1 }).skip(skip).limit(limit).lean(),
            Equipment.countDocuments(query),
            Equipment.aggregate([ { $match: { department: deptKey } }, { $group: { _id: '$status', count: { $sum: 1 } } } ]),
            UsageLog.find({ departmentKey: deptKey, createdAt: { $gte: startOfWeek } }).select('equipmentId -_id')
        ]);

        const loggedEquipmentIds = new Set(loggedThisWeek.map(log => log.equipmentId.toString()));
        
        // --- LOGIC RESET THANH HP NẾU QUA NGÀY MỚI ---
        const equipmentsWithLogStatus = equipmentsRaw.map(eq => {
            // Nếu ngày lưu cuối cùng KHÁC hôm nay, thì reset hiển thị về 0
            const displayUsage = (eq.lastLogDate === todayStr) ? eq.dailyUsage : 0;
            
            return {
                ...eq,
                dailyUsage: displayUsage, // Ghi đè giá trị hiển thị
                needsLog: !loggedEquipmentIds.has(eq._id.toString())
            };
        });

        const stats = statsResult.reduce((acc, curr) => { if (curr._id) acc[curr._id] = curr.count; return acc; }, {});
        const totalPages = Math.ceil(totalItems / limit);
        
        res.json({ equipments: equipmentsWithLogStatus, totalPages, currentPage: page, totalItems, stats });
    } catch (error) {
        console.error("Lỗi khi lấy dữ liệu equipment:", error);
        res.status(500).json({ message: 'Lỗi server khi lấy dữ liệu' });
    }
});

router.post('/api/equipment/:deptKey', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { deptKey } = req.params;
        const newEquipmentData = { ...req.body, department: deptKey };
        const existing = await Equipment.findOne({ serial: newEquipmentData.serial });
        if (existing) return res.status(400).json({ message: `Số serial "${newEquipmentData.serial}" đã tồn tại.` });
        const equipment = new Equipment(newEquipmentData);
        await equipment.save();
        res.status(201).json(equipment);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi thêm thiết bị' }); }
});

router.delete('/api/equipment/:deptKey/:serial', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { serial } = req.params;
        const equipmentToDelete = await Equipment.findOne({ serial: serial });
        if (!equipmentToDelete) {
            return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        }
        const incidentCount = await Incident.countDocuments({ equipmentId: equipmentToDelete._id });
        const maintenanceCount = await Maintenance.countDocuments({ equipmentId: equipmentToDelete._id });
        if (incidentCount > 0 || maintenanceCount > 0) {
            return res.status(400).json({ 
                message: "Không thể xóa thiết bị này vì đã có lịch sử sự cố hoặc bảo trì liên quan. Hãy xem xét chuyển trạng thái sang 'Ngừng hoạt động' thay vì xóa." 
            });
        }
        await Equipment.findByIdAndDelete(equipmentToDelete._id);
        res.json({ message: "Xóa thành công." });
    } catch (error) {
        console.error("Lỗi khi xóa thiết bị:", error);
        res.status(500).json({ message: 'Lỗi server khi xóa' });
    }
});
router.get('/api/search', authenticateToken, async (req, res) => {
    try {
        const { q, dept } = req.query; // Nhận thêm tham số 'dept' cho khoa
        if (!q) return res.status(400).json({ message: "Cần có từ khóa tìm kiếm." });

        const searchTerm = q.toLowerCase();
        let query = {
            $or: [
                { name: { $regex: searchTerm, $options: 'i' } },
                { serial: { $regex: searchTerm, $options: 'i' } },
                { manufacturer: { $regex: searchTerm, $options: 'i' } }
            ]
        };

        // Nếu người dùng là 'user', luôn giới hạn trong khoa của họ
        if (req.user.role === 'user') {
            query.department = req.user.departmentKey;
        } 
        // Nếu có tham số 'dept' (tìm kiếm cục bộ cho admin), thêm điều kiện lọc theo khoa
        else if (dept) {
            query.department = dept;
        }

        const results = await Equipment.find(query).lean();

        // Logic thêm cờ 'needsLog' để hiển thị dấu ! chính xác
        const now = new Date();
        const dayOfWeek = now.getDay();
        const diff = now.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1);
        const startOfWeek = new Date(now.setDate(diff));
        startOfWeek.setHours(0, 0, 0, 0);
        const loggedThisWeek = await UsageLog.find({ createdAt: { $gte: startOfWeek } }).select('equipmentId -_id');
        const loggedEquipmentIds = new Set(loggedThisWeek.map(log => log.equipmentId.toString()));
        const resultsWithLogStatus = results.map(eq => ({
            ...eq,
            needsLog: !loggedEquipmentIds.has(eq._id.toString())
        }));

        res.json(resultsWithLogStatus);
    } catch (error) {
        console.error("Lỗi khi tìm kiếm:", error);
        res.status(500).json({ message: 'Lỗi server khi tìm kiếm' });
    }
});
router.get('/api/equipment/item/:serial', authenticateToken, async (req, res) => {
    try {
        const serialToFind = req.params.serial.trim();
        const equipment = await Equipment.findOne({ serial: new RegExp('^' + serialToFind + '$', 'i') });
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị với số serial này." });
        res.json(equipment);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi lấy chi tiết thiết bị' }); }
});
// API Cập nhật giờ sử dụng (Hiệu suất)
router.put('/api/equipment/usage/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { dailyUsage } = req.body;
        const todayStr = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        
        const equipment = await Equipment.findById(id);
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        
        if (req.user.role === 'user' && req.user.departmentKey !== equipment.department) {
            return res.status(400).json({ message: "Bạn không có quyền cập nhật thiết bị của khoa khác." }); 
        }

        const hours = parseFloat(dailyUsage);

        // 1. Cập nhật thông tin hiện tại
        equipment.dailyUsage = hours;
        equipment.lastLogDate = todayStr;

        // 2. Cập nhật lịch sử (UsageHistory)
        // Tìm xem trong mảng history đã có ngày hôm nay chưa
        const historyIndex = equipment.usageHistory.findIndex(h => h.date === todayStr);
        
        if (historyIndex > -1) {
            // Nếu có rồi thì cập nhật lại giờ
            equipment.usageHistory[historyIndex].hours = hours;
        } else {
            // Nếu chưa có thì thêm mới
            equipment.usageHistory.push({ date: todayStr, hours: hours });
        }

        await equipment.save();

        res.json({ message: "Đã cập nhật hiệu suất.", dailyUsage: equipment.dailyUsage });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server.' });
    }
});


router.put('/api/equipment/:deptKey/:serial', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { serial } = req.params;
        const updatedData = req.body;

        // Tìm thiết bị gốc bằng serial cũ từ URL
        const originalEquipment = await Equipment.findOne({ serial: serial });
        if (!originalEquipment) {
            return res.status(404).json({ message: "Không tìm thấy thiết bị gốc." });
        }

        // Nếu người dùng muốn đổi số serial
        if (updatedData.serial && updatedData.serial !== serial) {
            // Kiểm tra xem số serial mới có bị trùng với thiết bị nào khác không
            const existingEquipment = await Equipment.findOne({ serial: updatedData.serial });
            if (existingEquipment) {
                return res.status(400).json({ message: `Số serial mới "${updatedData.serial}" đã tồn tại.` });
            }
        }

        const updatedEquipment = await Equipment.findByIdAndUpdate(originalEquipment._id, updatedData, { new: true });

        // Nếu tên hoặc serial thay đổi, cập nhật các bản ghi liên quan
        const needsSync = (updatedData.name && updatedData.name !== originalEquipment.name) || 
                          (updatedData.serial && updatedData.serial !== originalEquipment.serial);

        if (needsSync) {
            await Promise.all([
                Incident.updateMany({ equipmentId: originalEquipment._id }, { equipmentName: updatedEquipment.name, serial: updatedEquipment.serial }),
                Maintenance.updateMany({ equipmentId: originalEquipment._id }, { equipmentName: updatedEquipment.name, serial: updatedEquipment.serial })
            ]);
        }

        res.json(updatedEquipment);
    } catch (error) {
        console.error("Lỗi khi cập nhật thiết bị:", error);
        if (error.code === 11000) {
            return res.status(400).json({ message: `Số serial "${updatedData.serial}" đã tồn tại.` });
        }
        res.status(500).json({ message: 'Lỗi server khi cập nhật' });
    }
});
// 10.6. API CHO TRANG HỒ SƠ THIẾT BỊ
router.get('/api/equipment/profile/:serial', authenticateToken, async (req, res) => {
    try {
        const { serial } = req.params;
        const equipment = await Equipment.findOne({ serial }).lean();

        if (!equipment) {
            return res.status(404).json({ message: 'Không tìm thấy thiết bị.' });
        }

        const [incidents, maintenanceHistory] = await Promise.all([
            Incident.find({ equipmentId: equipment._id }).sort({ createdAt: -1 }).lean(),
            Maintenance.find({ equipmentId: equipment._id }).sort({ scheduleDate: -1 }).lean()
        ]);

        res.json({
            details: equipment,
            incidents,
            maintenanceHistory
        });

    } catch (error) {
        console.error("Lỗi khi lấy hồ sơ thiết bị:", error);
        res.status(500).json({ message: 'Lỗi server khi lấy hồ sơ thiết bị' });
    }
});
// 10.8. API NHẬP DỮ LIỆU HÀNG LOẠT TỪ EXCEL
router.post('/api/equipment/batch-import/:deptKey', authenticateToken, isAdmin, async (req, res) => {
    const { deptKey } = req.params;
    const equipmentList = req.body;

    if (!Array.isArray(equipmentList) || equipmentList.length === 0) {
        return res.status(400).json({ message: 'Dữ liệu gửi lên không hợp lệ.' });
    }

    let successCount = 0;
    let failedCount = 0;
    const errors = [];

    const dataToInsert = equipmentList.map(item => ({
        ...item,
        department: deptKey,
        status: item.status || 'active',
        year: item.year || new Date().getFullYear().toString(),
    }));

    try {
        const result = await Equipment.insertMany(dataToInsert, { ordered: false });
        successCount = result.length;
    } catch (error) {
        if (error.writeErrors) {
            successCount = error.insertedDocs.length;
            failedCount = error.writeErrors.length;
            error.writeErrors.forEach(err => {
                errors.push(`Serial '${err.err.op.serial}' đã tồn tại.`);
            });
        } else {
            console.error("Lỗi nghiêm trọng khi nhập hàng loạt:", error);
            return res.status(500).json({ message: 'Đã có lỗi nghiêm trọng xảy ra.' });
        }
    }

    res.status(201).json({
        message: `Hoàn tất! Thêm thành công ${successCount} thiết bị. Thất bại: ${failedCount} thiết bị.`,
        successCount,
        failedCount,
        errors
    });
});

module.exports = router;
