const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const Incident = require('../models/Incident');
const Maintenance = require('../models/Maintenance');
const departments = require('../data/departments');
const { authenticateToken, isAdmin } = require('../middleware/auth');
const cfg = require('../config/usage');
const { todayVN, addDays, isValidDateStr, createdDateOf } = require('../utils/dateVN');
const { loadLoggedWeeks, decorateEquipment } = require('../utils/usageStatus');
const { buildEquipmentSearchFilter, escapeRegex } = require('../utils/search');

const byNameVi = (a, b) => String(a.name || '').localeCompare(String(b.name || ''), 'vi');

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
        
        const page = Math.max(parseInt(req.query.page) || 1, 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 10000);
        const status = req.query.status;
        const missingOnly = req.query.missing === '1'; // chỉ hiện thiết bị còn thiếu dữ liệu cần ghi bù

        const query = { department: deptKey };
        if (status && status !== 'all') query.status = status;

        const [equipmentsRaw, statsResult, loggedMap] = await Promise.all([
            Equipment.find(query).lean(),
            Equipment.aggregate([ { $match: { department: deptKey } }, { $group: { _id: '$status', count: { $sum: 1 } } } ]),
            loadLoggedWeeks({ departmentKey: deptKey })
        ]);

        // Gắn cờ "còn thiếu" (tuần chưa ghi nhật ký, ngày chưa ghi giờ sử dụng) cho từng thiết bị.
        // Ngày/tuần được tính theo GIỜ VIỆT NAM (không còn lệch ngày do server chạy giờ UTC).
        let items = equipmentsRaw.map(eq => decorateEquipment(eq, loggedMap.get(eq._id.toString())));
        const missingTotal = items.filter(i => i.hasMissing).length;
        if (missingOnly) items = items.filter(i => i.hasMissing);
        items.sort(byNameVi);

        const totalItems = items.length;
        const totalPages = Math.ceil(totalItems / limit);
        const equipments = items.slice((page - 1) * limit, page * limit);
        const stats = statsResult.reduce((acc, curr) => { if (curr._id) acc[curr._id] = curr.count; return acc; }, {});

        res.json({ equipments, totalPages, currentPage: page, totalItems, stats, missingTotal });
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
        const { q, dept, status } = req.query; // 'dept': tìm trong một khoa; 'status': kết hợp bộ lọc trạng thái
        if (!q || !String(q).trim()) return res.status(400).json({ message: "Cần có từ khóa tìm kiếm." });

        const scopedDept = req.user.role === 'user' ? req.user.departmentKey : (dept || null);

        // Tìm không phân biệt dấu/hoa thường, nhiều từ khóa (mỗi từ phải khớp 1 trường bất kỳ).
        // Chỉ khi tìm toàn cục mới cho phép gõ tên khoa để tìm theo khoa.
        const query = buildEquipmentSearchFilter(q, scopedDept ? {} : departments);
        if (scopedDept) query.department = scopedDept;
        if (status && status !== 'all') query.status = status;

        const results = await Equipment.find(query).limit(300).lean();

        const loggedMap = await loadLoggedWeeks({ equipmentId: { $in: results.map(r => r._id) } });
        const resultsWithLogStatus = results
            .map(eq => decorateEquipment(eq, loggedMap.get(eq._id.toString())))
            .sort(byNameVi);

        res.json(resultsWithLogStatus);
    } catch (error) {
        console.error("Lỗi khi tìm kiếm:", error);
        res.status(500).json({ message: 'Lỗi server khi tìm kiếm' });
    }
});
router.get('/api/equipment/item/:serial', authenticateToken, async (req, res) => {
    try {
        const serialToFind = req.params.serial.trim();
        const equipment = await Equipment.findOne({ serial: new RegExp('^' + escapeRegex(serialToFind) + '$', 'i') });
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị với số serial này." });
        res.json(equipment);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi lấy chi tiết thiết bị' }); }
});
// API Cập nhật giờ sử dụng (Hiệu suất)
// Có thể truyền thêm 'date' (YYYY-MM-DD) để GHI BÙ cho một ngày đã qua (từ ngày bắt đầu áp dụng GO_LIVE_DATE).
router.put('/api/equipment/usage/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { dailyUsage, date } = req.body;
        const today = todayVN(); // YYYY-MM-DD theo giờ Việt Nam

        // --- Kiểm tra ngày ---
        const targetDate = (date === undefined || date === null || date === '') ? today : date;
        if (!isValidDateStr(targetDate)) {
            return res.status(400).json({ message: "Ngày không hợp lệ." });
        }
        if (targetDate > today) {
            return res.status(400).json({ message: "Không thể ghi giờ sử dụng cho ngày chưa đến." });
        }
        if (targetDate < cfg.GO_LIVE_DATE && req.user.role !== 'admin') {
            return res.status(400).json({ message: `Chỉ được ghi bù giờ sử dụng từ ngày ${cfg.GO_LIVE_DATE.split('-').reverse().join('/')} (thời điểm bắt đầu áp dụng phần mềm).` });
        }

        // --- Kiểm tra số giờ ---
        const hours = Number(dailyUsage);
        if (dailyUsage === undefined || dailyUsage === null || dailyUsage === '' || !Number.isFinite(hours) || hours < 0 || hours > 24) {
            return res.status(400).json({ message: "Số giờ sử dụng phải là số từ 0 đến 24." });
        }
        const roundedHours = Math.round(hours * 100) / 100;

        const equipment = await Equipment.findById(id);
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });

        if (req.user.role === 'user' && req.user.departmentKey !== equipment.department) {
            return res.status(403).json({ message: "Bạn không có quyền cập nhật thiết bị của khoa khác." });
        }

        const backfilled = targetDate < today;

        // 1. Cập nhật lịch sử (usageHistory): sửa nếu ngày đó đã có, chưa có thì thêm mới
        const historyIndex = equipment.usageHistory.findIndex(h => h.date === targetDate);
        if (historyIndex > -1) {
            const entry = equipment.usageHistory[historyIndex];
            entry.hours = roundedHours;
            entry.backfilled = backfilled;
            entry.loggedBy = req.user.username;
            entry.loggedAt = new Date();
        } else {
            equipment.usageHistory.push({
                date: targetDate, hours: roundedHours, backfilled,
                loggedBy: req.user.username, loggedAt: new Date()
            });
        }

        // 2. Giá trị "hiện tại" chỉ đổi khi ghi cho ngày mới nhất (không để ghi bù ngày cũ làm lệch thanh hôm nay)
        if (targetDate >= (equipment.lastLogDate || '')) {
            equipment.dailyUsage = roundedHours;
            equipment.lastLogDate = targetDate;
        }

        await equipment.save();

        const [, m, d] = targetDate.split('-');
        res.json({
            message: backfilled ? `Đã ghi bù giờ sử dụng ngày ${d}/${m}.` : "Đã cập nhật giờ sử dụng hôm nay.",
            date: targetDate,
            hours: roundedHours,
            backfilled,
            dailyUsage: equipment.dailyUsage
        });
    } catch (error) {
        console.error("Lỗi khi cập nhật giờ sử dụng:", error);
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

// Lịch sử giờ sử dụng theo từng ngày (để hiển thị lịch ghi bù trên giao diện)
router.get('/api/equipment/usage/:id/history', authenticateToken, async (req, res) => {
    try {
        const equipment = await Equipment.findById(req.params.id).select('name department usageHistory').lean();
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        if (req.user.role === 'user' && req.user.departmentKey !== equipment.department) {
            return res.status(403).json({ message: "Bạn không có quyền xem thiết bị của khoa khác." });
        }

        const today = todayVN();
        const created = createdDateOf(equipment);
        // Trả về toàn bộ các ngày từ ngày bắt đầu áp dụng đến hôm nay (giao diện tự chia theo tháng)
        const byDate = new Map((equipment.usageHistory || []).map(h => [h.date, h]));

        const days = [];
        for (let d = cfg.GO_LIVE_DATE; d <= today; d = addDays(d, 1)) {
            const h = byDate.get(d);
            days.push({
                date: d,
                hours: h ? h.hours : null,
                backfilled: !!(h && h.backfilled),
                loggedBy: h && h.loggedBy ? h.loggedBy : null,
                beforeCreation: d < created // trước khi thiết bị có trong hệ thống: không tính là "thiếu"
            });
        }
        res.json({ today, equipmentName: equipment.name, goLive: cfg.GO_LIVE_DATE, days });
    } catch (error) {
        console.error("Lỗi khi lấy lịch sử giờ sử dụng:", error);
        res.status(500).json({ message: 'Lỗi server.' });
    }
});


router.put('/api/equipment/:deptKey/:serial', authenticateToken, isAdmin, async (req, res) => {
    // Khai báo ngoài try để khối catch bên dưới dùng được (trước đây gây lỗi ReferenceError làm sập server khi trùng serial)
    const { serial } = req.params;
    // Không cho phép ghi đè dữ liệu giờ sử dụng/nhật ký qua form sửa thiết bị
    const { usageHistory, dailyUsage, lastLogDate, _id, __v, ...updatedData } = req.body;
    try {

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
