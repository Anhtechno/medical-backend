const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const UsageLog = require('../models/UsageLog');
const { authenticateToken, isAdmin } = require('../middleware/auth');
const cfg = require('../config/usage');
const {
    todayVN, addDays, weekStartOf, currentWeekStart, weekEndOf, isValidDateStr, weekLabel,
    startInstant, weekStartOfLog, createdDateOf
} = require('../utils/dateVN');
const { loadLoggedWeeks, computeUsageStatus, firstWeek, isLocked } = require('../utils/usageStatus');

const fmtMonthYear = (s) => `tháng ${s.slice(5, 7)}/${s.slice(0, 4)}`;

const VALID_STATUS = ['operational', 'minor_issue', 'not_in_use'];

// Chuẩn hóa & kiểm tra tuần được chọn để ghi (mặc định là tuần hiện tại).
// Người dùng khoa được ghi bù ngược về tuần chứa ngày bắt đầu áp dụng phần mềm (GO_LIVE_DATE).
function resolveWeek(input, role) {
    const cur = currentWeekStart();
    if (input === undefined || input === null || input === '') return { weekStart: cur };
    if (!isValidDateStr(input)) return { error: 'Tuần được chọn không hợp lệ.' };
    const weekStart = weekStartOf(input);
    if (weekStart > cur) return { error: 'Không thể ghi nhật ký cho tuần chưa đến.' };
    if (weekStart < firstWeek() && role !== 'admin') {
        return { error: `Chỉ được ghi bù nhật ký từ ${fmtMonthYear(cfg.GO_LIVE_DATE)} (thời điểm bắt đầu áp dụng phần mềm).` };
    }
    return { weekStart };
}

// Điều kiện tìm nhật ký thuộc một tuần (gồm cả nhật ký cũ chưa có trường weekStart)
function weekFilter(weekStart) {
    return {
        $or: [
            { weekStart },
            { weekStart: { $exists: false }, createdAt: { $gte: startInstant(weekStart), $lt: startInstant(addDays(weekStart, 7)) } }
        ]
    };
}

// =================================================================
// API NHẬT KÝ SỬ DỤNG
// =================================================================

// Khoa ghi nhật ký cho MỘT thiết bị. Có thể chọn tuần (weekStart) để ghi bù.
// Nếu thiết bị đã có nhật ký của tuần đó thì cập nhật lại (không tạo bản ghi trùng).
router.post('/api/logs', authenticateToken, async (req, res) => {
    try {
        const { equipmentId, status, notes, weekStart: weekInput } = req.body;
        if (!equipmentId || !status) {
            return res.status(400).json({ message: "Thiếu thông tin thiết bị hoặc trạng thái." });
        }
        if (!VALID_STATUS.includes(status)) {
            return res.status(400).json({ message: "Trạng thái nhật ký không hợp lệ." });
        }
        if (req.user.role !== 'user' && req.user.role !== 'admin') {
            return res.status(403).json({ message: "Tài khoản này không được ghi nhật ký sử dụng." });
        }

        const equipment = await Equipment.findById(equipmentId);
        if (!equipment) {
            return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        }
        // Khoa chỉ được ghi nhật ký cho thiết bị của chính khoa mình
        if (req.user.role === 'user' && equipment.department !== req.user.departmentKey) {
            return res.status(403).json({ message: "Bạn không thể ghi nhật ký cho thiết bị của khoa khác." });
        }

        // Thiết bị đang "Ngừng hoạt động": Khoa tạm thời không được ghi (Admin vẫn sửa được nếu cần)
        if (req.user.role === 'user' && isLocked(equipment)) {
            return res.status(403).json({ message: cfg.LOCKED_MESSAGE, locked: true });
        }

        const week = resolveWeek(weekInput, req.user.role);
        if (week.error) return res.status(400).json({ message: week.error });
        const { weekStart } = week;
        const isBackfill = weekStart < currentWeekStart();
        const cleanNotes = String(notes || '').slice(0, 1000);

        const existing = await UsageLog.findOne({ equipmentId: equipment._id, ...weekFilter(weekStart) }).sort({ createdAt: -1 });
        let log;
        let updated = false;
        if (existing) {
            existing.status = status;
            existing.notes = cleanNotes;
            existing.loggedBy = req.user.username;
            existing.weekStart = weekStart;
            existing.isBackfill = isBackfill;
            log = await existing.save();
            updated = true;
        } else {
            log = await UsageLog.create({
                equipmentId: equipment._id,
                equipmentName: equipment.name,
                serial: equipment.serial,
                departmentKey: equipment.department,
                loggedBy: req.user.username,
                status,
                notes: cleanNotes,
                weekStart,
                isBackfill
            });
        }

        const label = weekLabel(weekStart);
        res.status(updated ? 200 : 201).json({
            message: updated
                ? `Đã cập nhật nhật ký tuần ${label}.`
                : (isBackfill ? `Đã ghi bù nhật ký tuần ${label}.` : "Ghi nhật ký thành công!"),
            log
        });

    } catch (error) {
        console.error("Lỗi khi tạo nhật ký sử dụng:", error);
        res.status(500).json({ message: 'Lỗi server khi tạo nhật ký.' });
    }
});

// Admin xem lịch sử nhật ký của một thiết bị
router.get('/api/logs/equipment/:equipmentId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { equipmentId } = req.params;
        const logs = await UsageLog.find({ equipmentId }).lean();
        const result = logs.map(l => ({ ...l, weekStart: weekStartOfLog(l) }));
        result.sort((a, b) => (b.weekStart.localeCompare(a.weekStart)) || (new Date(b.createdAt) - new Date(a.createdAt)));
        res.json(result);
    } catch (error) {
        console.error("Lỗi khi lấy lịch sử nhật ký:", error);
        res.status(500).json({ message: 'Lỗi server khi lấy lịch sử nhật ký.' });
    }
});

// =================================================================
// GHI NHẬT KÝ HÀNG LOẠT (cho cả khoa) - có thể chọn tuần để ghi bù
// =================================================================
router.post('/api/logs/bulk', authenticateToken, async (req, res) => {
    try {
        const { status, notes, excludeIds = [], weekStart: weekInput } = req.body;
        const { departmentKey, username, role } = req.user;

        if (role !== 'user' || !departmentKey) {
            return res.status(403).json({ message: "Chỉ tài khoản của khoa/phòng mới được ghi nhật ký hàng loạt." });
        }
        if (!status) {
            return res.status(400).json({ message: "Thiếu thông tin trạng thái." });
        }
        if (!VALID_STATUS.includes(status)) {
            return res.status(400).json({ message: "Trạng thái nhật ký không hợp lệ." });
        }
        if (!Array.isArray(excludeIds)) {
            return res.status(400).json({ message: "Danh sách loại trừ không hợp lệ." });
        }

        const week = resolveWeek(weekInput, role);
        if (week.error) return res.status(400).json({ message: week.error });
        const { weekStart } = week;
        const isBackfill = weekStart < currentWeekStart();
        const excluded = new Set(excludeIds.map(String));
        const cleanNotes = String(notes || '').slice(0, 1000);

        // 1. Thiết bị trong khoa + các tuần đã ghi của từng thiết bị
        const [allEquipment, loggedMap] = await Promise.all([
            Equipment.find({ department: departmentKey }).select('_id name serial status').lean(),
            loadLoggedWeeks({ departmentKey })
        ]);

        // 2. Chỉ ghi cho thiết bị: chưa có nhật ký tuần đó, không bị loại trừ,
        //    và đã tồn tại tại thời điểm tuần đó (không ghi ngược cho thiết bị mới thêm)
        const weekEnd = weekEndOf(weekStart);
        const toLog = allEquipment.filter(eq => {
            const id = eq._id.toString();
            const logged = loggedMap.get(id);
            return !isLocked(eq) && !(logged && logged.has(weekStart)) && !excluded.has(id) && createdDateOf(eq) <= weekEnd;
        });

        const label = weekLabel(weekStart);
        if (toLog.length === 0) {
            return res.status(200).json({ message: `Không còn thiết bị nào cần ghi nhật ký cho tuần ${label}.`, count: 0 });
        }

        await UsageLog.insertMany(toLog.map(eq => ({
            equipmentId: eq._id, equipmentName: eq.name, serial: eq.serial,
            departmentKey, loggedBy: username, status, notes: cleanNotes, weekStart, isBackfill
        })));

        res.status(201).json({
            message: `Đã ghi nhật ký${isBackfill ? ' bù' : ''} tuần ${label} cho ${toLog.length} thiết bị.`,
            count: toLog.length
        });

    } catch (error) {
        console.error("Lỗi khi ghi nhật ký hàng loạt:", error);
        res.status(500).json({ message: 'Lỗi server khi ghi nhật ký hàng loạt.' });
    }
});

// =================================================================
// TỔNG HỢP "CÒN THIẾU GÌ CHƯA GHI" - dùng cho thông báo nổi bật trên giao diện khoa
// =================================================================
router.get('/api/logs/missing-summary', authenticateToken, async (req, res) => {
    try {
        const deptKey = req.user.role === 'user' ? req.user.departmentKey : req.query.dept;
        if (!deptKey) return res.status(400).json({ message: 'Thiếu thông tin khoa/phòng.' });

        const [equipments, loggedMap] = await Promise.all([
            Equipment.find({ department: deptKey }).select('_id usageHistory status').lean(),
            loadLoggedWeeks({ departmentKey: deptKey })
        ]);

        // Thiết bị đang ngừng hoạt động không bị tính là "thiếu"
        const active = equipments.filter(eq => !isLocked(eq));
        const statuses = active.map(eq => computeUsageStatus(eq, loggedMap.get(eq._id.toString())));

        const cur = currentWeekStart();
        const weeks = [];
        const fw = firstWeek();
        for (let i = 0; addDays(cur, -7 * i) >= fw; i++) {
            const wk = addDays(cur, -7 * i);
            const missingCount = statuses.filter(s => (i === 0 ? s.needsLog : s.missingWeeks.includes(wk))).length;
            weeks.push({ weekStart: wk, label: weekLabel(wk), isCurrent: i === 0, missingCount });
        }

        res.json({
            today: todayVN(),
            totalEquipment: active.length,
            weeks,
            dailyMissing: {
                since: cfg.GO_LIVE_DATE,
                equipmentCount: statuses.filter(s => s.missingDays.length > 0).length,
                totalDays: statuses.reduce((sum, s) => sum + s.missingDays.length, 0)
            }
        });
    } catch (error) {
        console.error("Lỗi khi tổng hợp dữ liệu còn thiếu:", error);
        res.status(500).json({ message: 'Lỗi server khi tổng hợp dữ liệu còn thiếu.' });
    }
});

module.exports = router;
