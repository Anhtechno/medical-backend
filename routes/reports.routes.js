const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const Incident = require('../models/Incident');
const departments = require('../data/departments');
const { authenticateToken, isAdmin } = require('../middleware/auth');
const cfg = require('../config/usage');
const { todayVN, isValidDateStr, diffDays, createdDateOf, startInstant, addDays } = require('../utils/dateVN');

// API Báo cáo hiệu suất máy (Cho Admin xem trong modal)
//
// CÔNG THỨC (đã sửa):
//   Giờ TB/ngày  = Tổng giờ đã ghi / Số ngày ĐÃ CÓ ghi nhận trong khoảng
//   Hiệu suất %  = Giờ TB/ngày / Công suất chuẩn (24h) x 100
//   Độ đầy đủ dữ liệu = Số ngày đã ghi / Số ngày trong khoảng
// Trước đây chia cho TẤT CẢ ngày trong lịch (kể cả ngày khoa quên chưa ghi, ngày chưa tới),
// khiến hiệu suất bị kéo thấp sai lệch. Nay ngày chưa ghi không bị tính là "0 giờ"; thay vào đó
// hệ thống báo độ đầy đủ dữ liệu để người xem biết kết quả đáng tin đến đâu.
router.post('/api/reports/machine-efficiency', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { equipmentId, startDate, endDate } = req.body;

        if (!isValidDateStr(startDate) || !isValidDateStr(endDate)) {
            return res.status(400).json({ message: "Vui lòng chọn khoảng ngày hợp lệ." });
        }
        if (startDate > endDate) {
            return res.status(400).json({ message: "Ngày bắt đầu phải trước hoặc bằng ngày kết thúc." });
        }

        const equipment = await Equipment.findById(equipmentId);
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });

        // Không tính những ngày chưa tới
        const today = todayVN();
        const effectiveEnd = endDate > today ? today : endDate;
        if (startDate > effectiveEnd) {
            return res.status(400).json({ message: "Khoảng ngày được chọn chưa có dữ liệu (nằm ở tương lai)." });
        }

        // Lọc lịch sử trong khoảng (so sánh chuỗi YYYY-MM-DD, không bị lệch múi giờ), mỗi ngày chỉ tính 1 lần
        const byDate = new Map();
        (equipment.usageHistory || []).forEach(h => {
            if (h.date >= startDate && h.date <= effectiveEnd && Number.isFinite(h.hours)) byDate.set(h.date, h.hours);
        });
        const loggedDays = byDate.size;
        const totalHours = [...byDate.values()].reduce((sum, h) => sum + h, 0);

        // Không tính những ngày trước khi thiết bị có trong hệ thống vào "số ngày trong khoảng"
        const created = createdDateOf(equipment);
        const earliestKnown = [created, ...byDate.keys()].sort()[0];
        const rangeStart = startDate > earliestKnown ? startDate : earliestKnown;
        const totalDays = Math.max(diffDays(rangeStart, effectiveEnd) + 1, 1);

        const rated = cfg.RATED_HOURS_PER_DAY;
        const avgRaw = loggedDays > 0 ? totalHours / loggedDays : 0;
        const efficiencyRaw = (avgRaw / rated) * 100;
        const coverageRaw = Math.min((loggedDays / totalDays) * 100, 100);
        const activeDays = [...byDate.values()].filter(h => h > 0).length;

        let level = 'normal';
        if (efficiencyRaw >= cfg.EFFICIENCY_OVERLOAD) level = 'overload';
        else if (efficiencyRaw >= cfg.EFFICIENCY_HIGH) level = 'high';

        res.json({
            equipmentName: equipment.name,
            totalHours: Math.round(totalHours * 100) / 100,
            totalDays,                       // số ngày trong khoảng (đã bỏ ngày chưa tới)
            loggedDays,                      // số ngày thực tế có ghi nhận
            activeDays,                      // số ngày có chạy (> 0 giờ)
            logsCount: loggedDays,           // giữ tên cũ để tương thích
            avgHoursPerDay: Math.round(avgRaw * 10) / 10,
            efficiencyPercent: Math.round(efficiencyRaw * 10) / 10,
            coveragePercent: Math.round(coverageRaw),
            ratedHoursPerDay: rated,
            level,
            rangeStart,
            rangeEnd: effectiveEnd
        });

    } catch (error) {
        console.error("Lỗi tính hiệu suất:", error);
        res.status(500).json({ message: 'Lỗi tính toán.' });
    }
});
// 10.9. API CHO TÍNH NĂNG BÁO CÁO (TÍNH NĂNG MỚI)
// =================================================================
router.get('/api/reports/monthly-summary', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;

        if (!startDate || !endDate) {
            return res.status(400).json({ message: 'Vui lòng cung cấp ngày bắt đầu và ngày kết thúc.' });
        }

        if (!isValidDateStr(startDate) || !isValidDateStr(endDate) || startDate > endDate) {
            return res.status(400).json({ message: 'Khoảng ngày không hợp lệ.' });
        }

        // Mốc đầu/cuối ngày tính theo GIỜ VIỆT NAM (server chạy giờ UTC nên không dùng setHours trực tiếp)
        const start = startInstant(startDate);
        const end = new Date(startInstant(addDays(endDate, 1)).getTime() - 1);

        const results = await Incident.aggregate([
            {
                $match: {
                    createdAt: {
                        $gte: start,
                        $lte: end
                    }
                }
            },
            {
                $facet: {
                    "totalIncidents": [
                        { $count: "count" }
                    ],
                    "resolvedIncidents": [
                        { $match: { status: 'resolved' } },
                        { $count: "count" }
                    ],
                    "incidentsByDepartment": [
                        {
                            $group: {
                                _id: "$departmentKey",
                                count: { $sum: 1 }
                            }
                        },
                        {
                            $sort: { count: -1 }
                        }
                    ]
                }
            }
        ]); // <--- Đã sửa lỗi ở đây
        
        const summary = {
            totalIncidents: results[0].totalIncidents[0] ? results[0].totalIncidents[0].count : 0,
            resolvedIncidents: results[0].resolvedIncidents[0] ? results[0].resolvedIncidents[0].count : 0,
            incidentsByDepartment: results[0].incidentsByDepartment.map(dept => ({
                departmentKey: dept._id,
                departmentName: departments[dept._id] || 'Không xác định',
                count: dept.count
            }))
        };

        res.json(summary);

    } catch (error) {
        console.error("Lỗi khi tạo báo cáo:", error);
        res.status(500).json({ message: 'Lỗi server khi tạo báo cáo.' });
    }
});

module.exports = router;
