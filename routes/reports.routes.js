const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const Incident = require('../models/Incident');
const departments = require('../data/departments');
const { authenticateToken, isAdmin } = require('../middleware/auth');

// API Báo cáo hiệu suất máy (Cho Admin xem trong modal)
router.post('/api/reports/machine-efficiency', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { equipmentId, startDate, endDate } = req.body;
        
        const equipment = await Equipment.findById(equipmentId);
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });

        const start = new Date(startDate);
        const end = new Date(endDate);
        
        // Lọc lịch sử trong khoảng thời gian
        const logsInRange = equipment.usageHistory.filter(log => {
            const logDate = new Date(log.date);
            return logDate >= start && logDate <= end;
        });

        // Tính tổng giờ
        const totalHours = logsInRange.reduce((sum, log) => sum + log.hours, 0);
        
        // Tính số ngày trong khoảng (bao gồm cả ngày bắt đầu và kết thúc)
        const diffTime = Math.abs(end - start);
        const totalDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1; 

        // Tính trung bình
        const avgHoursPerDay = totalDays > 0 ? (totalHours / totalDays).toFixed(1) : 0;
        const efficiencyPercent = ((avgHoursPerDay / 24) * 100).toFixed(1);

        res.json({
            equipmentName: equipment.name,
            totalHours,
            totalDays,
            avgHoursPerDay,
            efficiencyPercent,
            logsCount: logsInRange.length // Số ngày thực tế có nhập liệu
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

        const start = new Date(startDate);
        start.setHours(0, 0, 0, 0);

        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);

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
