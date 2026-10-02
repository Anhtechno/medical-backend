const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const Incident = require('../models/Incident');
const Maintenance = require('../models/Maintenance');
const { authenticateToken } = require('../middleware/auth');

// 10.5. API CHO TRANG DASHBOARD
router.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
    try {
        const [
            equipmentStats,
            newIncidentsCount,
            upcomingMaintenanceCount,
            recentActivities
        ] = await Promise.all([
            Equipment.aggregate([
                { $group: { _id: '$status', count: { $sum: 1 } } }
            ]),
            Incident.countDocuments({ status: 'new' }),
            Maintenance.countDocuments({ 
                status: { $in: ['scheduled', 'in_progress'] },
                scheduleDate: { $gte: new Date() } 
            }),
            Promise.all([
                Incident.find().sort({ createdAt: -1 }).limit(5).lean(),
                Maintenance.find().sort({ createdAt: -1 }).limit(5).lean()
            ]).then(([incidents, maintenances]) => {
                const activities = [
                    ...incidents.map(i => ({ ...i, type: 'incident', date: i.createdAt })),
                    ...maintenances.map(m => ({ ...m, type: 'maintenance', date: m.createdAt }))
                ];
                return activities.sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 5);
            })
        ]);

        const formattedStats = equipmentStats.reduce((acc, curr) => {
            if (curr._id) {
                acc[curr._id] = curr.count;
            }
            return acc;
        }, { active: 0, maintenance: 0, inactive: 0 });

        res.json({
            equipmentStats: formattedStats,
            newIncidentsCount,
            upcomingMaintenanceCount,
            recentActivities
        });

    } catch (error) {
        console.error("Lỗi khi lấy dữ liệu dashboard:", error);
        res.status(500).json({ message: 'Lỗi server khi lấy dữ liệu cho dashboard' });
    }
});
// =================================================================
// 10.11. API CHO DASHBOARD CỦA USER (TÍNH NĂNG MỚI)
// =================================================================
router.get('/api/dashboards/user', authenticateToken, async (req, res) => {
    try {
        const departmentKey = req.user.departmentKey;
        
        // --- LOG DEBUG ---
        console.log(`--- [DEBUG] Bắt đầu lấy dữ liệu Dashboard cho khoa: ${departmentKey} ---`);
        
        if (!departmentKey) {
            console.log('--- [DEBUG] Lỗi: User không có departmentKey.');
            return res.status(400).json({ message: 'Tài khoản không được gán vào khoa nào.' });
        }

        const [
            equipmentStats,
            incidentsInProgressCount,
            upcomingMaintenance
        ] = await Promise.all([
            Equipment.aggregate([
                { $match: { department: departmentKey } },
                { $group: { _id: '$status', count: { $sum: 1 } } }
            ]),
            Incident.countDocuments({ departmentKey: departmentKey, status: { $in: ['new', 'in_progress'] } }),
            Maintenance.find({ 
                departmentKey: departmentKey,
                status: { $in: ['scheduled', 'in_progress'] },
                scheduleDate: { $gte: new Date() }
            }).sort({ scheduleDate: 1 }).limit(5).lean()
        ]);
        
        // --- LOG DEBUG ---
        console.log('[DEBUG] Kết quả Equipment.aggregate:', JSON.stringify(equipmentStats));
        console.log('[DEBUG] Kết quả Incident.countDocuments:', incidentsInProgressCount);
        console.log('[DEBUG] Kết quả Maintenance.find:', JSON.stringify(upcomingMaintenance));

        const formattedStats = equipmentStats.reduce((acc, curr) => {
            if (curr._id) acc[curr._id] = curr.count;
            return acc;
        }, { active: 0, maintenance: 0, inactive: 0 });
        const totalEquipment = formattedStats.active + formattedStats.maintenance + formattedStats.inactive;

        const responsePayload = {
            totalEquipment,
            incidentsInProgressCount,
            equipmentStatusStats: formattedStats,
            upcomingMaintenance
        };
        
        // --- LOG DEBUG ---
        console.log('[DEBUG] Dữ liệu gửi về cho frontend:', JSON.stringify(responsePayload));
        console.log('--- [DEBUG] Kết thúc ---');
        
        res.json(responsePayload);

    } catch (error) {
        console.error("--- [DEBUG] LỖI TRONG QUÁ TRÌNH XỬ LÝ ---:", error);
        res.status(500).json({ message: 'Lỗi server khi tạo dashboard.' });
    }
});

module.exports = router;
