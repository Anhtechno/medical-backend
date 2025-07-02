// =================================================================
// FILE: server.js - PHIÊN BẢN HOÀN CHỈNH (CÓ CRUD BẢO TRÌ, DASHBOARD, HỒ SƠ)
// =================================================================

// 1. KHAI BÁO THƯ VIỆN
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 2. KHỞI TẠO ỨNG DỤNG VÀ CÁC BIẾN MÔI TRƯỜNG
const app = express();
const PORT = 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// 3. CẤU HÌNH MIDDLEWARE
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 4. KẾT NỐI VỚI MONGODB
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Đã kết nối thành công tới MongoDB Atlas!'))
    .catch(err => console.error('!!! LỖI KẾT NỐI MONGODB:', err));

// 5. ĐỊNH NGHĨA SCHEMAS & MODELS
const equipmentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    serial: { type: String, required: true, unique: true },
    manufacturer: String, accessories: String, year: String, status: String,
    description: String, image: String, department: { type: String, required: true }
});
const Equipment = mongoose.models.Equipment || mongoose.model('Equipment', equipmentSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['admin', 'user'], default: 'user' },
    departmentKey: { type: String } 
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

const incidentSchema = new mongoose.Schema({
    equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Equipment', required: true },
    equipmentName: { type: String, required: true },
    serial: { type: String, required: true },
    departmentKey: { type: String, required: true },
    reportedBy: { type: String, required: true },
    problemDescription: { type: String, required: true },
    status: { type: String, enum: ['new', 'in_progress', 'resolved'], default: 'new' },
    notes: String,
    resolvedAt: Date,
    isRead: { type: Boolean, default: false }
}, { timestamps: true });
const Incident = mongoose.models.Incident || mongoose.model('Incident', incidentSchema);

const maintenanceSchema = new mongoose.Schema({
    equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Equipment', required: true },
    equipmentName: { type: String, required: true },
    serial: { type: String, required: true },
    departmentKey: { type: String, required: true },
    
    type: { type: String, enum: ['periodic', 'ad-hoc'], default: 'ad-hoc' },

    scheduleDate: { type: Date, required: true },
    completionDate: { type: Date },
    
    technician: { type: String },
    notes: { type: String },
    cost: { type: Number, default: 0 },
    
    status: { 
        type: String, 
        enum: ['scheduled', 'in_progress', 'completed', 'canceled'], 
        default: 'scheduled' 
    },
    
    createdBy: { type: String, required: true }
}, { timestamps: true });
const Maintenance = mongoose.models.Maintenance || mongoose.model('Maintenance', maintenanceSchema);


const departments = { 'bvsk_tw_2b': 'Phòng Bảo vệ sức khỏe Trung ương 2B', 'cap_cuu': 'Khoa Cấp cứu', 'kham_benh': 'Khoa Khám bệnh', 'kham_benh_yc': 'Khoa Khám bệnh theo yêu cầu', 'noi_than_loc_mau': 'Khoa Nội thận – Lọc máu', 'dinh_duong_ls': 'Khoa Dinh dưỡng lâm sàng', 'phuc_hoi_cn': 'Khoa Phục hồi chức năng', 'icu': 'Khoa Hồi sức tích cực – Chống độc', 'phau_thuat_gmhs': 'Khoa Phẫu thuật – Gây mê hồi sức', 'ngoai_ctch': 'Khoa Ngoại chấn thương chỉnh hình', 'ngoai_tieu_hoa': 'Khoa Ngoại tiêu hoá', 'ngoai_gan_mat': 'Khoa Ngoại gan mật', 'noi_tiet': 'Khoa Nội tiết', 'ngoai_tim_mach_ln': 'Khoa Ngoại tim mạch – Lồng ngực', 'noi_tim_mach': 'Khoa Nội tim mạch', 'tim_mach_cc_ct': 'Khoa Tim mạch cấp cứu và can thiệp', 'noi_than_kinh': 'Khoa Nội thần kinh', 'loan_nhip_tim': 'Khoa Loạn nhịp tim', 'ngoai_than_kinh': 'Khoa Ngoại thần kinh', 'ngoai_than_tn': 'Khoa Ngoại thận – Tiết niệu', 'dieu_tri_cbcc': 'Khoa Điều trị Cán bộ cao cấp', 'noi_cxk': 'Khoa Nội cơ xương khớp', 'noi_dieu_tri_yc': 'Khoa Nội điều trị theo yêu cầu', 'noi_tieu_hoa_2': 'Khoa Nội tiêu hoá', 'noi_ho_hap': 'Khoa Nội hô hấp', 'mat': 'Khoa Mắt', 'tai_mui_hong': 'Khoa Tai mũi họng', 'pt_hm_thtm': 'Khoa Phẫu thuật hàm mặt – Tạo hình thẩm mỹ', 'ung_buou': 'Khoa Ung bướu', 'noi_nhiem': 'Khoa Nội nhiễm', 'y_hoc_co_truyen': 'Khoa Y học cổ truyền', 'ngoai_dieu_tri_yc': 'Khoa Ngoại điều trị theo yêu cầu', 'da_lieu_md_du': 'Khoa Da liễu – Miễn dịch – Dị ứng' };


// 6. API XÁC THỰC
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, role, departmentKey } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Vui lòng nhập đủ tên đăng nhập và mật khẩu." });
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ username, password: hashedPassword, role, departmentKey });
        await newUser.save();
        res.status(201).json({ message: "Đăng ký tài khoản thành công!" });
    } catch (error) { res.status(500).json({ message: "Lỗi server khi đăng ký.", error: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });
        const token = jwt.sign({ userId: user._id, username: user.username, role: user.role, departmentKey: user.departmentKey }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ message: "Đăng nhập thành công!", token });
    } catch (error) { res.status(500).json({ message: "Lỗi server khi đăng nhập.", error: error.message }); }
});

// 7. MIDDLEWARE "BẢO VỆ"
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Không có quyền thực hiện hành động này." });
    next();
};

// 8. API QUẢN LÝ THIẾT BỊ
app.get('/api/departments', authenticateToken, (req, res) => {
    if (req.user.role === 'admin') return res.json(departments);
    const userDept = {};
    if (req.user.departmentKey && departments[req.user.departmentKey]) {
        userDept[req.user.departmentKey] = departments[req.user.departmentKey];
    }
    res.json(userDept);
});

app.get('/api/equipment/:deptKey', authenticateToken, async (req, res) => {
    try {
        const { deptKey } = req.params;
        if (req.user.role === 'user' && req.user.departmentKey !== deptKey) {
            return res.status(403).json({ message: "Không có quyền xem dữ liệu của khoa này." });
        }
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const status = req.query.status;
        const skip = (page - 1) * limit;
        const queryForPagination = { department: deptKey };
        if (status && status !== 'all') {
            queryForPagination.status = status;
        }
        const equipmentsPromise = Equipment.find(queryForPagination).sort({ name: 1 }).skip(skip).limit(limit);
        const totalItemsPromise = Equipment.countDocuments(queryForPagination);
        const statsPromise = Equipment.aggregate([
            { $match: { department: deptKey } }, 
            { $group: { _id: '$status', count: { $sum: 1 } } } 
        ]);
        const [equipments, totalItems, statsResult] = await Promise.all([
            equipmentsPromise,
            totalItemsPromise,
            statsPromise
        ]);
        const stats = statsResult.reduce((acc, curr) => {
            if (curr._id) { acc[curr._id] = curr.count; }
            return acc;
        }, {});
        const totalPages = Math.ceil(totalItems / limit);
        res.json({
            equipments, totalPages, currentPage: page,
            totalItems, stats 
        });
    } catch (error) {
        console.error("Lỗi khi lấy dữ liệu equipment:", error);
        res.status(500).json({ message: 'Lỗi server khi lấy dữ liệu', error: error.message });
    }
});

app.post('/api/equipment/:deptKey', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { deptKey } = req.params;
        const newEquipmentData = { ...req.body, department: deptKey };
        const existing = await Equipment.findOne({ serial: newEquipmentData.serial });
        if (existing) return res.status(400).json({ message: `Số serial "${newEquipmentData.serial}" đã tồn tại.` });
        const equipment = new Equipment(newEquipmentData);
        await equipment.save();
        res.status(201).json(equipment);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi thêm thiết bị', error: error.message }); }
});

app.delete('/api/equipment/:deptKey/:serial', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { serial } = req.params;
        const deletedEquipment = await Equipment.findOneAndDelete({ serial: serial });
        if (!deletedEquipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        res.json({ message: "Xóa thành công." });
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi xóa', error: error.message }); }
});

app.get('/api/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.status(400).json({ message: "Cần có từ khóa tìm kiếm." });
        const searchTerm = q.toLowerCase();
        let query = { $or: [ { name: { $regex: searchTerm, $options: 'i' } },{ serial: { $regex: searchTerm, $options: 'i' } },{ manufacturer: { $regex: searchTerm, $options: 'i' } }] };
        if (req.user.role === 'user') { query.department = req.user.departmentKey; }
        const results = await Equipment.find(query);
        res.json(results);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi tìm kiếm', error: error.message }); }
});

app.get('/api/equipment/item/:serial', authenticateToken, async (req, res) => {
    try {
        const serialToFind = req.params.serial.trim();
        const equipment = await Equipment.findOne({ serial: new RegExp('^' + serialToFind + '$', 'i') });
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị với số serial này." });
        res.json(equipment);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi lấy chi tiết thiết bị', error: error.message }); }
});

app.put('/api/equipment/:deptKey/:serial', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { serial } = req.params;
        const updatedData = req.body;
        const updatedEquipment = await Equipment.findOneAndUpdate({ serial: serial }, updatedData, { new: true });
        if (!updatedEquipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        res.json(updatedEquipment);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi cập nhật', error: error.message }); }
});

// 9. API CHO BÁO CÁO SỰ CỐ
app.post('/api/incidents', authenticateToken, async (req, res) => {
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
        res.status(201).json(newIncident);
    } catch (error) {
        console.error("Lỗi khi tạo báo cáo sự cố:", error);
        res.status(500).json({ message: 'Lỗi server khi tạo báo cáo sự cố', error: error.message });
    }
});

app.get('/api/incidents', authenticateToken, async (req, res) => {
    try {
        let query = {};
        if (req.user.role === 'user') {
            query.departmentKey = req.user.departmentKey;
        }
        const incidents = await Incident.find(query).sort({ createdAt: -1 });
        res.json(incidents);
    } catch (error) {
        console.error("Lỗi khi lấy danh sách sự cố:", error);
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách sự cố', error: error.message });
    }
});

app.put('/api/incidents/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, notes } = req.body;
        const updateData = { status, notes, isRead: true };
        if (status === 'resolved') {
            updateData.resolvedAt = new Date();
        }
        const updatedIncident = await Incident.findByIdAndUpdate(id, updateData, { new: true });
        if (!updatedIncident) return res.status(404).json({ message: "Không tìm thấy báo cáo sự cố." });
        res.json(updatedIncident);
    } catch (error) {
        console.error("Lỗi khi cập nhật sự cố:", error);
        res.status(500).json({ message: 'Lỗi server khi cập nhật sự cố', error: error.message });
    }
});

app.get('/api/incidents/unread/count', authenticateToken, isAdmin, async (req, res) => {
    try {
        const count = await Incident.countDocuments({ isRead: false });
        res.json({ count });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi đếm sự cố' });
    }
});

app.get('/api/incidents/unread', authenticateToken, isAdmin, async (req, res) => {
    try {
        const incidents = await Incident.find({ isRead: false }).sort({ createdAt: -1 }).limit(5);
        res.json(incidents);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách sự cố chưa đọc' });
    }
});

// 10. API QUẢN LÝ BẢO TRÌ
app.post('/api/maintenance', authenticateToken, isAdmin, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server khi tạo lịch bảo trì', error: error.message });
    }
});

app.get('/api/maintenance', authenticateToken, async (req, res) => {
    try {
        let query = {};
        if (req.user.role === 'user') {
            query.departmentKey = req.user.departmentKey;
        }
        const maintenanceSchedules = await Maintenance.find(query).sort({ scheduleDate: -1 });
        res.json(maintenanceSchedules);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách bảo trì', error: error.message });
    }
});

app.get('/api/maintenance/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const maintenance = await Maintenance.findById(req.params.id);
        if (!maintenance) {
            return res.status(404).json({ message: 'Không tìm thấy lịch bảo trì.' });
        }
        res.json(maintenance);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy chi tiết bảo trì', error: error.message });
    }
});

app.put('/api/maintenance/:id', authenticateToken, isAdmin, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server khi cập nhật lịch bảo trì', error: error.message });
    }
});

app.delete('/api/maintenance/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedMaintenance = await Maintenance.findByIdAndDelete(id);
        if (!deletedMaintenance) return res.status(404).json({ message: "Không tìm thấy lịch bảo trì." });
        res.json({ message: "Xóa lịch bảo trì thành công." });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa lịch bảo trì', error: error.message });
    }
});

// 10.5. API CHO TRANG DASHBOARD
app.get('/api/dashboard/summary', authenticateToken, isAdmin, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server khi lấy dữ liệu cho dashboard', error: error.message });
    }
});

// 10.6. API CHO TRANG HỒ SƠ THIẾT BỊ
app.get('/api/equipment/profile/:serial', authenticateToken, isAdmin, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server khi lấy hồ sơ thiết bị', error: error.message });
    }
});

// 11. KHỞI ĐỘNG SERVER
app.listen(PORT, () => {
    console.log(`Backend đang chạy tại địa chỉ: http://localhost:${PORT}`);
});