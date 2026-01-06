// =================================================================
// FILE: server.js - PHIÊN BẢN HOÀN CHỈNH (CÓ TÍNH NĂNG IMPORT EXCEL & SỬA LỖI EDIT)
// =================================================================

// 1. KHAI BÁO THƯ VIỆN
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');
//const { GoogleGenerativeAI } = require("@google/generative-ai");
//const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Cấu hình Cloudinary bằng các biến môi trường chúng ta đã thêm
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Thiết lập nơi lưu trữ file cho multer
// Thay thế toàn bộ khối const storage cũ bằng phiên bản này


const upload = multer({ storage: multer.memoryStorage() });

// 2. KHỞI TẠO ỨNG DỤNG VÀ CÁC BIẾN MÔI TRƯỜNG
const app = express();
const PORT = 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// 3. CẤU HÌNH MIDDLEWARE
const corsOptions = {
    origin: 'https://resilient-dieffenbachia-5881b7.netlify.app',
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
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
    description: String, image: String, department: { type: String, required: true },
    
    dailyUsage: { type: Number, default: 0, min: 0, max: 24 },
    lastLogDate: { type: String, default: '' }, // Lưu ngày cập nhật cuối (dạng YYYY-MM-DD)
    usageHistory: [{ // Mảng lưu lịch sử dùng để tính báo cáo
        date: String, // YYYY-MM-DD
        hours: Number
    }]
});
const Equipment = mongoose.models.Equipment || mongoose.model('Equipment', equipmentSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    // Thêm role 'technician'
    role: { type: String, required: true, enum: ['admin', 'user', 'technician'], default: 'user' },
    departmentKey: { type: String }, // Dùng cho User khoa phòng
    fullName: { type: String }, // Tên hiển thị (Dành cho Kỹ sư)
    avatar: { type: String } // Link ảnh đại diện (Dành cho Kỹ sư)
}, { timestamps: true });
const User = mongoose.models.User || mongoose.model('User', userSchema);

const incidentSchema = new mongoose.Schema({
    equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Equipment', required: true },
    equipmentName: { type: String, required: true },
    serial: { type: String, required: true },
    departmentKey: { type: String, required: true },
    reportedBy: { type: String, required: true },
    problemDescription: { type: String, required: true },
    status: { type: String, enum: ['new', 'in_progress', 'resolved'], default: 'new' },
    notes: String, // Ghi chú chung
    resolvedAt: Date,
    isRead: { type: Boolean, default: false },
    // Thêm trường người được giao việc
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    assignedByName: { type: String } // Tên người giao việc (Admin)
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


const departments = {
    // === KHỐI LÂM SÀNG ===
    'cap_cuu': 'Khoa Cấp cứu',
    'kham_benh': 'Khoa Khám bệnh',
    'kham_benh_yc': 'Khoa Khám bệnh theo yêu cầu',
    'icu': 'Khoa Hồi sức tích cực – Chống độc',
    'noi_nhiem': 'Khoa Nội nhiễm',
    'noi_tiet': 'Khoa Nội tiết',
    'noi_cxk': 'Khoa Nội cơ xương khớp',
    'noi_than_kinh': 'Khoa Nội thần kinh',
    'noi_tim_mach': 'Khoa Nội tim mạch',
    'tim_mach_cc_ct': 'Khoa Tim mạch cấp cứu và can thiệp',
    'loan_nhip_tim': 'Khoa Loạn nhịp tim',
    'noi_than_loc_mau': 'Khoa Nội thận – Lọc máu',
    'noi_ho_hap': 'Khoa Nội hô hấp',
    'noi_tieu_hoa': 'Khoa Nội tiêu hoá',
    'ung_buou': 'Khoa Ung bướu',
    'dieu_tri_cbcc': 'Khoa Điều trị Cán bộ cao cấp',
    'noi_dieu_tri_yc': 'Khoa Nội điều trị theo yêu cầu',
    'ngoai_dieu_tri_yc': 'Khoa Ngoại điều trị theo yêu cầu',
    'ngoai_ctch': 'Khoa Ngoại chấn thương chỉnh hình',
    'ngoai_gan_mat': 'Khoa Ngoại gan mật',
    'ngoai_than_kinh': 'Khoa Ngoại thần kinh',
    'ngoai_than_tn': 'Khoa Ngoại thận – Tiết niệu',
    'ngoai_tieu_hoa': 'Khoa Ngoại tiêu hoá',
    'ngoai_tim_mach_ln': 'Khoa Ngoại tim mạch – Lồng ngực',
    'phau_thuat_gmhs': 'Khoa Phẫu thuật – Gây mê hồi sức',
    'pt_hm_thtm': 'Khoa Phẫu thuật hàm mặt – Tạo hình thẩm mỹ',
    'mat': 'Khoa Mắt',
    'tai_mui_hong': 'Khoa Tai mũi họng',
    'da_lieu_md_du': 'Khoa Da liễu – Miễn dịch – Dị ứng',
    'y_hoc_co_truyen': 'Khoa Y học cổ truyền',
    'phuc_hoi_cn': 'Khoa Phục hồi chức năng',
    
    // === KHỐI CẬN LÂM SÀNG (ĐÃ THÊM MỚI) ===
    'chan_doan_ha': 'Khoa Chẩn đoán hình ảnh',
    'tham_do_cn_ns': 'Khoa Thăm dò chức năng và Nội soi',
    'hoa_sinh': 'Khoa Hóa sinh',
    'vi_sinh': 'Khoa Vi sinh',
    'huyet_hoc': 'Khoa Huyết học',
    'giai_phau_benh': 'Khoa Giải phẫu bệnh',

    // === KHỐI HẬU CẦN & CÁC PHÒNG BAN ===
    'duoc': 'Khoa Dược',
    'dinh_duong_ls': 'Khoa Dinh dưỡng lâm sàng',
    'kiem_soat_nk': 'Khoa Kiểm soát nhiễm khuẩn',
    'bvsk_tw_2b': 'Phòng Bảo vệ sức khỏe Trung ương 2B'
};

const usageLogSchema = new mongoose.Schema({
    equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Equipment', required: true },
    equipmentName: { type: String, required: true }, // Thêm tên và serial để tiện tra cứu
    serial: { type: String, required: true },
    departmentKey: { type: String, required: true },
    loggedBy: { type: String, required: true },
    status: { 
        type: String, 
        required: true,
        enum: ['operational', 'minor_issue', 'not_in_use'] 
        // operational: Hoạt động tốt
        // minor_issue: Có vấn đề nhỏ
        // not_in_use: Không sử dụng
    },
    notes: { type: String, default: '' },
}, { timestamps: true });
const UsageLog = mongoose.models.UsageLog || mongoose.model('UsageLog', usageLogSchema);

const documentSchema = new mongoose.Schema({
    equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Equipment', required: true },
    fileName: { type: String, required: true },
    fileUrl: { type: String, required: true },
    cloudinaryId: { type: String, required: true }, // Để sau này có thể xóa file trên Cloudinary
    documentType: { 
        type: String, 
        required: true,
        enum: ['contract', 'co', 'cq', 'inspection', 'other'] 
    },
    uploadedBy: { type: String, required: true }
}, { timestamps: true });
const Document = mongoose.models.Document || mongoose.model('Document', documentSchema);

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
app.get('/api/equipment/:deptKey', authenticateToken, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server khi xóa', error: error.message });
    }
});

app.get('/api/search', authenticateToken, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server khi tìm kiếm', error: error.message });
    }
});

app.get('/api/equipment/item/:serial', authenticateToken, async (req, res) => {
    try {
        const serialToFind = req.params.serial.trim();
        const equipment = await Equipment.findOne({ serial: new RegExp('^' + serialToFind + '$', 'i') });
        if (!equipment) return res.status(404).json({ message: "Không tìm thấy thiết bị với số serial này." });
        res.json(equipment);
    } catch (error) { res.status(500).json({ message: 'Lỗi server khi lấy chi tiết thiết bị', error: error.message }); }
});

// API Báo cáo hiệu suất máy (Cho Admin xem trong modal)
app.post('/api/reports/machine-efficiency', authenticateToken, isAdmin, async (req, res) => {
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


// API Cập nhật giờ sử dụng (Hiệu suất)
app.put('/api/equipment/usage/:id', authenticateToken, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server.', error: error.message });
    }
});


app.put('/api/equipment/:deptKey/:serial', authenticateToken, isAdmin, async (req, res) => {
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
        res.status(500).json({ message: 'Lỗi server khi cập nhật', error: error.message });
    }
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

app.put('/api/incidents/:id', authenticateToken, async (req, res) => {
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

app.delete('/api/incidents/:id', authenticateToken, isAdmin, async (req, res) => {
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
app.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
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
app.get('/api/equipment/profile/:serial', authenticateToken, async (req, res) => {
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

// 10.7. API QUẢN LÝ NGƯỜI DÙNG
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find({ role: 'user' }).sort({ username: 1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách người dùng.' });
    }
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { username, password, departmentKey } = req.body;
        if (!username || !password || !departmentKey) {
            return res.status(400).json({ message: "Vui lòng nhập đủ Tên đăng nhập, Mật khẩu và Khoa." });
        }
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({
            username,
            password: hashedPassword,
            role: 'user',
            departmentKey
        });
        await newUser.save();
        res.status(201).json(newUser);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi tạo người dùng.' });
    }
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { departmentKey, password } = req.body;
        const updateData = { departmentKey };

        if (password && password.length > 0) {
            updateData.password = await bcrypt.hash(password, 12);
        }

        const updatedUser = await User.findByIdAndUpdate(id, updateData, { new: true });
        if (!updatedUser) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
        }
        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi cập nhật người dùng.' });
    }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
        }
        res.json({ message: 'Xóa người dùng thành công.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa người dùng.' });
    }
});

// --- API MỚI: TẠO TÀI KHOẢN KỸ SƯ (CÓ UPLOAD AVATAR) ---
app.post('/api/technicians', authenticateToken, isAdmin, upload.single('avatar'), async (req, res) => {
    try {
        const { username, password, fullName } = req.body;
        if (!username || !password || !fullName) {
            return res.status(400).json({ message: "Vui lòng nhập đủ: Tên đăng nhập, Mật khẩu, Họ tên." });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });

        let avatarUrl = null;
        // Xử lý upload ảnh nếu có
        if (req.file) {
            const uploadResult = await new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream(
                    { folder: 'avatars', resource_type: 'image' },
                    (error, result) => { if (error) reject(error); else resolve(result); }
                );
                uploadStream.end(req.file.buffer);
            });
            avatarUrl = uploadResult.secure_url;
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newTech = new User({
            username,
            password: hashedPassword,
            role: 'technician',
            fullName,
            avatar: avatarUrl
        });
        await newTech.save();
        res.status(201).json(newTech);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi tạo kỹ sư.', error: error.message });
    }
});

// --- API MỚI: LẤY DANH SÁCH KỸ SƯ (ĐỂ ADMIN CHỌN) ---
app.get('/api/technicians', authenticateToken, async (req, res) => {
    try {
        // Chỉ lấy role technician, trả về id, username, fullName, avatar
        const techs = await User.find({ role: 'technician' }).select('_id username fullName avatar');
        res.json(techs);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi lấy danh sách kỹ sư.' });
    }
});

// --- API MỚI: PHÂN CÔNG SỰ CỐ (ASSIGN) ---
app.put('/api/incidents/assign/:id', authenticateToken, isAdmin, async (req, res) => {
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

// 10.8. API NHẬP DỮ LIỆU HÀNG LOẠT TỪ EXCEL
app.post('/api/equipment/batch-import/:deptKey', authenticateToken, isAdmin, async (req, res) => {
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
            return res.status(500).json({ message: 'Đã có lỗi nghiêm trọng xảy ra.', details: error.message });
        }
    }

    res.status(201).json({
        message: `Hoàn tất! Thêm thành công ${successCount} thiết bị. Thất bại: ${failedCount} thiết bị.`,
        successCount,
        failedCount,
        errors
    });
});
// 10.9. PUBLIC APIS FOR QR CODE REPORTING (TÍNH NĂNG MỚI)
// =================================================================

// API công khai để lấy thông tin cơ bản của thiết bị bằng serial
// API công khai để lấy thông tin CHI TIẾT của thiết bị
app.get('/api/public/equipment-details/:serial', async (req, res) => {
    try {
        const { serial } = req.params;
        // Lấy nhiều trường hơn để hiển thị công khai
        const equipment = await Equipment.findOne({ serial: serial }, 'name serial department manufacturer year status'); 
        if (!equipment) {
            return res.status(404).json({ message: 'Không tìm thấy thiết bị với số serial này.' });
        }
        // Trả về tên khoa thay vì mã khoa
        const equipmentWithDeptName = {
            ...equipment.toObject(),
            departmentName: departments[equipment.department] || 'Không xác định'
        };
        res.json(equipmentWithDeptName);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

// API công khai để người dùng báo hỏng từ QR code
app.post('/api/public/incidents', async (req, res) => {
    try {
        const { equipmentSerial, problemDescription, reporterName } = req.body; // Thêm reporterName
        if (!equipmentSerial || !problemDescription || !reporterName) {
            return res.status(400).json({ message: "Vui lòng cung cấp đủ thông tin sự cố và tên người báo hỏng." });
        }
        const equipment = await Equipment.findOne({ serial: equipmentSerial });
        if (!equipment) {
            return res.status(404).json({ message: "Thiết bị không tồn tại trong hệ thống." });
        }

        const newIncident = new Incident({
            equipmentId: equipment._id,
            equipmentName: equipment.name,
            serial: equipment.serial,
            departmentKey: equipment.department,
            problemDescription: problemDescription,
            reportedBy: reporterName // Sử dụng tên người báo hỏng
        });

        await newIncident.save();
        res.status(201).json({ message: "Báo cáo sự cố đã được gửi thành công!" });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi tạo báo cáo sự cố' });
    }
});
// 10.9. API CHO TÍNH NĂNG BÁO CÁO (TÍNH NĂNG MỚI)
// =================================================================
app.get('/api/reports/monthly-summary', authenticateToken, isAdmin, async (req, res) => {
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

// 10.10. API CHO NHẬT KÝ SỬ DỤNG (TÍNH NĂNG MỚI)
// =================================================================

// API để khoa/phòng tạo một nhật ký sử dụng mới
app.post('/api/logs', authenticateToken, async (req, res) => {
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
app.get('/api/logs/equipment/:equipmentId', authenticateToken, isAdmin, async (req, res) => {
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
// 10.11. API CHO DASHBOARD CỦA USER (TÍNH NĂNG MỚI)
// =================================================================
app.get('/api/dashboards/user', authenticateToken, async (req, res) => {
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

// =================================================================
// 10.12. API DEBUG (CHẨN ĐOÁN LỖI)
// =================================================================
app.get('/api/debug/list-departments', async (req, res) => {
    try {
        console.log("--- [DEBUG] Bắt đầu chạy API chẩn đoán ---");
        // Lấy ra tất cả các giá trị 'department' duy nhất trong collection 'equipments'
        const distinctDepartments = await Equipment.distinct('department');
        
        console.log("--- [DEBUG] Các mã khoa tìm thấy trong database:", distinctDepartments);
        res.json({
            message: "Đây là danh sách tất cả các mã khoa (department key) mà server tìm thấy trong collection 'equipments'.",
            foundDepartments: distinctDepartments
        });

    } catch (error) {
        console.error("--- [DEBUG] Lỗi khi chạy API chẩn đoán ---:", error);
        res.status(500).json({ message: 'Lỗi server khi chạy chẩn đoán.' });
    }
});

// =================================================================
// 10.13. API GHI NHẬT KÝ HÀNG LOẠT (TÍNH NĂNG MỚI)
// =================================================================
app.post('/api/logs/bulk', authenticateToken, async (req, res) => {
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

// 10.14. API QUẢN LÝ TÀI LIỆU (TÍNH NĂNG MỚI)
// =================================================================

// Lấy danh sách tài liệu của một thiết bị
app.get('/api/documents/:equipmentId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { equipmentId } = req.params;
        const documents = await Document.find({ equipmentId: equipmentId }).sort({ createdAt: -1 });
        res.json(documents);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách tài liệu.' });
    }
});

// Upload một tài liệu mới
// Thay thế toàn bộ hàm app.post('/api/documents/upload...) cũ bằng hàm này
app.post('/api/documents/upload/:equipmentId', authenticateToken, isAdmin, upload.single('document'), async (req, res) => {
    try {
        const { equipmentId } = req.params;
        const { documentType } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ message: 'Không có file nào được tải lên.' });
        }

        // Tải file lên Cloudinary từ bộ nhớ đệm (buffer)
        const uploadResult = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                {
                    folder: 'equipment_documents',
                    resource_type: 'auto'
                },
                (error, result) => {
                    if (error) {
                        return reject(error);
                    }
                    resolve(result);
                }
            );
            uploadStream.end(req.file.buffer);
        });

        const newDocument = new Document({
            equipmentId: equipmentId,
            fileName: req.file.originalname,
            fileUrl: uploadResult.secure_url, // Lấy URL an toàn và chính xác từ kết quả
            cloudinaryId: uploadResult.public_id,
            documentType: documentType,
            uploadedBy: req.user.username
        });

        await newDocument.save();
        res.status(201).json(newDocument);

    } catch (error) {
        console.error("Lỗi khi upload tài liệu:", error);
        res.status(500).json({ message: 'Lỗi server khi upload tài liệu.' });
    }
});

// Xóa một tài liệu
app.delete('/api/documents/:documentId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { documentId } = req.params;
        const docToDelete = await Document.findById(documentId);

        if (!docToDelete) {
            return res.status(404).json({ message: 'Không tìm thấy tài liệu.' });
        }

        // Xóa file trên Cloudinary
        await cloudinary.uploader.destroy(docToDelete.cloudinaryId);
        
        // Xóa bản ghi trong database
        await Document.findByIdAndDelete(documentId);

        res.json({ message: 'Xóa tài liệu thành công.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa tài liệu.' });
    }
});

// --- API CHAT VỚI AI (SỬA LỖI 404: DÙNG MODEL GEMINI-PRO) ---
app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        const dbContext = await getSystemContext();

        // CẤU HÌNH GỌI TRỰC TIẾP
        const API_KEY = process.env.GEMINI_API_KEY;
        // ĐỔI SANG 'gemini-pro' ĐỂ ĐẢM BẢO KHÔNG BỊ LỖI 404
        const MODEL_NAME = "gemini-pro"; 
        const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent?key=${API_KEY}`;

        const payload = {
            contents: [{
                parts: [{ text: `${dbContext}\n----------------\nCÂU HỎI: "${message}"\nTRẢ LỜI NGẮN GỌN:` }]
            }]
        };

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Google từ chối: ${response.status} - ${response.statusText}`);
        }

        const data = await response.json();
        const replyText = data.candidates[0].content.parts[0].text;
        res.json({ reply: replyText });

    } catch (error) {
        console.error("Lỗi AI:", error);
        res.status(500).json({ reply: `Hệ thống đang bận. Lỗi chi tiết: ${error.message}` });
    }
});

// --- HÀM HỖ TRỢ AI: LẤY DỮ LIỆU TỔNG QUAN ---
async function getSystemContext() {
    try {
        // 1. Lấy thống kê thiết bị
        const equipment = await Equipment.find().select('name serial status department dailyUsage').lean();
        const total = equipment.length;
        const broken = equipment.filter(e => e.status === 'inactive').map(e => `${e.name} (${e.department})`);
        
        // 2. Lấy sự cố đang xử lý
        const incidents = await Incident.find({ status: 'in_progress' })
            .populate('assignedTo', 'fullName')
            .select('equipmentName departmentKey problemDescription assignedTo')
            .lean();
            
        // 3. Tạo đoạn văn bản tóm tắt dữ liệu để dạy cho AI
        const contextText = `
        DỮ LIỆU HỆ THỐNG HIỆN TẠI:
        - Tổng số thiết bị: ${total} máy.
        - Danh sách máy đang HỎNG/NGỪNG HOẠT ĐỘNG: ${broken.join(', ') || 'Không có'}.
        - Các sự cố đang chờ xử lý:
          ${incidents.map(i => `- Máy ${i.equipmentName} tại ${departments[i.departmentKey]}: Lỗi "${i.problemDescription}" (Kỹ sư phụ trách: ${i.assignedTo ? i.assignedTo.fullName : 'Chưa giao'}).`).join('\n          ')}
        
        Nhiệm vụ của bạn là Trợ lý ảo quản lý thiết bị y tế. Hãy trả lời câu hỏi của người dùng dựa trên dữ liệu trên. 
        Nếu không có trong dữ liệu, hãy nói là không tìm thấy thông tin. Trả lời ngắn gọn, súc tích bằng tiếng Việt.
        `;
        
        return contextText;
    } catch (error) {
        console.error(error);
        return "Không lấy được dữ liệu hệ thống.";
    }
}



// 11. KHỞI ĐỘNG SERVER
app.listen(PORT, () => {
    console.log(`Backend đang chạy tại địa chỉ: http://localhost:${PORT}`);
});