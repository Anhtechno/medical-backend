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

// Cấu hình Cloudinary bằng các biến môi trường chúng ta đã thêm
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Thiết lập nơi lưu trữ file cho multer
// Thay thế toàn bộ khối const storage cũ bằng phiên bản này
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'equipment_documents',
        resource_type: "auto",
        // THAY ĐỔI QUAN TRỌNG: SỬ DỤNG UPLOAD PRESET
        upload_preset: 'hoso_congkhai' 
    },
});

const upload = multer({ storage: storage });

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
    description: String, image: String, department: { type: String, required: true }
});
const Equipment = mongoose.models.Equipment || mongoose.model('Equipment', equipmentSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['admin', 'user'], default: 'user' },
    departmentKey: { type: String } 
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
        
        // --- LOGIC MỚI: TÍNH TOÁN ĐẦU TUẦN ---
        const now = new Date();
        const dayOfWeek = now.getDay(); // 0 = Sunday, 1 = Monday, etc.
        const diff = now.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1); // Lấy ngày đầu tuần (Thứ 2)
        const startOfWeek = new Date(now.setDate(diff));
        startOfWeek.setHours(0, 0, 0, 0);
        // ------------------------------------

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const status = req.query.status;
        const skip = (page - 1) * limit;
        
        const query = { department: deptKey };
        if (status && status !== 'all') {
            query.status = status;
        }

        const [equipments, totalItems, statsResult, loggedThisWeek] = await Promise.all([
            Equipment.find(query).sort({ name: 1 }).skip(skip).limit(limit).lean(),
            Equipment.countDocuments(query),
            Equipment.aggregate([ { $match: { department: deptKey } }, { $group: { _id: '$status', count: { $sum: 1 } } } ]),
            // --- LOGIC MỚI: LẤY DANH SÁCH THIẾT BỊ ĐÃ GHI NHẬT KÝ TUẦN NÀY ---
            UsageLog.find({
                departmentKey: deptKey,
                createdAt: { $gte: startOfWeek }
            }).select('equipmentId -_id') // Chỉ lấy ID thiết bị
        ]);
        
        // Tạo một set để tra cứu nhanh các ID đã ghi nhật ký
        const loggedEquipmentIds = new Set(loggedThisWeek.map(log => log.equipmentId.toString()));
        
        // Thêm trường 'needsLog' vào mỗi thiết bị
        const equipmentsWithLogStatus = equipments.map(eq => ({
            ...eq,
            needsLog: !loggedEquipmentIds.has(eq._id.toString())
        }));

        const stats = statsResult.reduce((acc, curr) => {
            if (curr._id) { acc[curr._id] = curr.count; }
            return acc;
        }, {});
        
        const totalPages = Math.ceil(totalItems / limit);
        
        res.json({
            equipments: equipmentsWithLogStatus, // Trả về danh sách đã được cập nhật
            totalPages, 
            currentPage: page,
            totalItems, 
            stats 
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

        const originalEquipment = await Equipment.findOne({ serial: serial });
        if (!originalEquipment) {
            return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        }

        const updatedEquipment = await Equipment.findByIdAndUpdate(originalEquipment._id, updatedData, { new: true });

        if (updatedData.name && updatedData.name !== originalEquipment.name) {
            await Promise.all([
                Incident.updateMany({ equipmentId: originalEquipment._id }, { equipmentName: updatedData.name }),
                Maintenance.updateMany({ equipmentId: originalEquipment._id }, { equipmentName: updatedData.name })
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
app.get('/api/public/equipment-info/:serial', async (req, res) => {
    try {
        const { serial } = req.params;
        const equipment = await Equipment.findOne({ serial: serial }, 'name serial department'); // Chỉ lấy các trường cần thiết
        if (!equipment) {
            return res.status(404).json({ message: 'Không tìm thấy thiết bị với số serial này.' });
        }
        res.json(equipment);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

// API công khai để người dùng báo hỏng từ QR code
app.post('/api/public/incidents', async (req, res) => {
    try {
        const { equipmentSerial, problemDescription } = req.body;
        if (!equipmentSerial || !problemDescription) {
            return res.status(400).json({ message: "Vui lòng cung cấp đủ thông tin sự cố." });
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
            reportedBy: "QR Scan User" // Đánh dấu đây là báo cáo từ QR
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
app.post('/api/documents/upload/:equipmentId', authenticateToken, isAdmin, upload.single('document'), async (req, res) => {
    try {
        const { equipmentId } = req.params;
        const { documentType } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ message: 'Không có file nào được tải lên.' });
        }

        const newDocument = new Document({
            equipmentId: equipmentId,
            fileName: req.file.originalname,
            fileUrl: req.file.path, // URL từ Cloudinary
            cloudinaryId: req.file.filename,
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

// 11. KHỞI ĐỘNG SERVER
app.listen(PORT, () => {
    console.log(`Backend đang chạy tại địa chỉ: http://localhost:${PORT}`);
});