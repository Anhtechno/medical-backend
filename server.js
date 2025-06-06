console.log("--- CAMERA 1: Bắt đầu chạy file server.js ---");

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
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://TEN_USER:MAT_KHAU@DIA_CHI_CLUSTER.net/medicalDB?retryWrites=true&w=majority";
const JWT_SECRET = process.env.JWT_SECRET || "DAY_LA_MOT_CAI_KHOA_BI_MAT_RAT_DAI_VA_KHONG_AI_DOAN_DUOC_12345";

// 3. CẤU HÌNH MIDDLEWARE
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 4. KẾT NỐI VỚI MONGODB
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Đã kết nối thành công tới MongoDB Atlas!'))
    .catch(err => console.error('!!! LỖI KẾT NỐI MONGODB:', err));

// 5. ĐỊNH NGHĨA SCHEMAS & MODELS
// Schema cho Thiết Bị
const equipmentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    serial: { type: String, required: true, unique: true },
    manufacturer: String, accessories: String, year: String, status: String,
    description: String, image: String, department: { type: String, required: true }
});
const Equipment = mongoose.models.Equipment || mongoose.model('Equipment', equipmentSchema);

// Schema cho Người Dùng
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true }
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

// Dữ liệu tĩnh về các khoa
const departments = { 'bvsk_tw_2b': 'Phòng Bảo vệ sức khỏe Trung ương 2B', 'cap_cuu': 'Khoa Cấp cứu', 'kham_benh': 'Khoa Khám bệnh', 'kham_benh_yc': 'Khoa Khám bệnh theo yêu cầu', 'noi_than_loc_mau': 'Khoa Nội thận – Lọc máu', 'dinh_duong_ls': 'Khoa Dinh dưỡng lâm sàng', 'phuc_hoi_cn': 'Khoa Phục hồi chức năng', 'hoi_suc_tc_cd': 'Khoa Hồi sức tích cực – Chống độc', 'phau_thuat_gmhs': 'Khoa Phẫu thuật – Gây mê hồi sức', 'ngoai_ctch': 'Khoa Ngoại chấn thương chỉnh hình', 'ngoai_tieu_hoa': 'Khoa Ngoại tiêu hoá', 'ngoai_gan_mat': 'Khoa Ngoại gan mật', 'noi_tiet': 'Khoa Nội tiết', 'ngoai_tim_mach_ln': 'Khoa Ngoại tim mạch – Lồng ngực', 'noi_tim_mach': 'Khoa Nội tim mạch', 'tim_mach_cc_ct': 'Khoa Tim mạch cấp cứu và can thiệp', 'noi_than_kinh': 'Khoa Nội thần kinh', 'loan_nhip_tim': 'Khoa Loạn nhịp tim', 'ngoai_than_kinh': 'Khoa Ngoại thần kinh', 'ngoai_than_tn': 'Khoa Ngoại thận – Tiết niệu', 'dieu_tri_cbcc': 'Khoa Điều trị Cán bộ cao cấp', 'noi_cxk': 'Khoa Nội cơ xương khớp', 'noi_dieu_tri_yc': 'Khoa Nội điều trị theo yêu cầu', 'noi_tieu_hoa': 'Khoa Nội tiêu hoá', 'noi_ho_hap': 'Khoa Nội hô hấp', 'mat': 'Khoa Mắt', 'tai_mui_hong': 'Khoa Tai mũi họng', 'pt_hm_thtm': 'Khoa Phẫu thuật hàm mặt – Tạo hình thẩm mỹ', 'ung_buou': 'Khoa Ung bướu', 'noi_nhiem': 'Khoa Nội nhiễm', 'y_hoc_co_truyen': 'Khoa Y học cổ truyền', 'ngoai_dieu_tri_yc': 'Khoa Ngoại điều trị theo yêu cầu', 'da_lieu_md_du': 'Khoa Da liễu – Miễn dịch – Dị ứng' };

console.log("--- CAMERA 2: Chuẩn bị định nghĩa API xác thực ---");
// 6. API CHO VIỆC XÁC THỰC (ĐĂNG KÝ, ĐĂNG NHẬP)
app.post('/api/auth/register', async (req, res) => {
    try {
        console.log("--- CAMERA 3: Yêu cầu ĐĂNG KÝ đã vào được tới API! ---");
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Vui lòng nhập đủ tên đăng nhập và mật khẩu." });

        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: "Tên đăng nhập đã tồn tại." });

        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: "Đăng ký tài khoản thành công!" });
    } catch (error) {
        console.error("Lỗi trong API Đăng ký:", error);
        res.status(500).json({ message: "Lỗi server khi đăng ký.", error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });

        const token = jwt.sign(
            { userId: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn: '8h' }
        );
        res.json({ message: "Đăng nhập thành công!", token });
    } catch (error) {
        console.error("Lỗi trong API Đăng nhập:", error);
        res.status(500).json({ message: "Lỗi server khi đăng nhập.", error: error.message });
    }
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

// 8. API QUẢN LÝ THIẾT BỊ (ĐÃ ĐƯỢC BẢO VỆ)
app.get('/api/departments', authenticateToken, (req, res) => res.json(departments));

app.get('/api/equipment/:deptKey', authenticateToken, async (req, res) => {
    try {
        const { deptKey } = req.params;
        const equipments = await Equipment.find({ department: deptKey });
        res.json(equipments);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy dữ liệu', error: error.message });
    }
});

app.post('/api/equipment/:deptKey', authenticateToken, async (req, res) => {
    try {
        const { deptKey } = req.params;
        const newEquipmentData = { ...req.body, department: deptKey };
        const existing = await Equipment.findOne({ serial: newEquipmentData.serial });
        if (existing) return res.status(400).json({ message: `Số serial "${newEquipmentData.serial}" đã tồn tại.` });
        const equipment = new Equipment(newEquipmentData);
        await equipment.save();
        res.status(201).json(equipment);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi thêm thiết bị', error: error.message });
    }
});
app.delete('/api/equipment/:deptKey/:serial', authenticateToken, async (req, res) => {
    try {
        const { serial } = req.params;
        const deletedEquipment = await Equipment.findOneAndDelete({ serial: serial });
        if (!deletedEquipment) return res.status(404).json({ message: "Không tìm thấy thiết bị." });
        res.json({ message: "Xóa thành công." });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa', error: error.message });
    }
});
app.get('/api/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.status(400).json({ message: "Cần có từ khóa tìm kiếm." });
        const searchTerm = q.toLowerCase();
        const results = await Equipment.find({$or: [{ name: { $regex: searchTerm, $options: 'i' } },{ serial: { $regex: searchTerm, $options: 'i' } },{ manufacturer: { $regex: searchTerm, $options: 'i' } }]});
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi tìm kiếm', error: error.message });
    }
});

console.log("--- CAMERA 4: Đã định nghĩa xong tất cả API, chuẩn bị lắng nghe... ---");
// 9. KHỞI ĐỘNG SERVER
app.listen(PORT, () => {
    console.log(`Backend đang chạy tại địa chỉ: http://localhost:${PORT}`);
});