const mongoose = require('mongoose');

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
    // Tuần mà nhật ký này thuộc về, lưu ngày THỨ HAI của tuần (YYYY-MM-DD, giờ VN).
    // Nhật ký cũ chưa có trường này sẽ được suy ra từ createdAt.
    weekStart: { type: String },
    // true nếu là ghi bù cho một tuần đã qua
    isBackfill: { type: Boolean, default: false },
}, { timestamps: true });

usageLogSchema.index({ equipmentId: 1, weekStart: 1 });
usageLogSchema.index({ departmentKey: 1, weekStart: 1 });

const UsageLog = mongoose.models.UsageLog || mongoose.model('UsageLog', usageLogSchema);

module.exports = UsageLog;
