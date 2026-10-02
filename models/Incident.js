const mongoose = require('mongoose');

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

module.exports = Incident;
