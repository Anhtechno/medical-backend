const mongoose = require('mongoose');

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

module.exports = Maintenance;
