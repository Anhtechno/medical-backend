const mongoose = require('mongoose');

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

module.exports = Document;
