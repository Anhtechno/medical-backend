// Tiện ích tìm kiếm tiếng Việt cho thiết bị.
//
// Khắc phục các lỗi của bản cũ:
//  - Ký tự đặc biệt (vd "(", "+", "\") làm câu lệnh regex lỗi -> server trả 500.
//  - Gõ không dấu ("may tho") không tìm ra "Máy thở".
//  - Gõ nhiều từ ("may tho siemens") chỉ khớp khi cả cụm nằm liền nhau trong MỘT trường.

const VI_GROUPS = {
    a: 'aàáảãạăằắẳẵặâầấẩẫậ',
    e: 'eèéẻẽẹêềếểễệ',
    i: 'iìíỉĩị',
    o: 'oòóỏõọôồốổỗộơờớởỡợ',
    u: 'uùúủũụưừứửữự',
    y: 'yỳýỷỹỵ',
    d: 'dđ'
};

// Bỏ dấu tiếng Việt, đưa về chữ thường
function stripAccents(str) {
    return String(str || '')
        .normalize('NFD')
        .replace(/[̀-ͯ]/g, '')
        .replace(/đ/g, 'd').replace(/Đ/g, 'D')
        .toLowerCase();
}

function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Tạo biểu thức chính quy "không phân biệt dấu" cho một từ khóa
function accentInsensitivePattern(token) {
    let out = '';
    for (const ch of stripAccents(token)) {
        const group = VI_GROUPS[ch];
        out += group ? `[${group}${group.toUpperCase()}]` : escapeRegex(ch);
    }
    return out;
}

// Tách chuỗi tìm kiếm thành các từ khóa (tối đa 8 từ)
function tokenize(q) {
    return String(q || '').trim().split(/\s+/).filter(Boolean).slice(0, 8);
}

// Xây điều kiện Mongo: MỖI từ khóa phải khớp ít nhất một trường (AND giữa các từ, OR giữa các trường)
function buildEquipmentSearchFilter(q, departments = {}) {
    const tokens = tokenize(q);
    const fields = ['name', 'serial', 'manufacturer', 'description', 'accessories', 'year'];
    const andConditions = tokens.map(token => {
        const regex = new RegExp(accentInsensitivePattern(token), 'i');
        const or = fields.map(f => ({ [f]: regex }));
        // Cho phép gõ tên khoa ("hồi sức") để tìm thiết bị thuộc khoa đó
        const normToken = stripAccents(token);
        const deptKeys = Object.keys(departments).filter(k => stripAccents(departments[k]).includes(normToken));
        if (deptKeys.length > 0) or.push({ department: { $in: deptKeys } });
        return { $or: or };
    });
    return andConditions.length > 0 ? { $and: andConditions } : {};
}

module.exports = { stripAccents, escapeRegex, accentInsensitivePattern, tokenize, buildEquipmentSearchFilter };
