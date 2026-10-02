    document.addEventListener('DOMContentLoaded', function() {
        const API_BASE_URL = 'https://quanlythietbi-anh.onrender.com';
        // BẢO MẬT: escape dữ liệu text do người dùng nhập (vd: mô tả sự cố gửi qua QR công khai)
        // trước khi chèn vào innerHTML, để tránh HTML/script lạ chạy trong trình duyệt (XSS).
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }
        let departments = {};
        let currentFullDeptList = []; 
        let currentStatusFilter = 'all';
        let userProfile = {};
        let userChartInstance = null;
        let currentPage = 1;
        let currentDisplayedData = [];
        
        const dom = {
            loginContainer: document.getElementById('login-container'),
            mainAppContainer: document.getElementById('main-app-container'),
            loginForm: document.getElementById('login-form'),
            loginError: document.getElementById('login-error'),
            logoutBtn: document.getElementById('logout-btn'),
            departmentSelect: document.getElementById('departmentSelect'),
            departmentSearchInput: document.getElementById('departmentSearchInput'),
            currentDepartment: document.getElementById('currentDepartment'),
            equipmentTableBody: document.getElementById('equipmentTableBody'),
            addEquipmentBtn: document.getElementById('addEquipmentBtn'),
            addEquipmentModal: document.getElementById('addEquipmentModal'),
            equipmentForm: document.getElementById('equipmentForm'),
            searchInput: document.getElementById('searchInput'),
            sidebarFilters: document.querySelectorAll('#sidebar-filters a'),
            exportExcelBtn: document.getElementById('exportExcelBtn'),
            viewContainers: document.querySelectorAll('.view-container'),
            equipmentView: document.getElementById('equipment-view-container'),
            incidentsView: document.getElementById('incidents-view-container'),
            maintenanceView: document.getElementById('maintenance-view-container'),
            dashboardView: document.getElementById('dashboard-view-container'),
            profileView: document.getElementById('profile-view-container'),
            usersView: document.getElementById('users-view-container'),
            usersTableBody: document.getElementById('users-table-body'),
            techniciansView: document.getElementById('technicians-view-container'),
            addUserBtn: document.getElementById('addUserBtn'),
            userModal: document.getElementById('userModal'),
            userForm: document.getElementById('userForm'),
            closeUserModalBtn: document.getElementById('closeUserModalBtn'),
            cancelUserBtn: document.getElementById('cancelUserBtn'),
            maintenanceTableBody: document.getElementById('maintenance-table-body'),
            addMaintenanceBtn: document.getElementById('addMaintenanceBtn'),
            maintenanceModal: document.getElementById('maintenanceModal'),
            maintenanceForm: document.getElementById('maintenanceForm'),
            closeMaintenanceModalBtn: document.getElementById('closeMaintenanceModalBtn'),
            cancelMaintenanceBtn: document.getElementById('cancelMaintenanceBtn'),
            maintenanceEquipmentSelect: document.getElementById('maintenanceEquipmentSelect'),
            sidebarNavLinks: document.querySelectorAll('#sidebar-main a'),
            adminIncidentView: document.getElementById('admin-incident-view'),
            userIncidentView: document.getElementById('user-incident-view'),
            incidentForm: document.getElementById('incident-form'),
            incidentEquipmentSelect: document.getElementById('incident-equipment-select'),
            incidentTableBodyAdmin: document.getElementById('incident-table-body-admin'),
            incidentTableBodyUser: document.getElementById('incident-table-body-user'),
            closeModalBtn: document.getElementById('closeModalBtn'),
            cancelBtn: document.getElementById('cancelBtn'),
            notificationBellContainer: document.getElementById('notificationBellContainer'),
            notificationBadge: document.getElementById('notificationBadge'),
            notificationDropdown: document.getElementById('notificationDropdown'),
            notificationList: document.getElementById('notificationList'),
            reportsView: document.getElementById('reports-view-container'),
            reportStartDate: document.getElementById('reportStartDate'),
            reportEndDate: document.getElementById('reportEndDate'),
            viewReportBtn: document.getElementById('viewReportBtn'),
            reportResults: document.getElementById('report-results'),
            usageLogModal: document.getElementById('usageLogModal'),
            usageLogForm: document.getElementById('usageLogForm'),
            closeUsageLogModalBtn: document.getElementById('closeUsageLogModalBtn'),
            userDashboardView: document.getElementById('user-dashboard-view-container'),
            userReportIncidentBtn: document.getElementById('userReportIncidentBtn'),
            bulkLogExceptBtn: document.getElementById('bulkLogExceptBtn'),
            bulkLogExceptionModal: document.getElementById('bulkLogExceptionModal'),
            closeBulkLogExceptionModalBtn: document.getElementById('closeBulkLogExceptionModalBtn'),
            cancelBulkLogExceptionBtn: document.getElementById('cancelBulkLogExceptionBtn'),
            confirmBulkLogExceptionBtn: document.getElementById('confirmBulkLogExceptionBtn'),
            exceptionListContainer: document.getElementById('exception-list-container'),
        };
        
        const saveToken = (token) => localStorage.setItem('authToken', token);
        const getToken = () => localStorage.getItem('authToken');
        const removeToken = () => { localStorage.removeItem('authToken'); localStorage.removeItem('userProfile'); };

        const saveUserProfile = (token) => {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                userProfile = { role: payload.role, departmentKey: payload.departmentKey, username: payload.username };
                localStorage.setItem('userProfile', JSON.stringify(userProfile));
            } catch (e) { console.error("Could not decode token", e); logout(); }
        };
        const getUserProfile = () => JSON.parse(localStorage.getItem('userProfile')) || {};

        function logout() { removeToken(); window.location.reload(); }
        function showLoginView() { dom.loginContainer.style.display = 'flex'; dom.mainAppContainer.style.display = 'none'; }
        
        function showMainAppView() {
    dom.loginContainer.style.display = 'none';
    dom.mainAppContainer.style.display = 'block';
    dom.logoutBtn.innerHTML = `<i class="fas fa-sign-out-alt"></i> ${userProfile.username} (Đăng xuất)`;

    if (userProfile.role === 'admin') {
            const sidebar = document.getElementById('sidebar-main');
            // Menu Quản lý Users (Khoa phòng)
            if (!document.querySelector('a[data-view="users"]')) {
                const userLi = document.createElement('li');
                userLi.innerHTML = `<a data-view="users"><i class="fas fa-hospital-user"></i> Quản lý Khoa/Phòng</a>`;
                sidebar.appendChild(userLi);
            }
            // Menu Quản lý Kỹ sư (MỚI)
            if (!document.querySelector('a[data-view="technicians"]')) {
                const techLi = document.createElement('li');
                techLi.innerHTML = `<a data-view="technicians"><i class="fas fa-user-shield"></i> Quản lý Kỹ sư</a>`;
                sidebar.appendChild(techLi);
            }
            // Menu Báo cáo
            if (!document.querySelector('a[data-view="reports"]')) {
                const reportLi = document.createElement('li');
                reportLi.innerHTML = `<a data-view="reports"><i class="fas fa-chart-pie"></i> Báo cáo</a>`;
                sidebar.appendChild(reportLi);
            }
            
            // Re-attach events
            dom.sidebarNavLinks = document.querySelectorAll('#sidebar-main a');
            dom.sidebarNavLinks.forEach(link => {
                link.removeEventListener('click', handleNavLinkClick);
                link.addEventListener('click', handleNavLinkClick);
            });
            dom.notificationBellContainer.style.display = 'flex';
            fetchNotifications();
            setInterval(fetchNotifications, 60000); 
        } else if (userProfile.role === 'technician') {
            // Logic cho Kỹ sư: Ẩn các menu không cần thiết nếu muốn
            // Hiện tại cứ để nguyên, chỉ cần xử lý hiển thị dữ liệu
        }
}
        
        function handleNavLinkClick(e) {
    e.preventDefault();
    let viewName = e.currentTarget.dataset.view; // Lấy view_name từ link

    // Logic điều hướng thông minh:
    // Nếu link là "dashboard" VÀ vai trò người dùng là "user" -> đổi hướng sang "userDashboard"
    if (viewName === 'dashboard' && userProfile.role === 'user') {
        viewName = 'userDashboard';
    }

    if (viewName) switchView(viewName);
}

        async function fetchWithAuth(url, options = {}) {
            const token = getToken();
            const headers = { 'Content-Type': 'application/json', ...options.headers };
            if (token) { headers['Authorization'] = `Bearer ${token}`; }
            const response = await fetch(url, { ...options, headers });
            if (response.status === 401) {
    logout();
    throw new Error('Phiên đăng nhập đã hết hạn.');
}

// Nếu lỗi 403 (Không có quyền), ta kiểm tra xem có phải đang gọi API 'usage' không
// Nếu đúng là đang update usage thì KHÔNG đăng xuất, chỉ báo lỗi thôi.
if (response.status === 403) {
    if (url.includes('/usage/')) {
        // Không logout, cho phép code bên dưới ném lỗi ra để hiện SweetAlert
        const err = await response.json();
        throw new Error(err.message || 'Bạn không có quyền thực hiện (Lỗi 403)');
    } else {
        // Các trường hợp khác thì vẫn logout để bảo mật
        logout();
        throw new Error('Bạn không có quyền truy cập.');
    }
}
            return response;
        }
        
        const handleApiError = (error, context = 'Thao tác') => {
            console.error(`${context} thất bại:`, error);
            Swal.fire({
                icon: 'error',
                title: `${context} thất bại`,
                text: `Lỗi: ${error.message}`,
            });
        };
        
        async function loadInitialData() {
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/departments`);
                if (!response.ok) throw new Error('Không thể tải danh sách khoa');
                departments = await response.json();
                populateDepartmentDropdown();
                let firstDeptKey = (userProfile.role === 'user') ? userProfile.departmentKey : Object.keys(departments)[0];
                if (firstDeptKey) {
                    dom.departmentSelect.value = firstDeptKey;
                    await fetchAndDisplayEquipment(firstDeptKey, 1);
                }
            } catch (error) { handleApiError(error, 'Tải dữ liệu ban đầu'); throw error; }
        }
        
        function populateDepartmentDropdown(filter = '') {
            const currentVal = dom.departmentSelect.value;
            dom.departmentSelect.innerHTML = '';
            for (const key in departments) {
                if (departments[key].toLowerCase().includes(filter.toLowerCase())) {
                    const option = document.createElement('option');
                    option.value = key;
                    option.textContent = departments[key];
                    dom.departmentSelect.appendChild(option);
                }
            }
            if ([...dom.departmentSelect.options].some(opt => opt.value === currentVal)) {
                dom.departmentSelect.value = currentVal;
            }
            const isUser = userProfile.role === 'user';
            dom.departmentSelect.disabled = isUser;
            dom.departmentSearchInput.disabled = isUser;
            dom.departmentSearchInput.style.opacity = isUser ? 0.6 : 1;
        }

        async function fetchAndDisplayEquipment(deptKey, page = 1) {
            currentPage = page;
            if (!deptKey) {
                dom.equipmentTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 30px;">Vui lòng chọn một khoa.</td></tr>`;
                document.getElementById('pagination-controls').innerHTML = '';
                return;
            }
            dom.currentDepartment.textContent = `Đang tải...`;
            try {
                const url = `${API_BASE_URL}/api/equipment/${deptKey}?page=${page}&limit=10&status=${currentStatusFilter}`;
                const response = await fetchWithAuth(url);
                if (!response.ok) throw new Error(`Không thể tải dữ liệu`);
                
                const data = await response.json();
                currentFullDeptList = data.equipments;
                
                updateEquipmentTable(currentFullDeptList); 
                updateDepartmentTitle(deptKey);
                updateStats(data.stats);
                renderPaginationControls(data.totalPages, data.currentPage);
            } catch (error) {
                handleApiError(error, `Tải dữ liệu cho khoa ${departments[deptKey] || deptKey}`);
                document.getElementById('pagination-controls').innerHTML = '';
            }
        }
        
        function updateEquipmentTable(list, isGlobalSearch = false) {
    currentDisplayedData = list;
    dom.equipmentTableBody.innerHTML = '';
    document.getElementById('departmentColumnHeader').style.display = isGlobalSearch ? '' : 'none';
    const colspan = isGlobalSearch ? 8 : 7;
    if (list.length === 0) {
        dom.equipmentTableBody.innerHTML = `<tr><td colspan="${colspan}" style="text-align:center; padding: 30px;">Không có thiết bị nào phù hợp.</td></tr>`;
        return;
    }
    list.forEach(item => {
        const row = document.createElement('tr');
        const itemDept = item.department || dom.departmentSelect.value;
        row.className = `status-${item.status}`;
        let actionButtons = '';

        // Phân quyền hiển thị nút bấm
        if (userProfile.role === 'admin') {
            actionButtons = `
                <button class="action-button view-btn" data-serial="${item.serial}" style="background-color: var(--success-color); padding: 6px 10px; font-size: 14px;"><i class="fas fa-eye"></i></button>
                <button class="edit-btn" data-serial="${item.serial}"><i class="fas fa-edit"></i></button>
                <button class="delete-btn" data-serial="${item.serial}" data-dept="${itemDept}"><i class="fas fa-trash"></i></button>
            `;
        } else { // Nếu là user thì hiển thị các nút tương ứng
            let warningIcon = '';
            if (item.needsLog) {
                warningIcon = `<i class="fas fa-exclamation-circle" style="color: yellow; margin-right: 5px;" title="Chưa ghi nhật ký tuần này"></i>`;
            }

            actionButtons = `
                <button class="action-button report-issue-btn" data-serial="${item.serial}" style="background-color: var(--danger-color); padding: 6px 10px; font-size: 14px;"><i class="fas fa-triangle-exclamation"></i> Báo hỏng</button>
                <button class="action-button log-usage-btn" data-id="${item._id}" data-name="${item.name}" style="background-color: var(--info-color); padding: 6px 10px; font-size: 14px;">${warningIcon}<i class="far fa-file-alt"></i> Ghi Nhật ký</button>
            `;
        }

        // Tính toán màu sắc và độ dài thanh HP
        const usage = item.dailyUsage || 0;
        const percentage = (usage / 24) * 100;
        let hpColor = '#28a745'; // Xanh (Tốt/Ít)
        if (usage > 12) hpColor = '#ffc107'; // Vàng (Trung bình)
        if (usage > 20) hpColor = '#dc3545'; // Đỏ (Cao/Quá tải)

        // HTML cho thanh HP
        const hpBarHtml = `
            <div class="hp-bar-container hp-trigger" data-id="${item._id}" data-current="${usage}" data-name="${item.name}" title="Click để cập nhật giờ hoạt động">
                <div class="hp-bar-fill" style="width: ${percentage}%; background-color: ${hpColor};"></div>
                <div class="hp-bar-text">${usage}h / 24h</div>
            </div>
        `;

        row.innerHTML = `
            <td><img src="${item.image || 'https://via.placeholder.com/60x60?text=N/A'}" class="equipment-image" alt="${item.name}"></td>
            <td>${item.name}</td>
            <td>${item.serial}</td> 
            ${isGlobalSearch ? `<td>${departments[itemDept] || 'N/A'}</td>` : ''} 
            <td>${item.manufacturer || 'N/A'}</td>
            <td>${item.year}</td>
            <td>
                <span class="status ${item.status}">${{active: 'Hoạt động', maintenance: 'Bảo trì', inactive: 'Ngừng HĐ'}[item.status] || 'Không rõ'}</span>
            </td>
            <td class="action-btn-group" style="vertical-align: middle;">
                <div style="margin-bottom: 5px;">${actionButtons}</div>
                ${hpBarHtml} </td>
        `;
        dom.equipmentTableBody.appendChild(row);
    });
}
        
        function updateStats(stats = {}) {
            const totalInDept = (stats.active || 0) + (stats.maintenance || 0) + (stats.inactive || 0);
            document.getElementById('totalEquipment').textContent = totalInDept;
            document.getElementById('activeEquipment').textContent = stats.active || 0;
            document.getElementById('maintenanceEquipment').textContent = stats.maintenance || 0;
            document.getElementById('inactiveEquipment').textContent = stats.inactive || 0;
        }

        function renderPaginationControls(totalPages, currentPage) {
            const paginationContainer = document.getElementById('pagination-controls');
            paginationContainer.innerHTML = '';
            if (totalPages <= 1) return;
            for (let i = 1; i <= totalPages; i++) {
            const button = document.createElement('button');
            button.textContent = i;
            if (i === currentPage) button.classList.add('active');
            button.addEventListener('click', () => {
                // Không gán trực tiếp i, mà gọi lại hàm fetchAndDisplayEquipment
                // Hàm này sẽ tự động cập nhật currentPage cho chúng ta
            fetchAndDisplayEquipment(dom.departmentSelect.value, i);
            });
            paginationContainer.appendChild(button);
        }
        }
        
        function updateDepartmentTitle(deptKey) {
            dom.currentDepartment.textContent = departments[deptKey];
        }

        dom.departmentSelect.addEventListener('change', () => {
            dom.searchInput.value = '';
            currentStatusFilter = 'all';
            setActiveSidebarFilter('all');
            fetchAndDisplayEquipment(dom.departmentSelect.value, 1);
        });
        
        dom.departmentSearchInput.addEventListener('input', (e) => {
    populateDepartmentDropdown(e.target.value);

    // --- PHẦN NÂNG CẤP ĐỂ TỰ ĐỘNG CHỌN VÀ TẢI DỮ LIỆU ---
    const firstVisibleOption = dom.departmentSelect.querySelector('option');
    if (firstVisibleOption) {
        // Nếu có kết quả, tự động chọn khoa đầu tiên
        dom.departmentSelect.value = firstVisibleOption.value;
        // Kích hoạt sự kiện 'change' để tải lại dữ liệu cho khoa mới được chọn
        dom.departmentSelect.dispatchEvent(new Event('change'));
    } else {
        // Nếu không có kết quả, xóa bảng
        dom.equipmentTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 30px;">Không tìm thấy khoa phù hợp.</td></tr>`;
        dom.currentDepartment.textContent = "Không tìm thấy khoa";
    }
    // --- KẾT THÚC PHẦN NÂNG CẤP ---
});
        
        dom.searchInput.addEventListener('input', async (e) => {
            const searchTerm = e.target.value.trim();
            const isGlobalSearch = document.getElementById('globalSearchCheckbox').checked;

            document.getElementById('pagination-controls').innerHTML = ''; // Xóa phân trang khi tìm kiếm

            if (searchTerm.length > 0) {
                try {
                    let searchUrl = `${API_BASE_URL}/api/search?q=${encodeURIComponent(searchTerm)}`;

            // Nếu không phải tìm kiếm toàn cục, thêm mã khoa vào URL
                if (!isGlobalSearch) {
                const deptKey = dom.departmentSelect.value;
                    if (deptKey) {
                    searchUrl += `&dept=${deptKey}`;
                    }
                }

                dom.currentDepartment.textContent = `Kết quả tìm kiếm cho "${searchTerm}"...`;
                updateStats(); // Reset stats

                const response = await fetchWithAuth(searchUrl);
                const results = await response.json();

                // Cập nhật bảng với kết quả, isGlobalSearch sẽ quyết định có hiển thị cột Khoa/Phòng hay không
                updateEquipmentTable(results, isGlobalSearch);

        } catch (error) {
            handleApiError(error, 'Tìm kiếm');
        }
    } else { // Nếu xóa hết chữ trong ô tìm kiếm, quay về danh sách của khoa
        fetchAndDisplayEquipment(dom.departmentSelect.value, 1);
    }
});

        dom.sidebarFilters.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                dom.searchInput.value = '';
                currentStatusFilter = e.currentTarget.dataset.filter;
                setActiveSidebarFilter(currentStatusFilter);
                fetchAndDisplayEquipment(dom.departmentSelect.value, 1);
            });
        });

        function setActiveSidebarFilter(activeFilter) {
            dom.sidebarFilters.forEach(link => {
                link.classList.remove('active');
                if(link.dataset.filter === activeFilter) link.classList.add('active');
            });
        }
        
        dom.equipmentForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const editSerial = document.getElementById('edit-serial').value;
            const isEditing = !!editSerial;
            const serialNumber = document.getElementById('serialNumber').value.trim();
            if (!serialNumber) { 
                Swal.fire('Lỗi', 'Số serial là bắt buộc.', 'error');
                return; 
            }
            const payload = {
                name: document.getElementById('equipmentName').value, serial: serialNumber, manufacturer: document.getElementById('manufacturer').value,
                accessories: document.getElementById('accessories').value, year: document.getElementById('purchaseDate').value,
                status: document.getElementById('status').value, description: document.getElementById('description').value,
                image: document.getElementById('imagePreview').src.startsWith('data:image') ? document.getElementById('imagePreview').src : null
            };
            let url, method, targetDeptKey;
            if (isEditing) {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/item/${editSerial}`);
                if (!response.ok) { 
                    handleApiError({ message: 'Không tìm thấy thiết bị gốc để cập nhật.'}, 'Cập nhật');
                    return; 
                }
                const originalItem = await response.json();
                targetDeptKey = originalItem.department;
                url = `${API_BASE_URL}/api/equipment/${targetDeptKey}/${encodeURIComponent(editSerial)}`;
                method = 'PUT';
            } else {
                targetDeptKey = dom.departmentSelect.value;
                if (!targetDeptKey) { 
                    Swal.fire('Lỗi', 'Vui lòng chọn một khoa trước khi thêm.', 'warning');
                    return; 
                }
                payload.department = targetDeptKey;
                url = `${API_BASE_URL}/api/equipment/${targetDeptKey}`;
                method = 'POST';
            }
            try {
                const response = await fetchWithAuth(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                if (!response.ok) { const errorData = await response.json(); throw new Error(errorData.message || 'Thao tác thất bại.'); }
                Swal.fire({ position: 'top-end', icon: 'success', title: 'Thao tác thành công!', showConfirmButton: false, timer: 1500 });
                closeModal();
                await fetchAndDisplayEquipment(targetDeptKey, currentPage);
            } catch (error) {
                handleApiError(error, isEditing ? 'Cập nhật' : 'Thêm mới');
            }
        });

        dom.equipmentTableBody.addEventListener('click', async (e) => {
            const hpTarget = e.target.closest('.hp-trigger');
    if (hpTarget) {
        const id = hpTarget.dataset.id;
        const currentVal = parseFloat(hpTarget.dataset.current);
        const name = hpTarget.dataset.name;

        // Hiện Popup thanh trượt
        const { value: hours } = await Swal.fire({
            title: `Hiệu suất: ${name}`,
            text: 'Kéo để chọn số giờ hoạt động hôm nay',
            input: 'range',
            inputLabel: 'Giờ hoạt động (0 - 24h)',
            inputAttributes: {
                min: 0,
                max: 24,
                step: 0.5
            },
            inputValue: currentVal,
            showCancelButton: true,
            confirmButtonText: 'Cập nhật',
            cancelButtonText: 'Hủy',
            didOpen: () => {
                // Thêm hiển thị số giờ real-time khi kéo
                const range = Swal.getInput();
                const output = Swal.getHtmlContainer().querySelector('output') || document.createElement('output');
                output.style.display = 'block';
                output.style.fontSize = '20px';
                output.style.fontWeight = 'bold';
                output.style.color = '#007bff';
                output.style.marginTop = '10px';
                output.innerText = `${range.value} giờ`;
                if(!Swal.getHtmlContainer().querySelector('output')) Swal.getHtmlContainer().appendChild(output);
                
                range.addEventListener('input', () => {
                    output.innerText = `${range.value} giờ`;
                });
            }
        });

        if (hours !== undefined) { // Người dùng ấn OK
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/usage/${id}`, {
                    method: 'PUT',
                    body: JSON.stringify({ dailyUsage: hours })
                });

                if (!response.ok) throw new Error('Cập nhật thất bại');
                
                // Cập nhật giao diện ngay lập tức mà không cần load lại trang
                const percentage = (hours / 24) * 100;
                let newColor = '#28a745';
                if (hours > 12) newColor = '#ffc107';
                if (hours > 20) newColor = '#dc3545';
                
                const fill = hpTarget.querySelector('.hp-bar-fill');
                const text = hpTarget.querySelector('.hp-bar-text');
                
                fill.style.width = `${percentage}%`;
                fill.style.backgroundColor = newColor;
                text.textContent = `${hours}h / 24h`;
                
                // Cập nhật lại data attribute để lần click sau đúng giá trị
                hpTarget.dataset.current = hours;
                
                Swal.fire({
                    icon: 'success',
                    title: 'Đã cập nhật!',
                    toast: true,
                    position: 'top-end',
                    showConfirmButton: false,
                    timer: 1500
                });

            } catch (error) {
                handleApiError(error, 'Cập nhật hiệu suất');
            }
        }
        return; // Dừng xử lý tiếp để không kích hoạt nhầm các nút khác
    }
    const target = e.target.closest('button, img');
    if (!target) return;

    // Logic cho việc nhấn vào ảnh để phóng to
    if (target.classList.contains('equipment-image')) {
        const modal = document.getElementById('image-zoom-modal');
        const modalImg = document.getElementById('zoomed-image');
        const captionText = document.getElementById('zoom-caption');
        const closeSpan = document.getElementById('close-zoom-modal');

        modal.style.display = "flex";
        modalImg.src = target.src;
        captionText.innerHTML = target.alt;

        closeSpan.onclick = function() { 
            modal.style.display = "none";
        }
        modal.onclick = function(event) {
            if (event.target === modal) {
                 modal.style.display = "none";
            }
        }
        return; // Dừng lại sau khi xử lý ảnh
    }

    // Logic cho các nút của Admin
    if (target.classList.contains('view-btn')) {
        const serial = target.dataset.serial;
        switchView('profile', encodeURIComponent(serial));
    } 
    else if (target.classList.contains('edit-btn')) {
        const serial = target.dataset.serial;
        try {
            const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/item/${encodeURIComponent(serial)}`);
            if (!response.ok) throw new Error("Không tìm thấy thông tin thiết bị để sửa.");
            const itemData = await response.json();
            if (itemData) openModal('edit', itemData);
        } catch(error) { handleApiError(error, 'Lấy thông tin sửa'); }
    } 
    else if (target.classList.contains('delete-btn')) {
        const serial = target.dataset.serial;
        const deptKey = target.dataset.dept;
        if (!deptKey) return;
        
        Swal.fire({
            title: 'Bạn chắc chắn không?',
            text: `Bạn sẽ không thể hoàn tác hành động xóa thiết bị có serial "${serial}"!`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Vâng, xóa nó!',
            cancelButtonText: 'Hủy bỏ'
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/${deptKey}/${encodeURIComponent(serial)}`, { method: 'DELETE' });
                    if (!response.ok) { const err = await response.json(); throw new Error(err.message); }
                    Swal.fire('Đã xóa!', 'Thiết bị đã được xóa thành công.', 'success');
                    await fetchAndDisplayEquipment(dom.departmentSelect.value, currentPage); 
                } catch (error) { 
                    handleApiError(error, 'Xóa thiết bị'); 
                }
            }
        });
    }

    // Logic cho các nút của User
    else if (target.classList.contains('log-usage-btn')) {
        const equipmentId = target.dataset.id;
        const equipmentName = target.dataset.name;
        openUsageLogModal({ _id: equipmentId, name: equipmentName });
    }
    // SỬA LẠI LOGIC CHO NÚT BÁO HỎNG
    else if (target.classList.contains('report-issue-btn')) {
        const serial = target.dataset.serial;
        // Gọi switchView và truyền trực tiếp serial, không cần setTimeout
        switchView('incidents', serial);
    }
});
        
        dom.exportExcelBtn.addEventListener('click', async () => {
    const searchTerm = dom.searchInput.value.trim();
    let dataToProcess = [];
    let reportTitle = "";

    // Quyết định dữ liệu nào sẽ được xuất
    if (searchTerm) { // Nếu người dùng đang tìm kiếm
        if (currentDisplayedData.length === 0) {
            Swal.fire('Thông báo', 'Không có dữ liệu tìm kiếm để xuất.', 'info');
            return;
        }
        dataToProcess = currentDisplayedData;
        reportTitle = `Ket-qua-tim-kiem_${searchTerm.replace(/\s/g, '_')}`;
    } else { // Nếu người dùng đang xem danh sách khoa
        const selectedDepartmentKey = dom.departmentSelect.value;
        if (!selectedDepartmentKey) {
            Swal.fire('Thông báo', 'Vui lòng chọn khoa để xuất file.', 'info');
            return;
        }
        const departmentName = departments[selectedDepartmentKey] || 'UnknownDept';
        reportTitle = `DS-Thiet-bi_${departmentName.replace(/[^\w]/g, '')}`;

        Swal.fire({
            title: `Đang tổng hợp dữ liệu cho khoa ${departmentName}...`,
            allowOutsideClick: false,
            didOpen: () => { Swal.showLoading() }
        });
        
        try {
            // Lấy TẤT CẢ thiết bị của khoa, không phân trang
            const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/${selectedDepartmentKey}?limit=10000`);
            if (!response.ok) throw new Error('Không thể tải toàn bộ danh sách thiết bị.');
            const data = await response.json();
            dataToProcess = data.equipments;
            Swal.close();
        } catch (error) {
            handleApiError(error, "Xuất file Excel");
            return;
        }
    }

    if (dataToProcess.length === 0) {
        Swal.fire('Thông báo', 'Không có dữ liệu để xuất.', 'info');
        return;
    }

    // Xử lý và tạo file Excel
    try {
        const statusMap = { active: 'Hoạt động', maintenance: 'Bảo trì', inactive: 'Ngừng hoạt động' };
        const dataToExport = dataToProcess.map(item => ({
            'Tên Thiết Bị': item.name,
            'Số Serial': item.serial,
            'Hãng Sản Xuất': item.manufacturer,
            'Khoa/Phòng': departments[item.department] || 'N/A',
            'Năm Sử Dụng': item.year,
            'Tình Trạng': statusMap[item.status] || 'Không rõ',
            'Phụ Kiện': item.accessories || '',
            'Mô Tả': item.description || ''
        }));

        const worksheet = XLSX.utils.json_to_sheet(dataToExport);
        const workbook = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Danh sách thiết bị');
        
        const headers = Object.keys(dataToExport[0]);
        // DÒNG ĐÚNG ĐỂ TÍNH ĐỘ RỘNG CỘT
        const colWidths = headers.map(header => ({ wch: Math.max(header.length, ...dataToExport.map(row => (row[header] || '').toString().length)) + 2 }));
        worksheet["!cols"] = colWidths;
        
        const fileName = `${reportTitle}_${new Date().toLocaleDateString('vi-VN').replace(/\//g, '-')}.xlsx`;
        XLSX.writeFile(workbook, fileName);
    } catch (error) {
        handleApiError(error, "Xử lý file Excel");
    }
});

        function openModal(mode = 'add', itemData = null) {
            dom.equipmentForm.reset();
            document.getElementById('imagePreview').src = "#";
            document.getElementById('imagePreview').style.display = 'none';
            document.getElementById('serialNumber').readOnly = false;
            document.getElementById('edit-serial').value = '';
            if (mode === 'edit' && itemData) {
                document.getElementById('modalTitle').textContent = 'Chỉnh Sửa Thiết Bị';
                document.getElementById('edit-serial').value = itemData.serial;
                document.getElementById('equipmentName').value = itemData.name;
                document.getElementById('serialNumber').value = itemData.serial;
                document.getElementById('manufacturer').value = itemData.manufacturer;
                document.getElementById('accessories').value = itemData.accessories;
                document.getElementById('purchaseDate').value = itemData.year;
                document.getElementById('status').value = itemData.status;
                document.getElementById('description').value = itemData.description;
                if (itemData.image) { document.getElementById('imagePreview').src = itemData.image; document.getElementById('imagePreview').style.display = 'block'; }
            } else {
                document.getElementById('modalTitle').textContent = 'Thêm Thiết Bị Mới';
            }
            dom.addEquipmentModal.style.display = 'flex';
        }
        function closeModal() { dom.addEquipmentModal.style.display = 'none'; }
        dom.addEquipmentBtn.addEventListener('click', () => openModal('add'));
        dom.closeModalBtn.addEventListener('click', closeModal);
        dom.cancelBtn.addEventListener('click', closeModal);
        window.addEventListener('click', (e) => { if (e.target === dom.addEquipmentModal) closeModal(); });
        document.getElementById('imageUpload').addEventListener('click', () => document.getElementById('imageInput').click());
        document.getElementById('imageInput').addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => { document.getElementById('imagePreview').src = e.target.result; document.getElementById('imagePreview').style.display = 'block'; };
                reader.readAsDataURL(this.files[0]);
            }
        });

        dom.sidebarNavLinks.forEach(link => {
            link.addEventListener('click', handleNavLinkClick);
        });

        function switchView(viewName, param = null) {
    dom.sidebarNavLinks.forEach(link => {
        const linkView = link.dataset.view;
        let isActive = linkView === viewName;
        if (viewName === 'profile' && linkView === 'equipment') {
            isActive = true;
        }
        link.classList.toggle('active', isActive);
    });

    dom.viewContainers.forEach(container => container.style.display = 'none');
    
    if (viewName !== 'equipment' && viewName !== 'profile') {
        dom.sidebarFilters.forEach(f => f.classList.remove('active'));
    } else {
        setActiveSidebarFilter(currentStatusFilter);
    }

    const viewToShow = dom[viewName + 'View'];
    if (viewToShow) {
        viewToShow.style.display = 'block';
        document.getElementById('equipment-filters').style.display = (viewName === 'equipment' || viewName === 'profile') ? 'block' : 'none';
        
        if (viewName === 'dashboard') renderDashboardView();
        if (viewName === 'incidents') renderIncidentView(param); // Truyền param (serial) vào đây
        if (viewName === 'maintenance') renderMaintenanceView();
        if (viewName === 'profile') renderProfileView(param);
        if (viewName === 'users') renderUsersView();
        if (viewName === 'reports') renderReportsView();
        if (viewName === 'userDashboard') renderUserDashboard();
        if (viewName === 'technicians') renderTechniciansView();
    }
}
        
        async function renderIncidentView(serialToSelect = null) {
    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/api/incidents`);
        if (!response.ok) throw new Error("Không thể tải danh sách sự cố");
        const incidents = await response.json();

        if (userProfile.role === 'admin') {
            dom.adminIncidentView.style.display = 'block';
            dom.userIncidentView.style.display = 'none';
            renderIncidentTableAdmin(incidents);
        } else if (userProfile.role === 'technician') {
            // Kỹ sư dùng chung view Admin nhưng data khác
            dom.adminIncidentView.style.display = 'block';
            dom.userIncidentView.style.display = 'none';
            renderIncidentTableTechnician(incidents);
        } else {
            dom.adminIncidentView.style.display = 'none';
            dom.userIncidentView.style.display = 'block';
            await populateIncidentFormEquipmentSelect(serialToSelect); // Truyền serial xuống đây
            renderIncidentTableUser(incidents);
            
            const userDeptName = departments[userProfile.departmentKey];
            document.getElementById('incident-department').value = userDeptName;
            const today = new Date();
            document.getElementById('incident-date').value = today.toLocaleDateString('vi-VN');
        }
    } catch (error) {
        handleApiError(error, "Tải dữ liệu sự cố");
    }
}
        
        async function populateIncidentFormEquipmentSelect(serialToSelect = null) {
    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/${userProfile.departmentKey}?limit=1000`);
        const data = await response.json();
        const equipmentList = data.equipments;

        dom.incidentEquipmentSelect.innerHTML = '<option value="">-- Chọn thiết bị --</option>';
        equipmentList.forEach(eq => {
            const option = document.createElement('option');
            option.value = eq.serial;
            option.textContent = `${eq.name} (Serial: ${eq.serial})`;
            dom.incidentEquipmentSelect.appendChild(option);
        });

        // Tự động chọn đúng serial nếu được truyền vào
        if (serialToSelect) {
            dom.incidentEquipmentSelect.value = serialToSelect;
        }
    } catch (error) {
        handleApiError(error, "Tải danh sách thiết bị cho form sự cố");
    }
}

        function renderIncidentTableAdmin(incidents) {
    const tableBody = dom.incidentTableBodyAdmin;
    tableBody.innerHTML = '';
    if (incidents.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 30px;">Chưa có báo cáo sự cố nào.</td></tr>`;
        return;
    }
    incidents.forEach(inc => {
        const row = document.createElement('tr');
        const statusMap = { new: 'Mới', in_progress: 'Đang xử lý', resolved: 'Đã giải quyết' };
        let actionButtons = '';
        const assignedInfo = inc.assignedTo ? `<br><small style="color:#007bff"><i class="fas fa-user-hard-hat"></i> ${inc.assignedTo.fullName}</small>` : '';

        // ADMIN: Nếu mới -> Hiện nút Giao việc. Nếu đang xử lý -> Hiện ai đang làm.
        // 1. Nếu là Mới HOẶC (Đang xử lý nhưng chưa ai nhận - Sự cố cũ bị kẹt)
        if (inc.status === 'new' || (inc.status === 'in_progress' && !inc.assignedTo)) {
            const btnLabel = inc.status === 'new' ? 'Giao việc' : 'Giao lại (Cứu hộ)';
            const btnColor = inc.status === 'new' ? '#6f42c1' : '#dc3545'; // Màu Tím (Mới) hoặc Đỏ (Cứu hộ)
            
            actionButtons = `<button class="btn-assign" data-id="${inc._id}" style="background-color: ${btnColor}; color: white; border: none; padding: 6px 10px; border-radius: 5px; cursor: pointer; margin-right: 5px;">
                                <i class="fas fa-tasks"></i> ${btnLabel}
                             </button>`;
        } 
        // 2. Nếu đang xử lý và ĐÃ có người nhận chuẩn chỉ
        else if (inc.status === 'in_progress') {
            actionButtons = `<span style="color: #17a2b8; font-size: 12px; font-style: italic;">Đang xử lý bởi:<br><b>${inc.assignedTo ? inc.assignedTo.fullName : 'Kỹ sư'}</b></span>`;
        } 
        // 3. Đã hoàn thành
        else if (inc.status === 'resolved') {
            actionButtons = `<button class="delete-btn incident-delete-btn" data-id="${inc._id}"><i class="fas fa-trash"></i></button>`;
        }

        row.innerHTML = `<td>${new Date(inc.createdAt).toLocaleDateString('vi-VN')}</td><td>${departments[inc.departmentKey] || 'Không rõ'}</td><td>${inc.equipmentName}</td><td>${inc.serial}</td><td>${escapeHtml(inc.problemDescription)}</td><td><span class="incident-status ${inc.status}">${statusMap[inc.status]}</span></td><td class="action-btn-group">${actionButtons}</td>`;
        tableBody.appendChild(row);
    });
}

        function renderIncidentTableUser(incidents) {
            const tableBody = dom.incidentTableBodyUser;
            tableBody.innerHTML = '';
            if (incidents.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 30px;">Khoa của bạn chưa có báo cáo nào.</td></tr>`;
                return;
            }
            incidents.forEach(inc => {
                const row = document.createElement('tr');
                const statusMap = { new: 'Mới', in_progress: 'Đang xử lý', resolved: 'Đã giải quyết' };
                row.innerHTML = `<td>${new Date(inc.createdAt).toLocaleDateString('vi-VN')}</td><td>${inc.equipmentName}</td><td>${escapeHtml(inc.problemDescription)}</td><td><span class="incident-status ${inc.status}">${statusMap[inc.status]}</span></td><td>${inc.notes ? escapeHtml(inc.notes) : 'Chưa có'}</td>`;
                tableBody.appendChild(row);
            });
        }

        function renderIncidentTableTechnician(incidents) {
        const tableBody = dom.incidentTableBodyAdmin; // Tái sử dụng bảng Admin cho Kỹ sư
        tableBody.innerHTML = '';
        if (incidents.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 30px;">Bạn chưa được giao nhiệm vụ nào.</td></tr>`;
            return;
        }
        incidents.forEach(inc => {
            const row = document.createElement('tr');
            // Kỹ sư chỉ có nút "Hoàn thành"
            let btn = '';
            if (inc.status === 'in_progress') {
                btn = `<button class="resolve-btn" data-id="${inc._id}" data-new-status="resolved">Báo cáo Hoàn thành</button>`;
            } else {
                btn = '<span style="color:green"><i class="fas fa-check"></i> Xong</span>';
            }

            row.innerHTML = `
                <td>${new Date(inc.createdAt).toLocaleDateString('vi-VN')}</td>
                <td>${departments[inc.departmentKey]}</td>
                <td>${inc.equipmentName}</td>
                <td>${inc.serial}</td>
                <td>${escapeHtml(inc.problemDescription)}<br><small style="color:red">Ghi chú: ${escapeHtml(inc.notes || '')}</small></td>
                <td><span class="incident-status ${inc.status}">${inc.status}</span></td>
                <td>${btn}</td>
            `;
            tableBody.appendChild(row);
        });
        }

        dom.incidentForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = { equipmentSerial: dom.incidentEquipmentSelect.value, problemDescription: document.getElementById('problem-description').value };
            if(!payload.equipmentSerial || !payload.problemDescription) { 
                Swal.fire('Lỗi', 'Vui lòng điền đầy đủ thông tin.', 'warning');
                return; 
            }
            try {
                await fetchWithAuth(`${API_BASE_URL}/api/incidents`, { method: 'POST', body: JSON.stringify(payload) });
                Swal.fire('Thành công', 'Gửi báo cáo sự cố thành công!', 'success');
                dom.incidentForm.reset();
                renderIncidentView();
                if(userProfile.role === 'admin') { fetchNotifications(); }
            } catch (error) { handleApiError(error, "Gửi báo cáo"); }
        });
        
        dom.incidentTableBodyAdmin.addEventListener('click', async (e) => {
            // Tìm xem người dùng có bấm vào nút nào không (kể cả bấm vào icon bên trong nút)
            const target = e.target.closest('button');
            if (!target) return;

            const incidentId = target.dataset.id;

            // TRƯỜNG HỢP 1: Bấm nút GIAO VIỆC (MỚI)
            if (target.classList.contains('btn-assign')) {
                openAssignModal(incidentId); // Gọi hàm mở modal
                return;
            }

            // TRƯỜNG HỢP 2: Bấm nút XỬ LÝ / HOÀN THÀNH (CŨ)
            if (target.classList.contains('resolve-btn')) {
                const newStatus = target.dataset.newStatus;
                // Nếu là Kỹ sư bấm Hoàn thành -> Không cần nhập nhiều, xác nhận luôn
                if (userProfile.role === 'technician') {
                    Swal.fire({
                        title: 'Xác nhận hoàn thành?',
                        text: "Bạn đã xử lý xong sự cố này?",
                        icon: 'question',
                        showCancelButton: true,
                        confirmButtonText: 'Đúng, đã xong!'
                    }).then(async (result) => {
                        if (result.isConfirmed) {
                            try {
                                await fetchWithAuth(`${API_BASE_URL}/api/incidents/${incidentId}`, { 
                                    method: 'PUT', 
                                    body: JSON.stringify({ status: 'resolved' }) 
                                });
                                Swal.fire('Thành công', 'Đã báo cáo hoàn thành!', 'success');
                                renderIncidentView();
                            } catch(e) { handleApiError(e, "Hoàn thành"); }
                        }
                    });
                } else {
                    // Logic cũ cho Admin nhập ghi chú nhanh (nếu cần)
                    // ...
                }
            }

            // TRƯỜNG HỢP 3: Bấm nút XÓA
            if (target.classList.contains('incident-delete-btn')) {
                Swal.fire({
                    title: 'Xóa báo cáo?',
                    text: "Không thể hoàn tác!",
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonColor: '#d33',
                    confirmButtonText: 'Xóa'
                }).then(async (result) => {
                    if (result.isConfirmed) {
                        try {
                            await fetchWithAuth(`${API_BASE_URL}/api/incidents/${incidentId}`, { method: 'DELETE' });
                            Swal.fire('Đã xóa', '', 'success');
                            renderIncidentView();
                        } catch (error) { handleApiError(error, "Xóa"); }
                    }
                });
            }
        });
        
        document.getElementById('print-report-btn').addEventListener('click', () => {
            const selectedEquipmentOption = dom.incidentEquipmentSelect.options[dom.incidentEquipmentSelect.selectedIndex];
            const equipmentText = selectedEquipmentOption.value ? selectedEquipmentOption.text : '';
            const equipmentSerial = selectedEquipmentOption.value || '';
            let equipmentName = equipmentText;
            if (equipmentText.includes('(Serial:')) {
                equipmentName = equipmentText.split('(Serial:')[0].trim();
            }

            const reportData = {
                department: document.getElementById('incident-department').value,
                phone: document.getElementById('incident-phone').value,
                reportDate: document.getElementById('incident-date').value,
                equipmentName: equipmentName,
                serial: equipmentSerial,
                problem: document.getElementById('problem-description').value
            };

            const printContent = `
                <!DOCTYPE html>
                <html lang="vi">
                <head>
                    <title>Phiếu Báo Hỏng Thiết Bị Y Tế</title>
                    <style>
                        body { font-family: 'Times New Roman', Times, serif; font-size: 13pt; margin: 40px; color: black; }
                        .header { text-align: center; margin-bottom: 20px; }
                        .header h2 { font-size: 14pt; font-weight: bold; text-transform: uppercase; margin: 0; }
                        .section { margin-top: 15px; }
                        .section-title { font-weight: bold; text-transform: uppercase; margin-bottom: 10px; }
                        .info-line { margin-bottom: 8px; }
                        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12pt; }
                        th, td { border: 1px solid black; padding: 8px; text-align: left; vertical-align: top; }
                        th { font-weight: bold; text-align: center; white-space: nowrap; }
                        .signatures { display: flex; justify-content: space-evenly; align-items: flex-end; }
                        .signature-block { width: 30%; text-align: center; }
                        .signature-block .role { font-weight: bold; min-height: 4em; padding-bottom: 40px; }
                        .signature-block .signature-name { font-style: italic; }
                        .page-break { page-break-before: always; }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h2>PHIẾU BÁO HỎNG THIẾT BỊ Y TẾ</h2>
                    </div>
                    
                    <div class="section">
                        <p class="section-title">A. Phần báo hỏng</p>
                        <p class="info-line"><strong>I. Thông tin chung</strong></p>
                        <p class="info-line" style="margin-left: 20px;"><strong>Khoa báo hỏng:</strong> ${reportData.department}</p>
                        <p class="info-line" style="margin-left: 20px;"><strong>Số điện thoại:</strong> ${reportData.phone}</p>
                        <p class="info-line" style="margin-left: 20px;"><strong>Ngày báo hỏng:</strong> ${reportData.reportDate}</p>
                        <p class="info-line"><strong>II. Thông tin báo hỏng</strong></p>
                        <table>
                            <thead>
                                <tr><th>Tên thiết bị</th><th>Số serial</th><th>Nguyên nhân hỏng</th></tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td style="height: 80px;">${reportData.equipmentName}</td>
                                    <td>${reportData.serial}</td>
                                    <td>${reportData.problem}</td>
                                </tr>
                            </tbody>
                        </table>
                        <p class="info-line" style="margin-top: 15px;"><strong>III. Xác nhận từ khoa phòng</strong></p>
                        <div style="text-align: right; font-style: italic; margin-bottom: 10px;">Ngày...Tháng...Năm...</div>
                        <div class="signatures" style="justify-content: space-around;">
                            <div class="signature-block" style="width: 45%;">
                                <p class="role">Ý kiến của người có thẩm quyền giải quyết</p>
                                <p class="signature-name">(Ký, Họ tên)</p>
                            </div>
                            <div class="signature-block" style="width: 45%;">
                                <p class="role">Trưởng Khoa, Phòng</p>
                                <p class="signature-name">(Ký, Họ tên)</p>
                            </div>
                        </div>
                    </div>

                    <div class="section page-break">
                        <p class="section-title">B. Phần thực hiện sửa chữa</p>
                        <table>
                            <thead>
                                <tr><th rowspan="2">STT</th><th rowspan="2">Tên vật tư cần thay thế</th><th rowspan="2">Đơn vị tính</th><th colspan="3">Dự toán</th><th colspan="3">Quyết toán</th></tr>
                                <tr><th>S.lượng</th><th>Đ. Giá</th><th>T. Tiền</th><th>S.lượng</th><th>Đ. Giá</th><th>T. Tiền</th></tr>
                            </thead>
                            <tbody>
                                ${Array(4).fill('<tr><td style="height: 25px;"></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>').join('')}
                            </tbody>
                        </table>
                        <p class="info-line" style="margin-top: 10px;"><strong>Đã tạm ứng số tiền:</strong> .....................................................</p>
                        <p class="info-line"><strong>Phiếu chi số:</strong> ...................................................   Ngày...Tháng...Năm...</p>
                    </div>

                    <div class="section">
                        <p class="section-title">C. Xác nhận chung</p>
                        <div style="text-align: right; font-style: italic; margin-bottom: 10px;">Ngày...Tháng...Năm...</div>
                        <div class="signatures">
                            <div class="signature-block">
                                <p class="role">Khoa, Phòng xác nhận<br>công tác hoàn tất</p>
                                <p class="signature-name">(Ký, Họ tên)</p>
                            </div>
                            <div class="signature-block">
                                <p class="role">Phụ trách bộ phận SC</p>
                                <p class="signature-name">(Ký, Họ tên)</p>
                            </div>
                            <div class="signature-block">
                                <p class="role">Người thực hiện công tác</p>
                                <p class="signature-name">(Ký, Họ tên)</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
            `;

            const printWindow = window.open('', '', 'height=800,width=900');
            printWindow.document.write(printContent);
            printWindow.document.close();
            setTimeout(() => {
                printWindow.focus();
                printWindow.print();
            }, 250);
        });
        
        async function renderMaintenanceView() {
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/maintenance`);
                if (!response.ok) throw new Error("Không thể tải danh sách bảo trì");
                const schedules = await response.json();
                updateMaintenanceTable(schedules);
            } catch (error) {
                handleApiError(error, "Tải dữ liệu bảo trì");
            }
        }

        function updateMaintenanceTable(schedules) {
            const tableBody = dom.maintenanceTableBody;
            tableBody.innerHTML = ''; 

            if (schedules.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 30px;">Chưa có lịch bảo trì nào.</td></tr>`;
                return;
            }

            const statusMap = {
                scheduled: { text: 'Đã lên lịch', class: 'maintenance' },
                in_progress: { text: 'Đang tiến hành', class: 'info' },
                completed: { text: 'Hoàn thành', class: 'success' },
                canceled: { text: 'Đã hủy', class: 'inactive' }
            };

            schedules.forEach(item => {
                const row = document.createElement('tr');
                const deptName = departments[item.departmentKey] || 'N/A';
                const scheduleDate = new Date(item.scheduleDate).toLocaleDateString('vi-VN');
                const completionDate = item.completionDate ? new Date(item.completionDate).toLocaleDateString('vi-VN') : 'Chưa có';
                const statusInfo = statusMap[item.status] || { text: item.status, class: '' };

                let actionButtons = '';
                if (userProfile.role === 'admin') {
                    actionButtons = `
                        <button class="edit-btn" data-id="${item._id}"><i class="fas fa-edit"></i></button>
                        <button class="delete-btn" data-id="${item._id}"><i class="fas fa-trash"></i></button>
                    `;
                }

                row.innerHTML = `
                    <td>${item.equipmentName}</td>
                    <td>${item.serial}</td>
                    <td>${deptName}</td>
                    <td>${scheduleDate}</td>
                    <td>${completionDate}</td>
                    <td><span class="status ${statusInfo.class}">${statusInfo.text}</span></td>
                    <td class="action-btn-group">${actionButtons}</td>
                `;
                tableBody.appendChild(row);
            });
        }
        
        async function fetchNotifications() {
            try {
                const [countResponse, listResponse] = await Promise.all([
                    fetchWithAuth(`${API_BASE_URL}/api/incidents/unread/count`),
                    fetchWithAuth(`${API_BASE_URL}/api/incidents/unread`)
                ]);
                
                const countData = await countResponse.json();
                const listData = await listResponse.json();

                if (countData.count > 0) {
                    dom.notificationBadge.textContent = countData.count;
                    dom.notificationBadge.style.display = 'block';
                } else {
                    dom.notificationBadge.style.display = 'none';
                }

                renderNotificationDropdown(listData);
            } catch (error) {
                console.error("Lỗi khi lấy thông báo:", error);
            }
        }

        function renderNotificationDropdown(notifications) {
            dom.notificationList.innerHTML = '';
            if (notifications.length === 0) {
                dom.notificationList.innerHTML = '<div class="notification-item" style="text-align: center; color: #888;">Không có thông báo mới</div>';
                return;
            }
            notifications.forEach(item => {
                const deptName = departments[item.departmentKey] || 'Không rõ';
                const itemDiv = document.createElement('a');
                itemDiv.href = "#";
                itemDiv.className = 'notification-item';
                itemDiv.innerHTML = `
                    <p><strong>${deptName}</strong> đã báo hỏng thiết bị <strong>${item.equipmentName}</strong></p>
                    <span>${new Date(item.createdAt).toLocaleString('vi-VN')}</span>
                `;
                itemDiv.addEventListener('click', (e) => {
                    e.preventDefault();
                    switchView('incidents');
                    dom.notificationDropdown.classList.remove('show');
                });
                dom.notificationList.appendChild(itemDiv);
            });
        }
        
        dom.notificationBellContainer.addEventListener('click', (e) => {
            e.stopPropagation();
            dom.notificationDropdown.classList.toggle('show');
        });

        window.addEventListener('click', (e) => {
            if (!dom.notificationBellContainer.contains(e.target)) {
                dom.notificationDropdown.classList.remove('show');
            }
        });

        async function openMaintenanceModal(mode = 'add', data = null) {
            dom.maintenanceForm.reset();
            const editIdInput = document.getElementById('maintenance-edit-id');
            editIdInput.value = '';
            
            const selectedDept = dom.departmentSelect.value;
            if (!selectedDept) {
                Swal.fire('Lỗi', 'Vui lòng chọn một khoa trước khi lên lịch bảo trì.', 'error');
                return;
            }
            
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/${selectedDept}?limit=1000`);
                const equipmentData = await response.json();
                const selectElement = dom.maintenanceEquipmentSelect;
                selectElement.innerHTML = '<option value="">-- Chọn thiết bị --</option>';
                equipmentData.equipments.forEach(eq => {
                    const option = document.createElement('option');
                    option.value = eq.serial;
                    option.textContent = `${eq.name} (Serial: ${eq.serial})`;
                    selectElement.appendChild(option);
                });
            } catch (error) {
                handleApiError(error, "Tải danh sách thiết bị");
                return;
            }

            if (mode === 'edit' && data) {
                document.getElementById('maintenanceModalTitle').textContent = 'Chỉnh Sửa Lịch Bảo Trì';
                editIdInput.value = data._id;
                dom.maintenanceEquipmentSelect.value = data.serial;
                document.getElementById('scheduleDate').value = data.scheduleDate.split('T')[0];
                document.getElementById('maintenanceType').value = data.type;
                document.getElementById('maintenanceNotes').value = data.notes;
            } else {
                document.getElementById('maintenanceModalTitle').textContent = 'Lên Lịch Bảo Trì Mới';
            }
            dom.maintenanceModal.style.display = 'flex';
        }

        function closeMaintenanceModal() {
            dom.maintenanceModal.style.display = 'none';
        }

        dom.addMaintenanceBtn.addEventListener('click', () => openMaintenanceModal('add'));
        dom.closeMaintenanceModalBtn.addEventListener('click', closeMaintenanceModal);
        dom.cancelMaintenanceBtn.addEventListener('click', closeMaintenanceModal);
        window.addEventListener('click', (e) => {
            if (e.target === dom.maintenanceModal) closeMaintenanceModal();
        });

        dom.maintenanceForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const editId = document.getElementById('maintenance-edit-id').value;
            const isEditing = !!editId;

            const payload = {
                equipmentSerial: document.getElementById('maintenanceEquipmentSelect').value,
                scheduleDate: document.getElementById('scheduleDate').value,
                type: document.getElementById('maintenanceType').value,
                notes: document.getElementById('maintenanceNotes').value,
            };

            if (!payload.equipmentSerial || !payload.scheduleDate) {
                Swal.fire('Lỗi', 'Vui lòng chọn thiết bị và ngày lên lịch.', 'warning');
                return;
            }
            
            const url = isEditing ? `${API_BASE_URL}/api/maintenance/${editId}` : `${API_BASE_URL}/api/maintenance`;
            const method = isEditing ? 'PUT' : 'POST';

            try {
                const response = await fetchWithAuth(url, { method: method, body: JSON.stringify(payload) });
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || 'Thao tác thất bại.');
                }
                Swal.fire({
                    position: 'top-end',
                    icon: 'success',
                    title: isEditing ? 'Cập nhật thành công!' : 'Lên lịch bảo trì thành công!',
                    showConfirmButton: false,
                    timer: 1500
                });
                closeMaintenanceModal();
                renderMaintenanceView(); 
                fetchAndDisplayEquipment(dom.departmentSelect.value, 1);
            } catch (error) {
                handleApiError(error, isEditing ? 'Cập nhật bảo trì' : 'Lên lịch bảo trì');
            }
        });
        
        dom.maintenanceTableBody.addEventListener('click', async (e) => {
            const target = e.target.closest('button');
            if (!target) return;
            const maintenanceId = target.dataset.id;
            if (!maintenanceId) return;

            if (target.classList.contains('delete-btn')) {
                Swal.fire({
                    title: 'Bạn chắc chắn không?',
                    text: "Bạn sẽ không thể hoàn tác hành động này!",
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonColor: '#d33',
                    cancelButtonColor: '#3085d6',
                    confirmButtonText: 'Vâng, xóa nó!',
                    cancelButtonText: 'Hủy bỏ'
                }).then(async (result) => {
                    if (result.isConfirmed) {
                        try {
                            const response = await fetchWithAuth(`${API_BASE_URL}/api/maintenance/${maintenanceId}`, { method: 'DELETE' });
                            if (!response.ok) throw new Error('Xóa lịch bảo trì thất bại');
                            Swal.fire('Đã xóa!', 'Lịch bảo trì đã được xóa.', 'success');
                            renderMaintenanceView();
                        } catch (error) {
                            handleApiError(error, 'Xóa lịch bảo trì');
                        }
                    }
                });
            }

            if (target.classList.contains('edit-btn')) {
                try {
                    const response = await fetchWithAuth(`${API_BASE_URL}/api/maintenance/${maintenanceId}`);
                    if (!response.ok) throw new Error('Không thể lấy thông tin chi tiết.');
                    const data = await response.json();
                    openMaintenanceModal('edit', data);
                } catch(error) {
                    handleApiError(error, 'Lấy thông tin bảo trì');
                }
            }
        });
        
        // ========================================================
        // LOGIC CHO TRANG DASHBOARD
        // ========================================================
        let equipmentChartInstance = null;

        async function renderDashboardView() {
            if (userProfile.role !== 'admin' && userProfile.role !== 'technician') {
                dom.dashboardView.innerHTML = '<p>Bạn không có quyền truy cập trang này.</p>';
                return;
            }
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/dashboard/summary`);
                if (!response.ok) throw new Error("Không thể tải dữ liệu tổng quan");
                const data = await response.json();

                const totalEquipment = Object.values(data.equipmentStats).reduce((a, b) => a + b, 0);
                document.getElementById('db-total-equipment').textContent = totalEquipment;
                document.getElementById('db-new-incidents').textContent = data.newIncidentsCount;
                document.getElementById('db-upcoming-maintenance').textContent = data.upcomingMaintenanceCount;
                renderEquipmentChart(data.equipmentStats);
                renderRecentActivities(data.recentActivities);
            } catch (error) {
                handleApiError(error, "Tải dữ liệu Dashboard");
            }
        }

        function renderEquipmentChart(stats) {
            const ctx = document.getElementById('equipmentStatusChart').getContext('2d');
            const chartData = {
                labels: ['Hoạt động', 'Bảo trì', 'Ngừng hoạt động'],
                datasets: [{
                    label: 'Trạng thái thiết bị',
                    data: [stats.active, stats.maintenance, stats.inactive],
                    backgroundColor: [ 'rgba(40, 167, 69, 0.8)', 'rgba(255, 193, 7, 0.8)', 'rgba(220, 53, 69, 0.8)' ],
                    borderColor: [ 'rgba(40, 167, 69, 1)', 'rgba(255, 193, 7, 1)', 'rgba(220, 53, 69, 1)' ],
                    borderWidth: 1
                }]
            };
            if (equipmentChartInstance) { equipmentChartInstance.destroy(); }
            equipmentChartInstance = new Chart(ctx, {
                type: 'doughnut', data: chartData,
                options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'bottom' } } }
            });
        }

        function renderRecentActivities(activities) {
            const listElement = document.getElementById('recentActivityList');
            listElement.innerHTML = '';
            if (activities.length === 0) {
                listElement.innerHTML = '<li>Không có hoạt động nào gần đây.</li>';
                return;
            }
            activities.forEach(act => {
                const li = document.createElement('li');
                li.style.borderBottom = '1px solid #eee';
                li.style.padding = '12px 0';
                let icon, title, details;
                const deptName = departments[act.departmentKey] || 'Không rõ';
                if (act.type === 'incident') {
                    icon = '<i class="fas fa-triangle-exclamation" style="color: var(--danger-color); width: 20px;"></i>';
                    title = `<strong>Sự cố mới:</strong> ${act.equipmentName}`;
                    details = `Khoa ${deptName} vừa báo hỏng.`;
                } else {
                    icon = '<i class="fas fa-wrench" style="color: var(--warning-color); width: 20px;"></i>';
                    title = `<strong>Bảo trì:</strong> ${act.equipmentName}`;
                    details = `Lên lịch bởi ${act.createdBy} - Trạng thái: ${act.status}`;
                }
                li.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span style="font-size: 1.2rem;">${icon}</span>
                        <div style="flex-grow: 1;">
                            <p style="margin: 0; font-weight: 500;">${title}</p>
                            <small style="color: #6c757d;">${details}</small>
                        </div>
                        <small style="color: #6c757d;">${new Date(act.date).toLocaleDateString('vi-VN')}</small>
                    </div>`;
                listElement.appendChild(li);
            });
        }
        
        // ========================================================
        // LOGIC CHO TRANG HỒ SƠ THIẾT BỊ
        // ========================================================
        async function renderProfileView(serial) {
    if (!serial) {
        switchView('equipment');
        return;
    }

    const profileView = dom.profileView;
    profileView.innerHTML = '<p style="text-align:center; padding: 40px;">Đang tải hồ sơ thiết bị...</p>';

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/profile/${decodeURIComponent(serial)}`);
        if (!response.ok) throw new Error("Không thể tải hồ sơ thiết bị.");
        const data = await response.json();

        profileView.innerHTML = `
            <div class="main-header">
                <h1 class="view-title">Hồ sơ: ${data.details.name}</h1>
                <div class="header-actions">
                    <button id="print-qr-btn" class="action-button" style="background-color: var(--dark-color);"><i class="fas fa-print"></i> In Mã QR</button>
                    <button id="back-to-list-btn" class="action-button"><i class="fas fa-arrow-left"></i> Quay lại</button>
                </div>
            </div>
            
            <div id="profile-content" style="display: grid; grid-template-columns: 280px 1fr; gap: 25px;">
                <div id="profile-info-card">
                    <div id="qrcode-container" style="width: 250px; margin: 0 auto; padding: 15px; border: 1px solid #ddd; background: white; margin-bottom: 20px; text-align:center;"></div>
                    
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6; margin-bottom: 20px;">
                        <h4 style="color: var(--primary-color); margin-bottom: 10px; border-bottom: 1px solid #ccc; padding-bottom: 5px;">
                            <i class="fas fa-chart-line"></i> Phân tích Hiệu suất
                        </h4>
                        <div class="form-group" style="margin-bottom: 10px;">
                            <label style="font-size: 12px;">Từ ngày:</label>
                            <input type="date" id="eff-start-date" style="padding: 5px;">
                        </div>
                        <div class="form-group" style="margin-bottom: 10px;">
                            <label style="font-size: 12px;">Đến ngày:</label>
                            <input type="date" id="eff-end-date" style="padding: 5px;">
                        </div>
                        <button id="calc-efficiency-btn" style="width: 100%; padding: 8px; background: var(--success-color); color: white; border: none; border-radius: 4px; cursor: pointer;">
                            Tính toán
                        </button>
                        <div id="efficiency-result" style="margin-top: 15px; display: none; text-align: center;">
                            <div style="font-size: 30px; font-weight: bold; color: var(--primary-color);" id="eff-percent">0%</div>
                            <div style="font-size: 12px; color: #666;">Hiệu suất trung bình</div>
                            <div style="font-size: 13px; margin-top: 5px; font-weight: 500;" id="eff-hours">0h/ngày</div>
                        </div>
                    </div>
                    <div id="profile-details">
                        <h3 style="color: var(--primary-color); margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 10px;">Thông tin chi tiết</h3>
                        <div style="font-size: 15px; line-height: 2.2;">
                            <p><strong>Số Serial:</strong> ${data.details.serial}</p>
                            <p><strong>Hãng sản xuất:</strong> ${data.details.manufacturer}</p>
                            <p><strong>Năm sử dụng:</strong> ${data.details.year}</p>
                            <p><strong>Khoa:</strong> ${departments[data.details.department]}</p>
                            <p><strong>Tình trạng:</strong> <span class="status ${data.details.status}">${{active: 'Hoạt động', maintenance: 'Bảo trì', inactive: 'Ngừng HĐ'}[data.details.status]}</span></p>
                        </div>
                    </div>
                </div>
                
                <div id="profile-history">
                    <h3 style="margin-bottom: 15px; border-bottom: 2px solid var(--light-color); padding-bottom: 10px;">Lịch sử & Hồ sơ</h3>
                    <div>
                        <h4 style="margin-bottom: 10px; font-weight: 500;">Quản lý Hồ sơ & Tài liệu</h4>
                        <div class="document-section">
                            <form id="documentUploadForm">
                                <input type="hidden" id="doc-equipment-id" value="${data.details._id}">
                                <div class="form-row">
                                    <div class="form-group">
                                        <label>Loại tài liệu</label>
                                        <select id="documentType">
                                            <option value="contract">Hợp đồng</option>
                                            <option value="co">CO (Chứng nhận xuất xứ)</option>
                                            <option value="cq">CQ (Chứng nhận chất lượng)</option>
                                            <option value="inspection">Kiểm định</option>
                                            <option value="other">Khác</option>
                                        </select>
                                    </div>
                                    <div class="form-group">
                                        <label>Chọn file (PDF, ảnh)</label>
                                        <input type="file" id="documentFile" required>
                                    </div>
                                </div>
                                <button type="submit" class="action-button" style="width: 100%; justify-content: center;"><i class="fas fa-upload"></i> Tải lên</button>
                            </form>
                            <table class="generic-table" style="margin-top: 15px;">
                                <thead><tr><th>Loại</th><th>Tên File</th><th>Ngày Tải Lên</th><th>Hành Động</th></tr></thead>
                                <tbody id="document-list-tbody"></tbody>
                            </table>
                        </div>
                    </div>
                    <div>
                        <h4 style="margin-top: 20px; margin-bottom: 10px; font-weight: 500;">Nhật ký Sử dụng hàng tuần</h4>
                        <div style="max-height: 200px; overflow-y: auto; border: 1px solid #eee; border-radius: 5px; margin-bottom: 20px;"><table class="generic-table"><thead><tr><th>Ngày Ghi</th><th>Người Ghi</th><th>Tình Trạng</th><th>Ghi Chú</th></tr></thead><tbody id="usage-log-tbody"></tbody></table></div>
                    </div>
                    <div>
                        <h4 style="margin-bottom: 10px; font-weight: 500;">Lịch sử Sự cố</h4>
                        <div style="max-height: 200px; overflow-y: auto; border: 1px solid #eee; border-radius: 5px; margin-bottom: 20px;"><table class="generic-table"><thead><tr><th>Ngày báo cáo</th><th>Mô tả</th><th>Trạng thái</th></tr></thead><tbody id="profile-incidents-tbody"></tbody></table></div>
                    </div>
                    <div>
                        <h4 style="margin-bottom: 10px; font-weight: 500;">Lịch sử Bảo trì</h4>
                        <div style="max-height: 200px; overflow-y: auto; border: 1px solid #eee; border-radius: 5px;"><table class="generic-table"><thead><tr><th>Ngày lên lịch</th><th>Ngày hoàn thành</th><th>Trạng thái</th></tr></thead><tbody id="profile-maintenance-tbody"></tbody></table></div>
                    </div>
                </div>
            </div>`;

        // --- CODE MỚI: XỬ LÝ NÚT TÍNH HIỆU SUẤT ---
        // Set mặc định ngày: Đầu tháng đến Hôm nay
        const today = new Date();
        const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
        document.getElementById('eff-end-date').value = today.toISOString().split('T')[0];
        document.getElementById('eff-start-date').value = firstDay.toISOString().split('T')[0];

        document.getElementById('calc-efficiency-btn').addEventListener('click', async () => {
            const start = document.getElementById('eff-start-date').value;
            const end = document.getElementById('eff-end-date').value;
            const resultBox = document.getElementById('efficiency-result');

            if(!start || !end) { Swal.fire('Lỗi', 'Vui lòng chọn ngày', 'warning'); return; }

            // Hiệu ứng loading nhẹ
            document.getElementById('calc-efficiency-btn').textContent = 'Đang tính...';
            
            try {
                const res = await fetchWithAuth(`${API_BASE_URL}/api/reports/machine-efficiency`, {
                    method: 'POST',
                    body: JSON.stringify({ equipmentId: data.details._id, startDate: start, endDate: end })
                });
                const report = await res.json();
                
                // Hiển thị kết quả
                document.getElementById('eff-percent').textContent = `${report.efficiencyPercent}%`;
                
                // Tô màu theo mức độ
                const p = parseFloat(report.efficiencyPercent);
                const color = p > 80 ? '#dc3545' : (p > 50 ? '#ffc107' : '#28a745');
                document.getElementById('eff-percent').style.color = color;

                document.getElementById('eff-hours').textContent = `TB: ${report.avgHoursPerDay} giờ / ngày`;
                resultBox.style.display = 'block';

            } catch (err) {
                console.error(err);
                Swal.fire('Lỗi', 'Không thể tính toán', 'error');
            } finally {
                document.getElementById('calc-efficiency-btn').textContent = 'Tính toán';
            }
        });
        
        // --- LOGIC MỚI: TẢI VÀ HIỂN THỊ NHẬT KÝ SỬ DỤNG ---
        const logResponse = await fetchWithAuth(`${API_BASE_URL}/api/logs/equipment/${data.details._id}`);
        const logs = await logResponse.json();
        renderUsageLogHistory(logs);
        // ----------------------------------------------------
        // --- CHỈ THÊM 2 DÒNG NÀY ĐỂ SỬA LỖI ẨN TÀI LIỆU ---
        fetchWithAuth(`${API_BASE_URL}/api/documents/${data.details._id}`).then(res => res.json()).then(docs => renderDocumentList(docs));
        fetchWithAuth(`${API_BASE_URL}/api/logs/equipment/${data.details._id}`).then(res => res.json()).then(logs => renderUsageLogHistory(logs));
        // Tạo QR Code
        const qrCodeContainer = document.getElementById('qrcode-container');
        new QRCode(qrCodeContainer, {
            text: `https://resilient-dieffenbachia-5881b7.netlify.app/qr-landing.html?serial=${encodeURIComponent(data.details.serial)}`,
            width: 220, height: 220, colorDark : "#000000", colorLight : "#ffffff", correctLevel : QRCode.CorrectLevel.H
        });
        
        // Gắn sự kiện cho các nút
        document.getElementById('back-to-list-btn').addEventListener('click', () => switchView('equipment'));
        document.getElementById('print-qr-btn').addEventListener('click', () => {
            const qrImageSrc = qrCodeContainer.querySelector('img').src;
            printQRCode(qrImageSrc, data.details.name, data.details.serial, departments[data.details.department]);
        });

        // Gắn sự kiện cho form upload và danh sách tài liệu
        document.getElementById('documentUploadForm').addEventListener('submit', handleDocumentUpload);
        document.getElementById('document-list-tbody').addEventListener('click', handleDocumentDelete);

        // Đổ dữ liệu vào các bảng lịch sử (giữ nguyên)
        const incidentBody = document.getElementById('profile-incidents-tbody');
        if (data.incidents.length > 0) {
            incidentBody.innerHTML = '';
            data.incidents.forEach(inc => {
                const statusMap = { new: 'Mới', in_progress: 'Đang xử lý', resolved: 'Đã giải quyết' };
                incidentBody.innerHTML += `<tr><td>${new Date(inc.createdAt).toLocaleDateString('vi-VN')}</td><td>${escapeHtml(inc.problemDescription)}</td><td><span class="incident-status ${inc.status}">${statusMap[inc.status]}</span></td></tr>`;
            });
        } else { incidentBody.innerHTML = '<tr><td colspan="3" style="text-align:center;">Không có lịch sử sự cố.</td></tr>'; }

        const maintenanceBody = document.getElementById('profile-maintenance-tbody');
        if (data.maintenanceHistory.length > 0) {
             maintenanceBody.innerHTML = '';
             const statusMap = { scheduled: 'Đã lên lịch', in_progress: 'Đang tiến hành', completed: 'Hoàn thành', canceled: 'Đã hủy' };
             data.maintenanceHistory.forEach(main => {
                maintenanceBody.innerHTML += `<tr><td>${new Date(main.scheduleDate).toLocaleDateString('vi-VN')}</td><td>${main.completionDate ? new Date(main.completionDate).toLocaleDateString('vi-VN') : 'Chưa có'}</td><td><span class="status ${main.status}">${statusMap[main.status]}</span></td></tr>`;
            });
        } else { maintenanceBody.innerHTML = '<tr><td colspan="3" style="text-align:center;">Không có lịch sử bảo trì.</td></tr>'; }

    } catch (error) {
        handleApiError(error, "Tải hồ sơ thiết bị");
        profileView.innerHTML = '<p style="text-align:center; padding: 40px; color: var(--danger-color);">Đã xảy ra lỗi khi tải dữ liệu.</p>';
    }
}

        // ========================================================
        // LOGIC CHO QUẢN LÝ NGƯỜI DÙNG
        // ========================================================
        async function renderUsersView() {
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/users`);
                if (!response.ok) throw new Error("Không thể tải danh sách người dùng");
                const users = await response.json();
                
                dom.usersTableBody.innerHTML = '';
                if (users.length === 0) {
                    dom.usersTableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 30px;">Không có người dùng nào.</td></tr>`;
                    return;
                }
                users.forEach(user => {
                    const row = document.createElement('tr');
                    const deptName = departments[user.departmentKey] || 'Chưa gán';
                    row.innerHTML = `
                        <td>${user.username}</td>
                        <td>${deptName}</td>
                        <td>${new Date(user.createdAt).toLocaleDateString('vi-VN')}</td>
                        <td class="action-btn-group">
                            <button class="edit-btn user-edit-btn" data-id="${user._id}"><i class="fas fa-edit"></i></button>
                            <button class="delete-btn user-delete-btn" data-id="${user._id}" data-username="${user.username}"><i class="fas fa-trash"></i></button>
                        </td>
                    `;
                    dom.usersTableBody.appendChild(row);
                });
            } catch (error) {
                handleApiError(error, "Tải danh sách người dùng");
            }
        }

        function openUserModal(mode = 'add', userData = null) {
            dom.userForm.reset();
            document.getElementById('edit-userId').value = '';
            const userPassInput = document.getElementById('userPassword');
            const userUsernameInput = document.getElementById('userUsername');
            
            const deptSelect = document.getElementById('userDepartment');
            deptSelect.innerHTML = '<option value="">-- Chọn khoa --</option>';
            for (const key in departments) {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = departments[key];
                deptSelect.appendChild(option);
            }
            
            if (mode === 'edit' && userData) {
                document.getElementById('userModalTitle').textContent = 'Chỉnh sửa Người dùng';
                document.getElementById('edit-userId').value = userData._id;
                userUsernameInput.value = userData.username;
                userUsernameInput.readOnly = true;
                deptSelect.value = userData.departmentKey;
                userPassInput.required = false;
            } else {
                document.getElementById('userModalTitle').textContent = 'Thêm Người dùng mới';
                userUsernameInput.readOnly = false;
                userPassInput.required = true;
            }
            dom.userModal.style.display = 'flex';
        }

        function closeUserModal() {
            dom.userModal.style.display = 'none';
        }

        dom.addUserBtn.addEventListener('click', () => openUserModal('add'));
        dom.closeUserModalBtn.addEventListener('click', closeUserModal);
        dom.cancelUserBtn.addEventListener('click', closeUserModal);
        window.addEventListener('click', (e) => {
            if (e.target === dom.userModal) closeUserModal();
        });

        dom.userForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userId = document.getElementById('edit-userId').value;
            const isEditing = !!userId;
            
            const payload = {
                username: document.getElementById('userUsername').value,
                password: document.getElementById('userPassword').value,
                departmentKey: document.getElementById('userDepartment').value
            };

            if (isEditing && !payload.password) {
                delete payload.password;
            }

            const url = isEditing ? `${API_BASE_URL}/api/users/${userId}` : `${API_BASE_URL}/api/users`;
            const method = isEditing ? 'PUT' : 'POST';

            try {
                const response = await fetchWithAuth(url, { method: method, body: JSON.stringify(payload) });
                if (!response.ok) {
                    const errData = await response.json();
                    throw new Error(errData.message);
                }
                Swal.fire('Thành công', `Thao tác với người dùng ${payload.username} thành công!`, 'success');
                closeUserModal();
                renderUsersView();
            } catch (error) {
                handleApiError(error, "Lưu người dùng");
            }
        });

        dom.usersTableBody.addEventListener('click', (e) => {
            const deleteBtn = e.target.closest('.user-delete-btn');
            if (deleteBtn) {
                const userId = deleteBtn.dataset.id;
                const username = deleteBtn.dataset.username;
                Swal.fire({
                    title: `Bạn có chắc muốn xóa người dùng "${username}"?`,
                    text: "Hành động này không thể hoàn tác!",
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonColor: '#d33',
                    cancelButtonText: 'Hủy'
                }).then(async (result) => {
                    if (result.isConfirmed) {
                        try {
                            await fetchWithAuth(`${API_BASE_URL}/api/users/${userId}`, { method: 'DELETE' });
                            Swal.fire('Đã xóa!', 'Người dùng đã được xóa.', 'success');
                            renderUsersView();
                        } catch (error) {
                            handleApiError(error, "Xóa người dùng");
                        }
                    }
                });
                return;
            }

            const editBtn = e.target.closest('.user-edit-btn');
            if (editBtn) {
                const userId = editBtn.dataset.id;
                const row = editBtn.closest('tr');
                const username = row.cells[0].textContent;
                const deptName = row.cells[1].textContent;
                const deptKey = Object.keys(departments).find(key => departments[key] === deptName);
                
                openUserModal('edit', { _id: userId, username: username, departmentKey: deptKey });
            }
        });

        async function checkAuth() {
        const token = getToken();
        if (!token) { showLoginView(); return; }
        userProfile = getUserProfile();
        if(!userProfile || !userProfile.role) { logout(); return; }
        try {
        await loadInitialData();
        showMainAppView();
        
        // Phân luồng hiển thị sau khi đăng nhập
        if (userProfile.role === 'admin' || userProfile.role === 'technician') switchView('dashboard');
                else switchView('equipment');

    } catch (error) { logout(); }
}

        dom.loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            dom.loginError.textContent = '';
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            try {
                const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.message || 'Đăng nhập thất bại.');
                saveToken(data.token);
                saveUserProfile(data.token);
                await checkAuth();
            } catch (error) {
                dom.loginError.textContent = error.message;
            }
        });
        
        dom.logoutBtn.addEventListener('click', logout);
        // ========================================================
        // LOGIC NHẬP FILE EXCEL (TÍNH NĂNG MỚI)
        // ========================================================
       const importBtn = document.getElementById('importExcelBtn');
       const fileInput = document.getElementById('excelFileInput');

importBtn.addEventListener('click', () => {
    // Khi bấm nút "Nhập", ta sẽ kích hoạt input file ẩn
    fileInput.click();
});

fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const selectedDeptKey = dom.departmentSelect.value;
    if (!selectedDeptKey) {
        Swal.fire('Lỗi', 'Vui lòng chọn một khoa trước khi nhập dữ liệu!', 'warning');
        return;
    }

    Swal.fire({
        title: 'Đang xử lý file...',
        text: 'Vui lòng chờ trong giây lát.',
        allowOutsideClick: false,
        didOpen: () => {
            Swal.showLoading();
        }
    });

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const data = new Uint8Array(e.target.result);
            const workbook = XLSX.read(data, { type: 'array' });
            const firstSheetName = workbook.SheetNames[0];
            const worksheet = workbook.Sheets[firstSheetName];
            
            // Chuyển sheet thành JSON
            const jsonData = XLSX.utils.sheet_to_json(worksheet);

            if (jsonData.length === 0) {
                throw new Error("File Excel rỗng hoặc không có dữ liệu.");
            }

            // Map tên cột trong Excel sang key của API
            const mappedData = jsonData.map(row => ({
                name: row['Tên Thiết Bị'],
                serial: row['Số Serial'],
                manufacturer: row['Hãng Sản Xuất'],
                year: row['Năm Sử Dụng'],
                accessories: row['Phụ Kiện'],
                description: row['Mô Tả']
            }));

            // Lọc ra những dòng không có Tên hoặc Serial
            const validData = mappedData.filter(item => item.name && item.serial);
            const invalidCount = mappedData.length - validData.length;

            if (validData.length === 0) {
                throw new Error("Không có dòng dữ liệu hợp lệ nào (thiếu Tên hoặc Serial).");
            }
            
            const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/batch-import/${selectedDeptKey}`, {
                method: 'POST',
                body: JSON.stringify(validData)
            });

            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.message || "Lỗi không xác định từ server.");
            }

            let resultText = `${result.message}`;
            if (invalidCount > 0) {
                resultText += ` Ngoài ra, có ${invalidCount} dòng bị bỏ qua do thiếu Tên hoặc Serial.`;
            }
            if (result.errors && result.errors.length > 0) {
                resultText += '<br><br><strong>Chi tiết lỗi:</strong><br>' + result.errors.join('<br>');
            }

            Swal.fire({
                title: 'Hoàn tất!',
                html: resultText,
                icon: 'success'
            });

            // Tải lại danh sách thiết bị để thấy dữ liệu mới
            fetchAndDisplayEquipment(selectedDeptKey, 1);

        } catch (error) {
            handleApiError(error, "Nhập dữ liệu từ Excel");
        } finally {
            // Reset input file để có thể chọn lại cùng 1 file
            fileInput.value = '';
        }
    };
    reader.readAsArrayBuffer(file);
});
        function printQRCode(qrImageSrc, equipmentName, serial, departmentName) {
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <html>
            <head>
                <title>In Mã QR - ${equipmentName}</title>
                <style>
                    /* Quy định khổ giấy và loại bỏ lề mặc định của trình duyệt */
                    @page {
                        size: A4;
                        margin: 0;
                    }
                    body {
                        margin: 0;
                        padding: 1cm; /* Thêm một chút lề để tránh bị cắt khi in */
                        box-sizing: border-box;
                        font-family: 'Roboto', sans-serif;
                        width: 210mm; /* Chiều rộng khổ A4 */
                        height: 297mm; /* Chiều cao khổ A4 */
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;
                    }
                    .print-container {
                        text-align: center;
                        border: 3px solid black;
                        padding: 20px;
                        width: 180mm; /* Chiều rộng vùng nội dung */
                    }
                    /* Phóng to ảnh QR Code */
                    img {
                        width: 150mm;
                        height: 150mm;
                        display: block;
                        margin: 0 auto 20mm; /* Canh giữa và tạo khoảng cách với text */
                    }
                    /* Phóng to chữ */
                    h3 {
                        margin: 10mm 0 5mm 0;
                        font-size: 28pt;
                        font-weight: bold;
                    }
                    p {
                        margin: 3mm 0;
                        font-size: 20pt;
                    }
                </style>
            </head>
            <body>
                <div class="print-container">
                    <img src="${qrImageSrc}" alt="QR Code">
                    <h3>${equipmentName}</h3>
                    <p>Serial: ${serial}</p>
                    <p>Khoa: ${departmentName || 'N/A'}</p>
                </div>
                <script>
                    window.onload = function() {
                        window.print();
                        window.onafterprint = function() {
                            window.close();
                        }
                    }
                <\/script>
            </body>
        </html>
    `);
    printWindow.document.close();
}

        // LOGIC CHO TRANG BÁO CÁO (TÍNH NĂNG MỚI)
// ========================================================
let departmentChartInstance = null;

function renderReportsView() {
    // Đặt ngày mặc định là ngày đầu tháng và ngày hiện tại
    const today = new Date();
    const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    
    // Định dạng lại cho đúng với input type="date" (YYYY-MM-DD)
    dom.reportStartDate.value = firstDayOfMonth.toISOString().split('T')[0];
    dom.reportEndDate.value = today.toISOString().split('T')[0];
}

dom.viewReportBtn.addEventListener('click', async () => {
    const startDate = dom.reportStartDate.value;
    const endDate = dom.reportEndDate.value;

    if (!startDate || !endDate) {
        Swal.fire('Lỗi', 'Vui lòng chọn đầy đủ ngày bắt đầu và kết thúc.', 'warning');
        return;
    }

    Swal.fire({
        title: `Đang tạo báo cáo từ ${startDate} đến ${endDate}...`,
        allowOutsideClick: false,
        didOpen: () => { Swal.showLoading(); }
    });

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/api/reports/monthly-summary?startDate=${startDate}&endDate=${endDate}`);
        if(!response.ok) {
            const errData = await response.json();
            throw new Error(errData.message);
        }
        const data = await response.json();

        // Hiển thị kết quả (logic này giữ nguyên)
        document.getElementById('report-total-incidents').textContent = data.totalIncidents;
        document.getElementById('report-resolved-incidents').textContent = data.resolvedIncidents;
        const resolutionRate = data.totalIncidents > 0 ? ((data.resolvedIncidents / data.totalIncidents) * 100).toFixed(1) : 0;
        document.getElementById('report-resolution-rate').textContent = `${resolutionRate}%`;
        renderDepartmentChart(data.incidentsByDepartment);
        dom.reportResults.style.display = 'block';
        Swal.close();

        // --- LOGIC MỚI ĐỂ HIỂN THỊ NÚT IN ---
        const printBtn = document.getElementById('printReportBtn');
        printBtn.style.display = 'inline-flex'; // Hiển thị nút
        // Gắn sự kiện click để gọi hàm in với dữ liệu vừa lấy được
        printBtn.onclick = () => printMonthlyReport(data, startDate, endDate); 
        // ------------------------------------

    } catch (error) {
        handleApiError(error, "Tạo báo cáo");
    }
});

// Thêm logic cho các nút chọn nhanh
document.querySelectorAll('.preset-btn').forEach(button => {
    button.addEventListener('click', () => {
        const range = button.dataset.range;
        const today = new Date();
        let startDate, endDate;

        if (range === 'this-month') {
            startDate = new Date(today.getFullYear(), today.getMonth(), 1);
            endDate = today;
        } else if (range === 'last-month') {
            startDate = new Date(today.getFullYear(), today.getMonth() - 1, 1);
            endDate = new Date(today.getFullYear(), today.getMonth(), 0);
        } else if (range === 'this-year') {
            startDate = new Date(today.getFullYear(), 0, 1);
            endDate = today;
        }
        
        dom.reportStartDate.value = startDate.toISOString().split('T')[0];
        dom.reportEndDate.value = endDate.toISOString().split('T')[0];
        // Tự động bấm nút xem báo cáo
        dom.viewReportBtn.click();
    });
});

function renderDepartmentChart(chartData) {
    const ctx = document.getElementById('departmentReportChart').getContext('2d');
    const labels = chartData.map(d => d.departmentName);
    const data = chartData.map(d => d.count);

    if (departmentChartInstance) {
        departmentChartInstance.destroy();
    }

    departmentChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Số sự cố',
                data: data,
                backgroundColor: 'rgba(220, 53, 69, 0.7)',
                borderColor: 'rgba(220, 53, 69, 1)',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}
        // LOGIC IN QR CODE HÀNG LOẠT
// ========================================================
document.getElementById('bulkPrintQrBtn').addEventListener('click', async () => {
    const selectedDeptKey = dom.departmentSelect.value;
    if (!selectedDeptKey) {
        Swal.fire('Lỗi', 'Vui lòng chọn một khoa để in QR hàng loạt!', 'warning');
        return;
    }
    const departmentName = departments[selectedDeptKey];

    Swal.fire({
        title: `Đang tạo file in cho khoa ${departmentName}...`,
        text: 'Việc này có thể mất một lúc tùy vào số lượng thiết bị. Vui lòng chờ.',
        allowOutsideClick: false,
        didOpen: () => { Swal.showLoading(); }
    });

    try {
        // Lấy TẤT CẢ thiết bị của khoa (đặt limit rất lớn)
        const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/${selectedDeptKey}?limit=10000`);
        if (!response.ok) throw new Error("Không thể tải danh sách thiết bị.");
        
        const data = await response.json();
        const equipments = data.equipments;

        if (equipments.length === 0) {
            Swal.fire('Thông báo', `Khoa ${departmentName} không có thiết bị nào để in.`, 'info');
            return;
        }

        // Mở một cửa sổ mới để chuẩn bị nội dung in
        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <html>
                <head>
                    <title>In Hàng Loạt Mã QR - ${departmentName}</title>
                    <style>
                        @page { size: A4; margin: 0; }
                        body { margin: 0; padding: 0; font-family: 'Roboto', sans-serif; }
                        .page-container {
                            width: 210mm;
                            height: 297mm;
                            padding: 1cm;
                            box-sizing: border-box;
                            display: flex;
                            flex-direction: column;
                            justify-content: center;
                            align-items: center;
                            page-break-after: always; /* Quan trọng: Ngắt trang sau mỗi mã QR */
                        }
                        .print-container { text-align: center; border: 3px solid black; padding: 20px; width: 180mm; }
                        img { width: 150mm; height: 150mm; display: block; margin: 0 auto 20mm; }
                        h3 { margin: 10mm 0 5mm 0; font-size: 28pt; font-weight: bold; }
                        p { margin: 3mm 0; font-size: 20pt; }
                    </style>
                </head>
                <body>
                    </body>
            </html>
        `);

        // Tạo một div ẩn để sinh mã QR
        const tempQrDiv = document.createElement('div');
        tempQrDiv.style.display = 'none';
        document.body.appendChild(tempQrDiv);

        // Lặp qua từng thiết bị để tạo HTML cho từng trang
        for (const equipment of equipments) {
            tempQrDiv.innerHTML = ''; // Xóa QR cũ
            new QRCode(tempQrDiv, {
                text: `https://resilient-dieffenbachia-5881b7.netlify.app/qr-landing.html?serial=${encodeURIComponent(equipment.serial)}`,
                width: 600,
                height: 600,
                correctLevel : QRCode.CorrectLevel.H
            });
            
            const canvas = tempQrDiv.querySelector('canvas');
            const qrImageSrc = canvas.toDataURL("image/png");
            const pageHtml = `
                <div class="page-container">
                    <div class="print-container">
                        <img src="${qrImageSrc}" alt="QR Code">
                        <h3>${equipment.name}</h3>
                        <p>Serial: ${equipment.serial}</p>
                        <p>Khoa: ${departmentName}</p>
                    </div>
                </div>
            `;
            printWindow.document.body.innerHTML += pageHtml;
        }

        document.body.removeChild(tempQrDiv); // Xóa div tạm
        
        // Thêm script để tự động mở hộp thoại in
        const printScript = printWindow.document.createElement('script');
        printScript.innerHTML = `
            window.onload = function() {
                window.print();
                window.onafterprint = function() { window.close(); }
            }
        `;
        printWindow.document.body.appendChild(printScript);
        printWindow.document.close();
        Swal.close();

    } catch (error) {
        handleApiError(error, "Tạo file in hàng loạt");
    }
});
        // LOGIC IN BÁO CÁO (TÍNH NĂNG MỚI)
// ========================================================
function printMonthlyReport(reportData, startDate, endDate) {
    // Lấy ảnh của biểu đồ
    const chartImage = departmentChartInstance ? departmentChartInstance.toBase64Image() : '';

    // Tạo bảng HTML cho danh sách khoa phòng
    let departmentRows = '';
    reportData.incidentsByDepartment.forEach(dept => {
        departmentRows += `<tr><td>${dept.departmentName}</td><td>${dept.count}</td></tr>`;
    });
    if (reportData.incidentsByDepartment.length === 0) {
        departmentRows = '<tr><td colspan="2">Không có dữ liệu.</td></tr>';
    }

    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <html>
            <head>
                <title>Báo cáo Sự cố từ ${startDate} đến ${endDate}</title>
                <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
                <style>
                    @page { size: A4; margin: 1.5cm; }
                    body { font-family: 'Roboto', sans-serif; color: #333; }
                    h1 { text-align: center; color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
                    h2 { color: #343a40; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 30px;}
                    .summary-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; text-align: center; margin: 20px 0; }
                    .summary-card { background-color: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #eee; }
                    .summary-card .value { font-size: 28px; font-weight: bold; color: #007bff; }
                    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                    th, td { border: 1px solid #ccc; padding: 10px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    .chart-container { text-align: center; margin-top: 30px; }
                    .chart-container img { max-width: 90%; }
                </style>
            </head>
            <body>
                <h1>BÁO CÁO TÌNH HÌNH SỰ CỐ THIẾT BỊ</h1>
                <p style="text-align: center;">Thời gian: Từ ngày ${startDate} đến ngày ${endDate}</p>
                
                <h2>I. Tóm tắt số liệu</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <p>Tổng Sự Cố</p>
                        <p class="value">${reportData.totalIncidents}</p>
                    </div>
                    <div class="summary-card">
                        <p>Đã Giải Quyết</p>
                        <p class="value">${reportData.resolvedIncidents}</p>
                    </div>
                    <div class="summary-card">
                        <p>Tỷ Lệ Giải Quyết</p>
                        <p class="value">${reportData.totalIncidents > 0 ? ((reportData.resolvedIncidents / reportData.totalIncidents) * 100).toFixed(1) : 0}%</p>
                    </div>
                </div>

                <h2>II. Thống kê theo Khoa/Phòng</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Tên Khoa/Phòng</th>
                            <th>Số lượng Sự cố</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${departmentRows}
                    </tbody>
                </table>
                
                <div class="chart-container">
                    <h2>III. Biểu đồ trực quan</h2>
                    <img src="${chartImage}" alt="Biểu đồ thống kê">
                </div>
            </body>
        </html>
    `);
    printWindow.document.close();
    
    // Đợi ảnh và CSS tải xong rồi mới in
    setTimeout(() => {
        printWindow.print();
        printWindow.close();
    }, 500);
}
// LOGIC CHO MODAL GHI NHẬT KÝ SỬ DỤNG
// ========================================================
function openUsageLogModal(equipment) {
    dom.usageLogForm.reset();
    document.getElementById('log-equipment-id').value = equipment._id;
    document.getElementById('log-equipment-name').value = equipment.name;
    dom.usageLogModal.style.display = 'flex';
}

function closeUsageLogModal() {
    dom.usageLogModal.style.display = 'none';
}
dom.usageLogForm.addEventListener('submit', async (e) => {
    e.preventDefault(); // Ngăn trang tải lại
    const payload = {
        equipmentId: document.getElementById('log-equipment-id').value,
        status: document.getElementById('logStatus').value,
        notes: document.getElementById('logNotes').value
    };

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/api/logs`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.message);
        }
        await Swal.fire('Thành công', 'Đã ghi lại nhật ký sử dụng cho thiết bị.', 'success');
        closeUsageLogModal();
        fetchAndDisplayEquipment(dom.departmentSelect.value, 1); // Tải lại để cập nhật dấu !
    } catch (error) {
        handleApiError(error, "Ghi nhật ký");
    }
});

document.getElementById('bulkLogSubmitBtn').addEventListener('click', () => {
    const status = document.getElementById('logStatus').value;
    const notes = document.getElementById('logNotes').value;

    Swal.fire({
        title: 'Xác nhận Ghi hàng loạt?',
        text: `Bạn có chắc muốn áp dụng tình trạng này cho tất cả thiết bị còn lại trong khoa?`,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Vâng, xác nhận!',
        cancelButtonText: 'Hủy'
    }).then(async (result) => {
        if (result.isConfirmed) {
            Swal.fire({
                title: 'Đang xử lý...',
                allowOutsideClick: false,
                didOpen: () => { Swal.showLoading() }
            });
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/logs/bulk`, {
                    method: 'POST',
                    body: JSON.stringify({ status, notes })
                });
                const resultData = await response.json();
                if (!response.ok) throw new Error(resultData.message);

                await Swal.fire('Thành công!', resultData.message, 'success');
                closeUsageLogModal();
                fetchAndDisplayEquipment(dom.departmentSelect.value, 1); // Tải lại danh sách để xóa các dấu '!'
            } catch (error) {
                handleApiError(error, "Ghi nhật ký hàng loạt");
            }
        }
    });
});

dom.closeUsageLogModalBtn.addEventListener('click', closeUsageLogModal);
window.addEventListener('click', (e) => {
    if (e.target === dom.usageLogModal) closeUsageLogModal();
});

dom.usageLogForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
        equipmentId: document.getElementById('log-equipment-id').value,
        status: document.getElementById('logStatus').value,
        notes: document.getElementById('logNotes').value
    };

    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/api/logs`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.message);
        }
        Swal.fire('Thành công', 'Đã ghi lại nhật ký sử dụng cho thiết bị.', 'success');
        closeUsageLogModal();
    } catch (error) {
        handleApiError(error, "Ghi nhật ký");
    }
});

        // Dán hàm này vào cuối thẻ script
function renderUsageLogHistory(logs) {
    const logBody = document.getElementById('usage-log-tbody');
    if (!logBody) return; 
    logBody.innerHTML = '';

    if (logs.length === 0) {
        logBody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Chưa có nhật ký sử dụng.</td></tr>';
        return;
    }

    const statusMap = {
        operational: 'Hoạt động tốt',
        minor_issue: 'Có vấn đề nhỏ',
        not_in_use: 'Không sử dụng'
    };

    logs.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(log.createdAt).toLocaleDateString('vi-VN')}</td>
            <td>${log.loggedBy}</td>
            <td>${statusMap[log.status] || log.status}</td>
            <td>${log.notes || ''}</td>
        `;
        logBody.appendChild(row);
    });
}

          // LOGIC CHO DASHBOARD CỦA USER
// ========================================================


async function renderUserDashboard() {
    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/api/dashboards/user`);
        if (!response.ok) throw new Error("Không thể tải dữ liệu dashboard.");
        const data = await response.json();

        // Cập nhật thẻ KPI
        document.getElementById('user-total-equipment').textContent = data.totalEquipment || 0;
        document.getElementById('user-attention-equipment').textContent = data.incidentsInProgressCount || 0;
        document.getElementById('user-active-equipment').textContent = data.equipmentStatusStats.active || 0;

        // Vẽ biểu đồ
        renderUserEquipmentChart(data.equipmentStatusStats);

        // Hiển thị lịch bảo trì
        renderUserUpcomingMaintenance(data.upcomingMaintenance);

    } catch (error) {
        handleApiError(error, "Tải dữ liệu Dashboard");
    }
}

function renderUserEquipmentChart(stats) {
    const ctx = document.getElementById('userEquipmentStatusChart').getContext('2d');
    const chartData = {
        labels: ['Hoạt động', 'Bảo trì', 'Ngừng hoạt động'],
        datasets: [{
            data: [stats.active || 0, stats.maintenance || 0, stats.inactive || 0],
            backgroundColor: ['rgba(40, 167, 69, 0.8)', 'rgba(255, 193, 7, 0.8)', 'rgba(220, 53, 69, 0.8)'],
            borderColor: ['#fff'],
            borderWidth: 2
        }]
    };
    if (userChartInstance) { userChartInstance.destroy(); }
    userChartInstance = new Chart(ctx, {
        type: 'pie', data: chartData,
        options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'bottom' } } }
    });
}

function renderUserUpcomingMaintenance(schedules) {
    const listElement = document.getElementById('userUpcomingMaintenanceList');
    listElement.innerHTML = '';
    if (!schedules || schedules.length === 0) {
        listElement.innerHTML = '<li style="padding: 10px;">Không có lịch bảo trì nào sắp tới.</li>';
        return;
    }
    schedules.forEach(item => {
        const li = document.createElement('li');
        li.style.borderBottom = '1px solid #eee';
        li.style.padding = '12px 5px';
        li.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 500;">${item.equipmentName}</span>
                <span style="font-size: 14px; color: #555;">${new Date(item.scheduleDate).toLocaleDateString('vi-VN')}</span>
            </div>
        `;
        listElement.appendChild(li);
    });
}

// Gắn sự kiện cho nút Báo hỏng nhanh
dom.userReportIncidentBtn.addEventListener('click', () => {
    switchView('incidents');
});     

// ========================================================
// LOGIC CHO GHI NHẬT KÝ HÀNG LOẠT
// ========================================================
document.getElementById('bulkLogSubmitBtn').addEventListener('click', () => {
    const status = document.getElementById('logStatus').value;
    const notes = document.getElementById('logNotes').value;

    Swal.fire({
        title: 'Xác nhận Ghi hàng loạt?',
        text: `Bạn có chắc muốn áp dụng tình trạng "${status === 'operational' ? 'Hoạt động tốt' : (status === 'minor_issue' ? 'Có vấn đề nhỏ' : 'Không sử dụng')}" cho tất cả thiết bị còn lại trong khoa?`,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Vâng, xác nhận!',
        cancelButtonText: 'Hủy'
    }).then(async (result) => {
        if (result.isConfirmed) {
            Swal.fire({
                title: 'Đang xử lý...',
                allowOutsideClick: false,
                didOpen: () => { Swal.showLoading() }
            });
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/logs/bulk`, {
                    method: 'POST',
                    body: JSON.stringify({ status, notes })
                });
                const resultData = await response.json();
                if (!response.ok) throw new Error(resultData.message);

                await Swal.fire('Thành công!', resultData.message, 'success');
                closeUsageLogModal();
                fetchAndDisplayEquipment(dom.departmentSelect.value, 1); // Tải lại danh sách để xóa các dấu '!'
            } catch (error) {
                handleApiError(error, "Ghi nhật ký hàng loạt");
            }
        }
    });
});

// ========================================================
// LOGIC CHO GHI NHẬT KÝ HÀNG LOẠT (NGOẠI TRỪ)
// ========================================================

function closeBulkLogExceptionModal() {
    dom.bulkLogExceptionModal.style.display = 'none';
}

dom.closeBulkLogExceptionModalBtn.addEventListener('click', closeBulkLogExceptionModal);
dom.cancelBulkLogExceptionBtn.addEventListener('click', closeBulkLogExceptionModal);
window.addEventListener('click', (e) => {
    if (e.target === dom.bulkLogExceptionModal) closeBulkLogExceptionModal();
});

dom.bulkLogExceptBtn.addEventListener('click', async () => {
    console.log('Nút "Áp dụng, trừ một vài thiết bị..." đã được nhấn!'); // Dòng code kiểm tra

    Swal.fire({
        title: 'Đang tải danh sách thiết bị...',
        allowOutsideClick: false,
        didOpen: () => { Swal.showLoading() }
    });

    try {
        // Lấy danh sách TẤT CẢ thiết bị của khoa, không phân trang
        const response = await fetchWithAuth(`${API_BASE_URL}/api/equipment/${userProfile.departmentKey}?limit=10000`);
        if (!response.ok) throw new Error("Không thể tải danh sách thiết bị.");
        
        const data = await response.json();
        const equipments = data.equipments || []; // Đảm bảo equipments là một mảng
        
        dom.exceptionListContainer.innerHTML = ''; // Xóa danh sách cũ
        
        if (equipments.length === 0) {
            dom.exceptionListContainer.innerHTML = '<p>Không có thiết bị nào trong khoa này.</p>';
        } else {
            equipments.forEach(eq => {
                const itemHtml = `
                    <div style="display: flex; align-items: center; padding: 8px 0; border-bottom: 1px solid #f0f0f0;">
                        <input type="checkbox" id="exc-${eq._id}" value="${eq._id}" style="width: 20px; height: 20px; margin-right: 15px;">
                        <label for="exc-${eq._id}" style="font-weight: 500; cursor: pointer;">${eq.name} <span style="color: #6c757d;">(Serial: ${eq.serial})</span></label>
                    </div>
                `;
                dom.exceptionListContainer.innerHTML += itemHtml;
            });
        }

        Swal.close();
        dom.bulkLogExceptionModal.style.display = 'flex';

    } catch (error) {
        handleApiError(error, "Tải danh sách thiết bị");
    }
});

dom.confirmBulkLogExceptionBtn.addEventListener('click', () => {
    const status = document.getElementById('logStatus').value;
    const notes = document.getElementById('logNotes').value;
    const excludeIds = [];
    document.querySelectorAll('#exception-list-container input[type="checkbox"]:checked').forEach(checkbox => {
        excludeIds.push(checkbox.value);
    });

    closeBulkLogExceptionModal();

    Swal.fire({
        title: 'Xác nhận Ghi hàng loạt?',
        text: `Áp dụng cho tất cả thiết bị còn lại, ngoại trừ ${excludeIds.length} thiết bị đã chọn?`,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Vâng, xác nhận!',
        cancelButtonText: 'Hủy'
    }).then(async (result) => {
        if (result.isConfirmed) {
            Swal.fire({ title: 'Đang xử lý...', allowOutsideClick: false, didOpen: () => { Swal.showLoading() } });
            try {
                const response = await fetchWithAuth(`${API_BASE_URL}/api/logs/bulk`, {
                    method: 'POST',
                    body: JSON.stringify({ status, notes, excludeIds }) // Gửi kèm danh sách loại trừ
                });
                const resultData = await response.json();
                if (!response.ok) throw new Error(resultData.message);
                
                await Swal.fire('Thành công!', resultData.message, 'success');
                closeUsageLogModal();
                fetchAndDisplayEquipment(dom.departmentSelect.value, 1); // Tải lại danh sách để cập nhật dấu '!'
            } catch (error) {
                handleApiError(error, "Ghi nhật ký hàng loạt");
            }
        }
    });
});

// ========================================================
// LOGIC CHO QUẢN LÝ TÀI LIỆU
// ========================================================

function renderDocumentList(documents) {
    const tableBody = document.getElementById('document-list-tbody');
    tableBody.innerHTML = '';
    if (!documents || documents.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="4" style="text-align: center;">Chưa có tài liệu nào.</td></tr>`;
        return;
    }

    const typeMap = { contract: 'Hợp đồng', co: 'CO', cq: 'CQ', inspection: 'Kiểm định', other: 'Khác' };
    documents.forEach(doc => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${typeMap[doc.documentType] || 'Không rõ'}</td>
            <td><a href="${doc.fileUrl}" target="_blank" title="Mở file">${doc.fileName} <i class="fas fa-external-link-alt" style="font-size: 12px;"></i></a></td>
            <td>${new Date(doc.createdAt).toLocaleDateString('vi-VN')}</td>
            <td class="action-btn-group">
                <button class="delete-btn doc-delete-btn" data-id="${doc._id}"><i class="fas fa-trash"></i></button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

async function handleDocumentUpload(e) {
    e.preventDefault();
    const equipmentId = document.getElementById('doc-equipment-id').value;
    const documentType = document.getElementById('documentType').value;
    const fileInput = document.getElementById('documentFile');

    if (!fileInput.files[0]) {
        Swal.fire('Lỗi', 'Vui lòng chọn một file để tải lên.', 'warning');
        return;
    }

    const formData = new FormData();
    formData.append('document', fileInput.files[0]);
    formData.append('documentType', documentType);
    
    Swal.fire({ title: 'Đang tải lên...', allowOutsideClick: false, didOpen: () => { Swal.showLoading() } });

    try {
        // Lưu ý: fetchWithAuth cần được điều chỉnh để không tự set 'Content-Type' cho FormData
        const token = getToken();
        const headers = {};
        if (token) { headers['Authorization'] = `Bearer ${token}`; }

        const response = await fetch(`${API_BASE_URL}/api/documents/upload/${equipmentId}`, {
            method: 'POST',
            headers: headers, // Không có 'Content-Type'
            body: formData,
        });

        if (response.status === 401 || response.status === 403) { logout(); throw new Error('Phiên đăng nhập hết hạn.'); }
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        Swal.fire('Thành công', 'Tải tài liệu lên thành công!', 'success');
        fileInput.value = ''; // Reset input
        // Tải lại danh sách tài liệu
        const newDocsResponse = await fetchWithAuth(`${API_BASE_URL}/api/documents/${equipmentId}`);
        const newDocs = await newDocsResponse.json();
        renderDocumentList(newDocs);

    } catch (error) {
        handleApiError(error, "Tải tài liệu");
    }
}

function handleDocumentDelete(e) {
    const deleteBtn = e.target.closest('.doc-delete-btn');
    if (!deleteBtn) return;

    const documentId = deleteBtn.dataset.id;
    const equipmentId = document.getElementById('doc-equipment-id').value;

    Swal.fire({
        title: 'Bạn chắc chắn muốn xóa?',
        text: "Tài liệu này sẽ bị xóa vĩnh viễn cả trên server!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#d33',
        confirmButtonText: 'Vâng, xóa nó!',
        cancelButtonText: 'Hủy'
    }).then(async (result) => {
        if (result.isConfirmed) {
            try {
                await fetchWithAuth(`${API_BASE_URL}/api/documents/${documentId}`, { method: 'DELETE' });
                Swal.fire('Đã xóa!', 'Tài liệu đã được xóa.', 'success');
                // Tải lại danh sách tài liệu
                const newDocsResponse = await fetchWithAuth(`${API_BASE_URL}/api/documents/${equipmentId}`);
                const newDocs = await newDocsResponse.json();
                renderDocumentList(newDocs);
            } catch (error) {
                handleApiError(error, "Xóa tài liệu");
            }
        }
    });
}

document.getElementById('globalSearchCheckbox').addEventListener('change', (e) => {
    const isGlobal = e.target.checked;
    if (isGlobal) {
        dom.searchInput.placeholder = "Tìm kiếm trên toàn bộ các khoa...";
    } else {
        dom.searchInput.placeholder = "Tìm kiếm trong khoa hiện tại...";
    }
    // Tự động tìm kiếm lại khi tick/bỏ tick checkbox
    if (dom.searchInput.value.trim().length > 0) {
        dom.searchInput.dispatchEvent(new Event('input'));
    }
});

// Hàm này sẽ được gọi khi đăng nhập để ẩn checkbox cho user thường
function updateUserUIByRole() {
    if (userProfile.role === 'user') {
        document.getElementById('search-scope-container').style.display = 'none';
    } else {
        document.getElementById('search-scope-container').style.display = 'flex';
    }
}

// --- LOGIC QUẢN LÝ KỸ SƯ ---
    async function renderTechniciansView() {
        try {
            const response = await fetchWithAuth(`${API_BASE_URL}/api/technicians`);
            const techs = await response.json();
            const tbody = document.getElementById('technicians-table-body');
            tbody.innerHTML = '';
            
            if (techs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Chưa có kỹ sư nào.</td></tr>';
                return;
            }

            techs.forEach(t => {
                const avatarUrl = t.avatar || 'https://via.placeholder.com/40?text=KS';
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><img src="${avatarUrl}" style="width: 40px; height: 40px; border-radius: 50%; object-fit: cover;"></td>
                    <td style="font-weight: 500;">${t.fullName}</td>
                    <td>${t.username}</td>
                    <td>${new Date(t.createdAt).toLocaleDateString('vi-VN')}</td>
                    <td style="text-align: center;"><button class="delete-btn" onclick="deleteUser('${t._id}', 'technician')"><i class="fas fa-trash"></i></button></td>
                `;
                tbody.appendChild(row);
            });
        } catch (e) { handleApiError(e, 'Tải danh sách kỹ sư'); }
    }

    // Xử lý Modal Thêm Kỹ sư
    const techModal = document.getElementById('technicianModal');
    document.getElementById('addTechnicianBtn').addEventListener('click', () => {
        document.getElementById('technicianForm').reset();
        document.getElementById('avatarPreview').src = '#';
        document.getElementById('avatarPreview').style.display = 'none';
        techModal.style.display = 'flex';
    });
    document.getElementById('closeTechnicianModalBtn').addEventListener('click', () => techModal.style.display = 'none');
    document.getElementById('cancelTechBtn').addEventListener('click', () => techModal.style.display = 'none');
    
    // Upload Avatar Preview
    document.getElementById('avatarUpload').addEventListener('click', () => document.getElementById('avatarInput').click());
    document.getElementById('avatarInput').addEventListener('change', function() {
        if(this.files && this.files[0]) {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = document.getElementById('avatarPreview');
                img.src = e.target.result;
                img.style.display = 'block';
            };
            reader.readAsDataURL(this.files[0]);
        }
    });

    // Submit Thêm Kỹ sư
    document.getElementById('technicianForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append('username', document.getElementById('techUsername').value);
        formData.append('password', document.getElementById('techPassword').value);
        formData.append('fullName', document.getElementById('techFullName').value);
        const fileInput = document.getElementById('avatarInput');
        if (fileInput.files[0]) {
            formData.append('avatar', fileInput.files[0]);
        }

        Swal.fire({ title: 'Đang tạo hồ sơ...', didOpen: () => Swal.showLoading() });
        
        try {
            const token = getToken();
            const res = await fetch(`${API_BASE_URL}/api/technicians`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }, // Không set Content-Type để browser tự làm
                body: formData
            });
            if(!res.ok) throw new Error((await res.json()).message);
            
            Swal.fire('Thành công', 'Đã thêm kỹ sư mới!', 'success');
            techModal.style.display = 'none';
            renderTechniciansView();
        } catch (err) { handleApiError(err, 'Thêm kỹ sư'); }
    });

    // --- LOGIC PHÂN CÔNG VIỆC (ASSIGNMENT) ---
    const assignModal = document.getElementById('assignTaskModal');
    
    // Hàm mở modal phân công (được gọi khi Admin bấm nút "Giao việc")
    async function openAssignModal(incidentId) {
        document.getElementById('assign-incident-id').value = incidentId;
        const select = document.getElementById('assignTechnicianSelect');
        select.innerHTML = '<option>Đang tải danh sách...</option>';
        assignModal.style.display = 'flex';

        try {
            const res = await fetchWithAuth(`${API_BASE_URL}/api/technicians`);
            const techs = await res.json();
            select.innerHTML = '<option value="">-- Chọn Kỹ sư --</option>';
            techs.forEach(t => {
                const opt = document.createElement('option');
                opt.value = t._id;
                opt.textContent = `${t.fullName} (${t.username})`;
                select.appendChild(opt);
            });
        } catch (e) { select.innerHTML = '<option>Lỗi tải danh sách</option>'; }
    }

    document.getElementById('closeAssignModalBtn').addEventListener('click', () => assignModal.style.display = 'none');
    document.getElementById('cancelAssignBtn').addEventListener('click', () => assignModal.style.display = 'none');

    // Submit Phân công
    document.getElementById('assignTaskForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const incidentId = document.getElementById('assign-incident-id').value;
        const techId = document.getElementById('assignTechnicianSelect').value;
        const notes = document.getElementById('assignNotes').value;

        try {
            await fetchWithAuth(`${API_BASE_URL}/api/incidents/assign/${incidentId}`, {
                method: 'PUT',
                body: JSON.stringify({ assignedToId: techId, notes: notes })
            });
            Swal.fire('Đã giao việc!', 'Kỹ sư đã nhận được thông báo.', 'success');
            assignModal.style.display = 'none';
            renderIncidentView(); // Reload lại bảng
        } catch (err) { handleApiError(err, 'Giao việc'); }
    });

    // --- CHATBOT LOGIC ---
    const CHAT_HISTORY_KEY = 'hospital_chat_history'; // Tên khóa lưu trữ

    // 1. Hàm khởi tạo: Tự động chạy khi web tải xong
    function initChat() {
        const history = localStorage.getItem(CHAT_HISTORY_KEY);
        const container = document.getElementById('chat-messages');
        
        if (history) {
            // Nếu có lịch sử cũ, xóa tin nhắn chào mặc định và tải lại
            container.innerHTML = ''; 
            const messages = JSON.parse(history);
            messages.forEach(msg => {
                addMessageToUI(msg.text, msg.sender, false);
            });
        }
    }

    function toggleChat() {
        const win = document.getElementById('chat-window');
        if (win.style.display === 'flex') {
            win.style.display = 'none';
        } else {
            win.style.display = 'flex';
            document.getElementById('chatInput').focus();
            // Cuộn xuống dưới cùng khi mở
            const container = document.getElementById('chat-messages');
            container.scrollTop = container.scrollHeight;
        }
    }

    function handleChatEnter(e) {
        if (e.key === 'Enter') sendMessage();
    }

    // Hàm xóa lịch sử
    function clearChatHistory() {
        if(confirm('Bạn có chắc muốn xóa toàn bộ đoạn chat cũ không?')) {
            localStorage.removeItem(CHAT_HISTORY_KEY);
            document.getElementById('chat-messages').innerHTML = 
                '<div class="message bot">Đã xóa lịch sử. Tôi có thể giúp gì cho bạn?</div>';
        }
    }

    // Hàm lưu tin nhắn vào LocalStorage
    function saveToHistory(text, sender) {
        let history = localStorage.getItem(CHAT_HISTORY_KEY);
        let messages = history ? JSON.parse(history) : [];
        
        // Giới hạn lưu 50 tin nhắn gần nhất để không bị nặng máy
        if (messages.length > 50) messages.shift(); 
        
        messages.push({ text: text, sender: sender });
        localStorage.setItem(CHAT_HISTORY_KEY, JSON.stringify(messages));
    }

    async function sendMessage() {
        const input = document.getElementById('chatInput');
        const msg = input.value.trim();
        if (!msg) return;

        // 1. Hiển thị & Lưu tin nhắn người dùng
        addMessageToUI(msg, 'user');
        saveToHistory(msg, 'user'); // <--- LƯU
        input.value = '';

        // 2. Hiển thị trạng thái đang nhập...
        const loadingId = addMessageToUI('Đang suy nghĩ...', 'bot', true);

        try {
            // 3. Gửi lên Server
            const res = await fetchWithAuth(`${API_BASE_URL}/api/chat`, {
                method: 'POST',
                body: JSON.stringify({ message: msg })
            });
            const data = await res.json();
            
            // 4. Xóa loading, hiện câu trả lời & Lưu
            document.getElementById(loadingId).remove();
            
            const botReply = data.reply || 'Xin lỗi, tôi không hiểu.';
            addMessageToUI(botReply, 'bot');
            saveToHistory(botReply, 'bot'); // <--- LƯU

        } catch (e) {
            if(document.getElementById(loadingId)) document.getElementById(loadingId).remove();
            addMessageToUI('Lỗi kết nối AI.', 'bot');
        }
    }

    // Hàm chỉ làm nhiệm vụ hiển thị (UI), tách biệt với logic lưu
    function addMessageToUI(text, sender, isLoading = false) {
        const div = document.createElement('div');
        div.className = `message ${sender}`;
        
        // Xử lý xuống dòng cho đẹp nếu AI trả về văn bản dài
        if (!isLoading) {
            div.innerHTML = text.replace(/\n/g, '<br>');
        } else {
            div.innerText = text;
        }

        if (isLoading) div.id = 'msg-loading-' + Date.now();
        
        const container = document.getElementById('chat-messages');
        container.appendChild(div);
        container.scrollTop = container.scrollHeight; 
        return div.id;
    }

    // --- QUAN TRỌNG: GẮN HÀM VÀO WINDOW & KHỞI CHẠY ---
    window.toggleChat = toggleChat;
    window.handleChatEnter = handleChatEnter;
    window.sendMessage = sendMessage;
    window.clearChatHistory = clearChatHistory;
    
    // Gọi hàm load lịch sử ngay khi script chạy
    initChat();


        checkAuth();
    });
