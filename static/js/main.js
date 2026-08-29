// HEX PROTOCOL - Main JavaScript

function getToken() {
    return localStorage.getItem('token');
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/admin/login';
}

function checkAuth() {
    const token = getToken();
    if (!token && window.location.pathname !== '/admin/login') {
        window.location.href = '/admin/login';
    }
}

async function apiRequest(url, method = 'GET', data = null) {
    const token = getToken();
    const headers = {};
    
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    
    const options = {
        method: method,
        headers: headers
    };
    
    if (data) {
        options.body = data;
    }
    
    const response = await fetch(url, options);
    
    if (response.status === 401) {
        logout();
        throw new Error('Unauthorized');
    }
    
    return response;
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    
    // Set active nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('bg-white/10');
            link.classList.add('border-l-4');
            link.classList.add('border-blue-500');
        }
    });
});