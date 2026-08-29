// License Admin Panel - Main JavaScript

// Authentication helper
function getToken() {
    return localStorage.getItem('token');
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/admin/login';
}

// Check authentication on protected pages
function checkAuth() {
    const token = getToken();
    if (!token && window.location.pathname !== '/admin/login') {
        window.location.href = '/admin/login';
    }
}

// API helper function
async function apiRequest(url, method = 'GET', data = null, isFormData = false) {
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
        if (isFormData) {
            options.body = data;
        } else {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(data);
        }
    }
    
    const response = await fetch(url, options);
    
    if (response.status === 401) {
        logout();
        throw new Error('Unauthorized');
    }
    
    return response;
}

// Format date helper
function formatDate(dateString) {
    if (!dateString) return 'Permanent';
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    
    // Add active class to current nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});
