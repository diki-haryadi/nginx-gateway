// Simple frontend for Service Manager with SSL support

document.addEventListener('DOMContentLoaded', () => {
    loadServices();
    
    // Add service form
    document.getElementById('addServiceForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const domain = document.getElementById('domain').value;
        const serviceUrl = document.getElementById('serviceUrl').value;
        const ssl = document.getElementById('ssl').checked;
        
        addService(domain, serviceUrl, ssl);
    });
});

// Load all services
async function loadServices() {
    try {
        const response = await fetch('/api/services');
        const services = await response.json();
        
        const servicesList = document.getElementById('servicesList');
        servicesList.innerHTML = '';
        
        if (services.length === 0) {
            servicesList.innerHTML = '<tr><td colspan="5">No services found</td></tr>';
            return;
        }
        
        services.forEach(service => {
            const row = document.createElement('tr');
            
            // Domain
            const domainCell = document.createElement('td');
            domainCell.textContent = service.domain;
            row.appendChild(domainCell);
            
            // Service URL
            const urlCell = document.createElement('td');
            urlCell.textContent = service.serviceUrl;
            row.appendChild(urlCell);
            
            // Status
            const statusCell = document.createElement('td');
            const statusBtn = document.createElement('button');
            statusBtn.className = service.active ? 'btn btn-success' : 'btn btn-danger';
            statusBtn.textContent = service.active ? 'Active' : 'Inactive';
            statusBtn.addEventListener('click', () => toggleService(service.id));
            statusCell.appendChild(statusBtn);
            row.appendChild(statusCell);
            
            // SSL
            const sslCell = document.createElement('td');
            const sslBtn = document.createElement('button');
            sslBtn.className = service.ssl ? 'btn btn-success' : 'btn btn-secondary';
            sslBtn.textContent = service.ssl ? 'SSL Enabled' : 'SSL Disabled';
            sslBtn.addEventListener('click', () => toggleSSL(service.id));
            sslCell.appendChild(sslBtn);
            row.appendChild(sslCell);
            
            // Actions
            const actionsCell = document.createElement('td');
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-danger';
            deleteBtn.textContent = 'Delete';
            deleteBtn.addEventListener('click', () => deleteService(service.id));
            actionsCell.appendChild(deleteBtn);
            row.appendChild(actionsCell);
            
            servicesList.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading services:', error);
        alert('Failed to load services');
    }
}

// Add a new service
async function addService(domain, serviceUrl, ssl) {
    try {
        const response = await fetch('/api/services', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                domain,
                serviceUrl,
                ssl
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || 'Failed to add service');
        }
        
        // Reset form
        document.getElementById('domain').value = '';
        document.getElementById('serviceUrl').value = '';
        document.getElementById('ssl').checked = false;
        
        // Reload services
        loadServices();
        
        alert('Service added successfully');
    } catch (error) {
        console.error('Error adding service:', error);
        alert(error.message || 'Failed to add service');
    }
}

// Toggle service active state
async function toggleService(serviceId) {
    try {
        const response = await fetch(`/api/services/${serviceId}/toggle`, {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error('Failed to toggle service status');
        }
        
        // Reload services
        loadServices();
    } catch (error) {
        console.error('Error toggling service:', error);
        alert('Failed to toggle service status');
    }
}

// Toggle SSL for a service
async function toggleSSL(serviceId) {
    try {
        const response = await fetch(`/api/services/${serviceId}/togglessl`, {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error('Failed to toggle SSL status');
        }
        
        // Reload services
        loadServices();
    } catch (error) {
        console.error('Error toggling SSL:', error);
        alert('Failed to toggle SSL status');
    }
}

// Delete a service
async function deleteService(serviceId) {
    if (!confirm('Are you sure you want to delete this service?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/services/${serviceId}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            throw new Error('Failed to delete service');
        }
        
        // Reload services
        loadServices();
        
        alert('Service deleted successfully');
    } catch (error) {
        console.error('Error deleting service:', error);
        alert('Failed to delete service');
    }
}