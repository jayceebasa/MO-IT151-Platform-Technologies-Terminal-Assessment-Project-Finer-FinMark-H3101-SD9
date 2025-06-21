class DataSyncService {
    constructor() {
        this.isOnline = navigator.onLine;
        this.syncQueue = JSON.parse(localStorage.getItem('syncQueue') || '[]');
        this.localData = JSON.parse(localStorage.getItem('appData') || '{}');
        
        // Listen for online/offline events
        window.addEventListener('online', () => this.handleOnline());
        window.addEventListener('offline', () => this.handleOffline());
    }

    // Check if user is online
    isUserOnline() {
        return navigator.onLine;
    }

    // Save data locally
    saveToLocal(key, data) {
        this.localData[key] = {
            data: data,
            timestamp: Date.now(),
            synced: false
        };
        localStorage.setItem('appData', JSON.stringify(this.localData));
        
        // Add to sync queue if online
        if (this.isUserOnline()) {
            this.addToSyncQueue('save', key, data);
        }
    }

    // Get data from local storage
    getFromLocal(key) {
        return this.localData[key] || null;
    }

    // Add operation to sync queue
    addToSyncQueue(operation, key, data) {
        const syncItem = {
            id: Date.now(),
            operation: operation,
            key: key,
            data: data,
            timestamp: Date.now()
        };
        
        this.syncQueue.push(syncItem);
        localStorage.setItem('syncQueue', JSON.stringify(this.syncQueue));
        
        // Try to sync immediately if online
        if (this.isUserOnline()) {
            this.syncWithServer();
        }
    }

    // Sync data with server
    async syncWithServer() {
        if (!this.isUserOnline() || this.syncQueue.length === 0) {
            return;
        }

        const itemsToSync = [...this.syncQueue];
        
        for (let item of itemsToSync) {
            try {
                let success = false;
                
                switch (item.operation) {
                    case 'save':
                        success = await this.syncSaveToServer(item.key, item.data);
                        break;
                    case 'delete':
                        success = await this.syncDeleteToServer(item.key);
                        break;
                    case 'update':
                        success = await this.syncUpdateToServer(item.key, item.data);
                        break;
                }
                
                if (success) {
                    // Remove from sync queue
                    this.syncQueue = this.syncQueue.filter(queueItem => queueItem.id !== item.id);
                    
                    // Mark as synced in local data
                    if (this.localData[item.key]) {
                        this.localData[item.key].synced = true;
                    }
                }
                
            } catch (error) {
                console.error('Sync failed for item:', item, error);
            }
        }
        
        // Update localStorage
        localStorage.setItem('syncQueue', JSON.stringify(this.syncQueue));
        localStorage.setItem('appData', JSON.stringify(this.localData));
    }

    // Sync save operation to server
    async syncSaveToServer(key, data) {
        try {
            const response = await fetch('/auth/api/sync/save/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    key: key,
                    data: data
                }),
                credentials: 'include'
            });
            
            return response.ok;
        } catch (error) {
            console.error('Server sync failed:', error);
            return false;
        }
    }

    // Sync delete operation to server
    async syncDeleteToServer(key) {
        try {
            const response = await fetch('/auth/api/sync/delete/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ key: key }),
                credentials: 'include'
            });
            
            return response.ok;
        } catch (error) {
            console.error('Server delete sync failed:', error);
            return false;
        }
    }

    // Fetch data from server
    async fetchFromServer(key) {
        if (!this.isUserOnline()) {
            return this.getFromLocal(key);
        }

        try {
            const response = await fetch(`/auth/api/sync/get/${key}/`, {
                method: 'GET',
                credentials: 'include'
            });
            
            if (response.ok) {
                const serverData = await response.json();
                
                // Update local storage with server data
                this.localData[key] = {
                    data: serverData,
                    timestamp: Date.now(),
                    synced: true
                };
                localStorage.setItem('appData', JSON.stringify(this.localData));
                
                return serverData;
            }
        } catch (error) {
            console.error('Fetch from server failed:', error);
        }
        
        // Fallback to local data
        return this.getFromLocal(key);
    }

    // Handle when user comes online
    handleOnline() {
        console.log('Back online - starting sync...');
        this.isOnline = true;
        this.syncWithServer();
    }

    // Handle when user goes offline
    handleOffline() {
        console.log('Gone offline - using local storage...');
        this.isOnline = false;
    }

    // Get sync status
    getSyncStatus() {
        return {
            isOnline: this.isUserOnline(),
            pendingSync: this.syncQueue.length,
            lastSync: localStorage.getItem('lastSyncTime') || 'Never'
        };
    }

    // Force sync all data
    async forceSync() {
        if (this.isUserOnline()) {
            await this.syncWithServer();
            localStorage.setItem('lastSyncTime', new Date().toISOString());
        }
    }
}

// Initialize the sync service
const dataSyncService = new DataSyncService();