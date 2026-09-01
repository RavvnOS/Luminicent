// Centralized configuration for Backend API & Socket.IO URL.
// Production values should be supplied via VITE_API_URL; local development falls back to localhost.

export const getBackendUrl = () => {
  const configuredUrl = import.meta.env.VITE_API_URL || import.meta.env.VITE_BACKEND_URL;

  if (configuredUrl) {
    return configuredUrl.replace(/\/$/, '');
  }

  if (typeof window !== 'undefined' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
    return window.location.origin.replace(/\/$/, '');
  }

  return 'http://localhost:5000';
};

export const BACKEND_URL = getBackendUrl();
