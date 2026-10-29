/**
 * Global reactive state manager for the frontend.
 */

class StateStore {
  constructor() {
    this.state = {
      currentPage: 'overview',
      apiOnline: false,
      isAnalyzing: false,
      datasetStatus: null,
      selectedHost: null,
      selectedCommunity: null,
      error: null,
    };
    this.listeners = new Map();
  }

  get(key) {
    return this.state[key];
  }

  set(key, value) {
    const prev = this.state[key];
    this.state[key] = value;
    if (this.listeners.has(key)) {
      this.listeners.get(key).forEach((cb) => cb(value, prev));
    }
  }

  subscribe(key, callback) {
    if (!this.listeners.has(key)) {
      this.listeners.set(key, new Set());
    }
    this.listeners.get(key).add(callback);
    return () => this.listeners.get(key).delete(callback);
  }
}

export const store = new StateStore();
