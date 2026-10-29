/**
 * API Client for SNA Cybersecurity Platform.
 * Communicates with the FastAPI backend.
 */

const BASE_URL = '/api';

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  try {
    const res = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      ...options,
    });

    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const errJson = await res.json();
        detail = errJson.detail || detail;
      } catch {
        // ignore json parse error
      }
      throw new ApiError(res.status, detail);
    }

    return await res.json();
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, `Network error: ${err.message}`);
  }
}

export const api = {
  getHealth: () => request('/health'),
  getDatasetStatus: () => request('/dataset/status'),
  runAnalysis: (params) =>
    request('/analysis/run', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  getOverview: () => request('/overview'),
  getNetwork: ({ maxNodes = 100, focusHost = null, communityId = null, minWeight = 1 } = {}) => {
    const sp = new URLSearchParams();
    if (maxNodes) sp.set('max_nodes', maxNodes);
    if (focusHost) sp.set('focus_host', focusHost);
    if (communityId !== null && communityId !== undefined) sp.set('community_id', communityId);
    if (minWeight) sp.set('min_weight', minWeight);
    return request(`/network?${sp.toString()}`);
  },
  getHosts: ({
    page = 1,
    pageSize = 25,
    sortBy = 'combined_criticality',
    sortDir = 'desc',
    search = '',
    priorityTier = '',
    communityId = null,
  } = {}) => {
    const sp = new URLSearchParams();
    sp.set('page', page);
    sp.set('page_size', pageSize);
    sp.set('sort_by', sortBy);
    sp.set('sort_dir', sortDir);
    if (search) sp.set('search', search);
    if (priorityTier && priorityTier !== 'ALL') sp.set('priority_tier', priorityTier);
    if (communityId !== null && communityId !== undefined && communityId !== 'ALL') {
      sp.set('community_id', communityId);
    }
    return request(`/hosts?${sp.toString()}`);
  },
  getHostDetail: (hostId) => request(`/hosts/${encodeURIComponent(hostId)}`),
  getCommunities: () => request('/communities'),
  getCommunityDetail: (communityId) => request(`/communities/${communityId}`),
  getTimeline: () => request('/timeline'),
  getEvaluation: () => request('/evaluation'),
  getExportUrl: (fileType) => `${BASE_URL}/export/${fileType}`,
};
