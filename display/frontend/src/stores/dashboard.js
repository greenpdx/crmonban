import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'

export const useDashboardStore = defineStore('dashboard', () => {
  // State
  const stats = ref({
    activeBans: 0,
    eventsToday: 0,
    eventsHour: 0,
    pps: 0,
    eps: 0,
    workerUtilization: 0,
    threatLevel: 'low'
  })

  const events = ref([])
  const bans = ref([])
  const incidents = ref([])
  const flows = ref([])

  const loading = ref(false)
  const error = ref(null)
  const connected = ref(false)

  let ws = null

  // Actions
  async function fetchOverview() {
    try {
      loading.value = true
      const res = await axios.get('/api/overview')
      Object.assign(stats.value, res.data.stats)
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchEvents(params = {}) {
    try {
      const res = await axios.get('/api/events', { params })
      events.value = res.data.events
      return res.data
    } catch (e) {
      error.value = e.message
      return { events: [], total: 0 }
    }
  }

  async function fetchBans(params = {}) {
    try {
      const res = await axios.get('/api/bans', { params })
      bans.value = res.data.bans
      return res.data
    } catch (e) {
      error.value = e.message
      return { bans: [], total: 0 }
    }
  }

  function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`)

    ws.onopen = () => {
      connected.value = true
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        handleRealtimeEvent(data)
      } catch (e) {
        console.error('WS parse error:', e)
      }
    }

    ws.onclose = () => {
      connected.value = false
      // Reconnect after 5s
      setTimeout(connectWebSocket, 5000)
    }

    ws.onerror = () => {
      connected.value = false
    }
  }

  function handleRealtimeEvent(data) {
    switch (data.event_type) {
      case 'stats':
        Object.assign(stats.value, data.data)
        break
      case 'event':
        events.value.unshift(data.data)
        if (events.value.length > 100) events.value.pop()
        break
      case 'ban':
        bans.value.unshift(data.data)
        stats.value.activeBans++
        break
    }
  }

  function disconnect() {
    if (ws) {
      ws.close()
      ws = null
    }
  }

  return {
    stats,
    events,
    bans,
    incidents,
    flows,
    loading,
    error,
    connected,
    fetchOverview,
    fetchEvents,
    fetchBans,
    connectWebSocket,
    disconnect
  }
})
