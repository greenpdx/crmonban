<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import DataTable from '../components/DataTable.vue'

const status = ref({
  running: true,
  pid: 1234,
  uptime: '24h 15m 32s',
  memory: '1.2 GB',
  cpu: '12%'
})

const services = ref([
  { name: 'ssh', status: 'active', events: 523 },
  { name: 'nginx', status: 'active', events: 234 },
  { name: 'postfix', status: 'active', events: 89 },
  { name: 'dpi', status: 'active', events: 156 }
])

const activityColumns = [
  { key: 'time', label: 'Time', width: '100px' },
  { key: 'action', label: 'Action', width: '100px' },
  { key: 'ip', label: 'IP', width: '140px' },
  { key: 'details', label: 'Details' }
]

const activity = ref([
  { time: '14:32:05', action: 'Ban', ip: '192.168.1.100', details: 'SSH brute force (5 attempts)' },
  { time: '14:30:18', action: 'Unban', ip: '10.0.0.50', details: 'Ban expired after 1h' },
  { time: '14:28:42', action: 'Whitelist', ip: '172.16.0.1', details: 'Added by admin' },
  { time: '14:15:00', action: 'Reload', ip: '-', details: 'Configuration reloaded' }
])

const actionColors = {
  Ban: 'text-red-400',
  Unban: 'text-green-400',
  Whitelist: 'text-blue-400',
  Reload: 'text-yellow-400'
}
</script>

<template>
  <div class="space-y-2">
    <!-- Status Cards -->
    <div class="grid grid-cols-5 gap-2">
      <ChartBlock title="Status" height="80px">
        <div class="flex items-center gap-2">
          <span :class="status.running ? 'text-green-400' : 'text-red-400'" class="text-lg">●</span>
          <span class="text-lg font-semibold text-gray-200">{{ status.running ? 'Running' : 'Stopped' }}</span>
        </div>
      </ChartBlock>
      <ChartBlock title="PID" height="80px">
        <div class="text-2xl font-semibold text-accent-blue font-mono">{{ status.pid }}</div>
      </ChartBlock>
      <ChartBlock title="Uptime" height="80px">
        <div class="text-lg font-semibold text-accent-green">{{ status.uptime }}</div>
      </ChartBlock>
      <ChartBlock title="Memory" height="80px">
        <div class="text-2xl font-semibold text-accent-yellow">{{ status.memory }}</div>
      </ChartBlock>
      <ChartBlock title="CPU" height="80px">
        <div class="text-2xl font-semibold text-accent-purple">{{ status.cpu }}</div>
      </ChartBlock>
    </div>

    <div class="grid grid-cols-3 gap-2">
      <!-- Monitored Services -->
      <ChartBlock title="Monitored Services" height="180px">
        <div class="space-y-1.5">
          <div
            v-for="svc in services"
            :key="svc.name"
            class="flex items-center justify-between p-1 bg-dark-200 rounded"
          >
            <div class="flex items-center gap-2">
              <span class="text-green-400 text-xs">●</span>
              <span class="text-xs text-gray-200">{{ svc.name }}</span>
            </div>
            <span class="text-xs text-gray-500">{{ svc.events }} events</span>
          </div>
        </div>
      </ChartBlock>

      <!-- Quick Actions -->
      <ChartBlock title="Quick Actions" height="180px" :clickable="false">
        <div class="space-y-1.5">
          <button class="w-full px-2 py-1.5 bg-dark-200 hover:bg-dark-100 rounded text-xs text-gray-300 text-left">
            ↻ Reload Configuration
          </button>
          <button class="w-full px-2 py-1.5 bg-dark-200 hover:bg-dark-100 rounded text-xs text-gray-300 text-left">
            ⟳ Restart Daemon
          </button>
          <button class="w-full px-2 py-1.5 bg-dark-200 hover:bg-dark-100 rounded text-xs text-gray-300 text-left">
            ⊘ Clear All Bans
          </button>
          <button class="w-full px-2 py-1.5 bg-dark-200 hover:bg-dark-100 rounded text-xs text-gray-300 text-left">
            ⬇ Export Logs
          </button>
        </div>
      </ChartBlock>

      <!-- Config Summary -->
      <ChartBlock title="Configuration" height="180px">
        <div class="text-xs space-y-1">
          <div class="flex justify-between"><span class="text-gray-500">Default Ban</span><span class="text-gray-300">1h</span></div>
          <div class="flex justify-between"><span class="text-gray-500">Port Scan</span><span class="text-green-400">Enabled</span></div>
          <div class="flex justify-between"><span class="text-gray-500">DPI</span><span class="text-green-400">Enabled</span></div>
          <div class="flex justify-between"><span class="text-gray-500">DNS Monitor</span><span class="text-green-400">Enabled</span></div>
          <div class="flex justify-between"><span class="text-gray-500">Auto Intel</span><span class="text-green-400">Enabled</span></div>
        </div>
      </ChartBlock>
    </div>

    <!-- Activity Log -->
    <ChartBlock title="Activity Log" :clickable="false" height="calc(100vh - 400px)">
      <DataTable :columns="activityColumns" :rows="activity" max-height="calc(100vh - 440px)">
        <template #action="{ value }">
          <span :class="actionColors[value] || 'text-gray-400'">{{ value }}</span>
        </template>
        <template #ip="{ value }">
          <span class="font-mono text-accent-blue">{{ value }}</span>
        </template>
      </DataTable>
    </ChartBlock>
  </div>
</template>
