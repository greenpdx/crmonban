<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import DataTable from '../components/DataTable.vue'
import SeverityBadge from '../components/SeverityBadge.vue'

const columns = [
  { key: 'time', label: 'Time', width: '80px' },
  { key: 'severity', label: 'Sev', width: '60px' },
  { key: 'type', label: 'Type', width: '100px' },
  { key: 'src', label: 'Source', width: '120px' },
  { key: 'dst', label: 'Destination', width: '120px' },
  { key: 'message', label: 'Message' }
]

const events = ref([
  { time: '14:32:05', severity: 'Critical', type: 'BruteForce', src: '192.168.1.100', dst: '10.0.0.1:22', message: 'SSH brute force attempt detected' },
  { time: '14:31:42', severity: 'High', type: 'PortScan', src: '10.0.0.50', dst: '10.0.0.1', message: 'TCP SYN scan on multiple ports' },
  { time: '14:30:18', severity: 'Medium', type: 'DNSAnomaly', src: '192.168.1.55', dst: '8.8.8.8', message: 'High entropy DNS query' },
  { time: '14:29:55', severity: 'Low', type: 'SignatureMatch', src: '172.16.0.20', dst: '10.0.0.1:80', message: 'ET SCAN Potential SSH Scan' },
  { time: '14:28:30', severity: 'Info', type: 'PolicyViolation', src: '192.168.1.10', dst: '10.0.0.5:3389', message: 'RDP connection attempt' }
])

const handleRowClick = (row) => {
  console.log('Event detail:', row)
}
</script>

<template>
  <div class="space-y-2">
    <!-- Filters -->
    <div class="flex gap-2 items-center">
      <select class="bg-dark-300 border border-dark-100 text-gray-300 text-xs rounded px-2 py-1">
        <option>All Severities</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
      </select>
      <select class="bg-dark-300 border border-dark-100 text-gray-300 text-xs rounded px-2 py-1">
        <option>All Types</option>
        <option>PortScan</option>
        <option>BruteForce</option>
        <option>Exploit</option>
      </select>
      <input type="text" placeholder="Search..." class="bg-dark-300 border border-dark-100 text-gray-300 text-xs rounded px-2 py-1 w-48">
      <span class="ml-auto text-xs text-gray-500">{{ events.length }} events</span>
    </div>

    <!-- Events Table -->
    <ChartBlock title="Detection Events" :clickable="false" height="calc(100vh - 180px)">
      <DataTable :columns="columns" :rows="events" max-height="calc(100vh - 220px)" @row-click="handleRowClick">
        <template #severity="{ value }">
          <SeverityBadge :severity="value" />
        </template>
        <template #src="{ value }">
          <span class="text-accent-blue">{{ value }}</span>
        </template>
      </DataTable>
    </ChartBlock>
  </div>
</template>
