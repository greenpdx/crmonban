<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import DataTable from '../components/DataTable.vue'

const columns = [
  { key: 'ip', label: 'IP Address', width: '140px' },
  { key: 'reason', label: 'Reason' },
  { key: 'source', label: 'Source', width: '80px' },
  { key: 'created', label: 'Created', width: '100px' },
  { key: 'expires', label: 'Expires', width: '100px' },
  { key: 'count', label: '#', width: '40px' }
]

const bans = ref([
  { ip: '192.168.1.100', reason: 'SSH brute force', source: 'ssh', created: '2h ago', expires: '22h', count: 3 },
  { ip: '10.0.0.50', reason: 'Port scan', source: 'portscan', created: '4h ago', expires: '20h', count: 1 },
  { ip: '172.16.0.20', reason: 'DPI: SQLi attempt', source: 'dpi', created: '1d ago', expires: '6d', count: 5 }
])
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Active Bans" height="80px">
        <div class="text-2xl font-semibold text-accent-red">42</div>
      </ChartBlock>
      <ChartBlock title="Total Bans" height="80px">
        <div class="text-2xl font-semibold text-accent-blue">1,234</div>
      </ChartBlock>
      <ChartBlock title="Today" height="80px">
        <div class="text-2xl font-semibold text-accent-yellow">15</div>
      </ChartBlock>
      <ChartBlock title="Permanent" height="80px">
        <div class="text-2xl font-semibold text-accent-purple">8</div>
      </ChartBlock>
    </div>

    <ChartBlock title="Active Bans" :clickable="false" height="calc(100vh - 230px)">
      <DataTable :columns="columns" :rows="bans" max-height="calc(100vh - 270px)">
        <template #ip="{ value }">
          <span class="text-accent-blue font-mono">{{ value }}</span>
        </template>
        <template #count="{ value }">
          <span class="text-accent-red">{{ value }}</span>
        </template>
      </DataTable>
    </ChartBlock>
  </div>
</template>
