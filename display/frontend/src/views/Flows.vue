<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import DataTable from '../components/DataTable.vue'

const columns = [
  { key: 'src', label: 'Source', width: '140px' },
  { key: 'dst', label: 'Destination', width: '140px' },
  { key: 'proto', label: 'Proto', width: '60px' },
  { key: 'state', label: 'State', width: '80px' },
  { key: 'packets', label: 'Pkts', width: '60px' },
  { key: 'bytes', label: 'Bytes', width: '70px' },
  { key: 'risk', label: 'Risk', width: '50px' }
]

const flows = ref([
  { src: '192.168.1.100:45678', dst: '10.0.0.1:443', proto: 'TCP', state: 'Established', packets: 1542, bytes: '1.2M', risk: 0.1 },
  { src: '10.0.0.50:12345', dst: '10.0.0.1:22', proto: 'TCP', state: 'SynSent', packets: 45, bytes: '2.1K', risk: 0.8 },
  { src: '172.16.0.20:53421', dst: '8.8.8.8:53', proto: 'UDP', state: 'Active', packets: 89, bytes: '12K', risk: 0.2 }
])

const getRiskColor = (risk) => {
  if (risk >= 0.7) return 'text-red-400'
  if (risk >= 0.4) return 'text-yellow-400'
  return 'text-green-400'
}
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Active Flows" height="80px">
        <div class="text-2xl font-semibold text-accent-blue">4,521</div>
      </ChartBlock>
      <ChartBlock title="Flow Rate" height="80px">
        <div class="text-2xl font-semibold text-accent-green">1.2K/s</div>
      </ChartBlock>
      <ChartBlock title="High Risk" height="80px">
        <div class="text-2xl font-semibold text-accent-red">23</div>
      </ChartBlock>
      <ChartBlock title="Avg Duration" height="80px">
        <div class="text-2xl font-semibold text-accent-purple">45s</div>
      </ChartBlock>
    </div>

    <ChartBlock title="Flow Table" :clickable="false" height="calc(100vh - 230px)">
      <DataTable :columns="columns" :rows="flows" max-height="calc(100vh - 270px)">
        <template #risk="{ value }">
          <span :class="getRiskColor(value)">{{ (value * 100).toFixed(0) }}%</span>
        </template>
        <template #state="{ value }">
          <span :class="value === 'Established' ? 'text-green-400' : 'text-yellow-400'">{{ value }}</span>
        </template>
      </DataTable>
    </ChartBlock>
  </div>
</template>
