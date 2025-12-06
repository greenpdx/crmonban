<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import DataTable from '../components/DataTable.vue'

const columns = [
  { key: 'sid', label: 'SID', width: '80px' },
  { key: 'msg', label: 'Message' },
  { key: 'classtype', label: 'Class', width: '120px' },
  { key: 'priority', label: 'Pri', width: '40px' },
  { key: 'matches', label: 'Hits', width: '60px' }
]

const rules = ref([
  { sid: 2001219, msg: 'ET SCAN Potential SSH Scan', classtype: 'attempted-recon', priority: 2, matches: 156 },
  { sid: 2010935, msg: 'ET POLICY Suspicious inbound to MSSQL', classtype: 'policy-violation', priority: 2, matches: 89 },
  { sid: 2024897, msg: 'ET EXPLOIT Apache Struts RCE', classtype: 'web-application-attack', priority: 1, matches: 23 },
  { sid: 2019284, msg: 'ET TROJAN CnC Beacon', classtype: 'trojan-activity', priority: 1, matches: 12 }
])

const getPriorityColor = (p) => {
  if (p === 1) return 'text-red-400'
  if (p === 2) return 'text-yellow-400'
  return 'text-gray-400'
}
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Total Rules" height="80px">
        <div class="text-2xl font-semibold text-accent-blue">45,892</div>
      </ChartBlock>
      <ChartBlock title="Enabled" height="80px">
        <div class="text-2xl font-semibold text-accent-green">42,103</div>
      </ChartBlock>
      <ChartBlock title="Matches Today" height="80px">
        <div class="text-2xl font-semibold text-accent-yellow">1,247</div>
      </ChartBlock>
      <ChartBlock title="Unique Rules Hit" height="80px">
        <div class="text-2xl font-semibold text-accent-purple">89</div>
      </ChartBlock>
    </div>

    <ChartBlock title="Top Matching Signatures" :clickable="false" height="calc(100vh - 230px)">
      <DataTable :columns="columns" :rows="rules" max-height="calc(100vh - 270px)">
        <template #sid="{ value }">
          <span class="font-mono text-accent-blue">{{ value }}</span>
        </template>
        <template #priority="{ value }">
          <span :class="getPriorityColor(value)">{{ value }}</span>
        </template>
        <template #matches="{ value }">
          <span class="text-accent-red font-medium">{{ value }}</span>
        </template>
      </DataTable>
    </ChartBlock>
  </div>
</template>
