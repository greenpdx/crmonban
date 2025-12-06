<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'

const tactics = ref([
  { id: 'TA0043', name: 'Reconnaissance', count: 45, techniques: ['T1595', 'T1592'] },
  { id: 'TA0042', name: 'Resource Development', count: 12, techniques: ['T1583'] },
  { id: 'TA0001', name: 'Initial Access', count: 23, techniques: ['T1190', 'T1133'] },
  { id: 'TA0002', name: 'Execution', count: 8, techniques: ['T1059'] },
  { id: 'TA0003', name: 'Persistence', count: 5, techniques: ['T1098'] },
  { id: 'TA0004', name: 'Privilege Escalation', count: 3, techniques: ['T1068'] },
  { id: 'TA0005', name: 'Defense Evasion', count: 7, techniques: ['T1070'] },
  { id: 'TA0006', name: 'Credential Access', count: 34, techniques: ['T1110', 'T1555'] },
  { id: 'TA0007', name: 'Discovery', count: 28, techniques: ['T1046', 'T1018'] },
  { id: 'TA0008', name: 'Lateral Movement', count: 4, techniques: ['T1021'] },
  { id: 'TA0009', name: 'Collection', count: 2, techniques: ['T1005'] },
  { id: 'TA0011', name: 'Command and Control', count: 15, techniques: ['T1071', 'T1095'] },
  { id: 'TA0010', name: 'Exfiltration', count: 6, techniques: ['T1048'] },
  { id: 'TA0040', name: 'Impact', count: 1, techniques: ['T1499'] }
])

const getHeatColor = (count) => {
  if (count >= 30) return 'bg-red-600'
  if (count >= 15) return 'bg-orange-600'
  if (count >= 5) return 'bg-yellow-600'
  if (count > 0) return 'bg-blue-600'
  return 'bg-dark-200'
}
</script>

<template>
  <div class="space-y-2">
    <ChartBlock title="MITRE ATT&CK Coverage" subtitle="Detected Tactics & Techniques" :clickable="false" height="auto">
      <div class="grid grid-cols-7 gap-1 p-1">
        <div
          v-for="tactic in tactics"
          :key="tactic.id"
          :class="['p-1.5 rounded cursor-pointer transition-colors', getHeatColor(tactic.count)]"
        >
          <div class="text-[9px] text-gray-400 font-mono">{{ tactic.id }}</div>
          <div class="text-[10px] text-white font-medium truncate">{{ tactic.name }}</div>
          <div class="text-xs font-semibold text-white mt-0.5">{{ tactic.count }}</div>
          <div class="text-[9px] text-gray-300 mt-0.5">
            {{ tactic.techniques.slice(0, 2).join(', ') }}
          </div>
        </div>
      </div>
    </ChartBlock>

    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Total Tactics" height="80px">
        <div class="text-2xl font-semibold text-accent-blue">14</div>
      </ChartBlock>
      <ChartBlock title="Active Tactics" height="80px">
        <div class="text-2xl font-semibold text-accent-red">12</div>
      </ChartBlock>
      <ChartBlock title="Techniques" height="80px">
        <div class="text-2xl font-semibold text-accent-yellow">28</div>
      </ChartBlock>
      <ChartBlock title="Detections" height="80px">
        <div class="text-2xl font-semibold text-accent-purple">193</div>
      </ChartBlock>
    </div>

    <ChartBlock title="Attack Chain Timeline" height="150px">
      <div class="flex items-center justify-center h-full">
        <div class="flex items-center gap-1">
          <div class="px-2 py-1 bg-blue-600 rounded text-[10px] text-white">Recon</div>
          <span class="text-gray-500">→</span>
          <div class="px-2 py-1 bg-yellow-600 rounded text-[10px] text-white">Initial Access</div>
          <span class="text-gray-500">→</span>
          <div class="px-2 py-1 bg-orange-600 rounded text-[10px] text-white">Credential Access</div>
          <span class="text-gray-500">→</span>
          <div class="px-2 py-1 bg-red-600 rounded text-[10px] text-white">Lateral Movement</div>
          <span class="text-gray-500">→</span>
          <div class="px-2 py-1 bg-dark-100 rounded text-[10px] text-gray-400">C2</div>
        </div>
      </div>
    </ChartBlock>
  </div>
</template>
