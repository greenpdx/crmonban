<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import SeverityBadge from '../components/SeverityBadge.vue'

const incidents = ref([
  { id: 'INC-001', name: 'Active Brute Force Attack', severity: 'Critical', priority: 'P1', status: 'Investigating', events: 45, hosts: 3 },
  { id: 'INC-002', name: 'Lateral Movement Detected', severity: 'High', priority: 'P2', status: 'Escalated', events: 23, hosts: 5 },
  { id: 'INC-003', name: 'Suspicious DNS Activity', severity: 'Medium', priority: 'P3', status: 'New', events: 12, hosts: 1 }
])

const priorityColors = {
  P1: 'border-red-500 bg-red-900/20',
  P2: 'border-orange-500 bg-orange-900/20',
  P3: 'border-yellow-500 bg-yellow-900/20',
  P4: 'border-blue-500 bg-blue-900/20'
}
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Open Incidents" height="80px">
        <div class="text-2xl font-semibold text-accent-red">3</div>
      </ChartBlock>
      <ChartBlock title="P1 Critical" height="80px">
        <div class="text-2xl font-semibold text-red-400">1</div>
      </ChartBlock>
      <ChartBlock title="P2 High" height="80px">
        <div class="text-2xl font-semibold text-orange-400">1</div>
      </ChartBlock>
      <ChartBlock title="Closed Today" height="80px">
        <div class="text-2xl font-semibold text-accent-green">5</div>
      </ChartBlock>
    </div>

    <ChartBlock title="Active Incidents" :clickable="false" height="calc(100vh - 230px)">
      <div class="space-y-2 overflow-auto" style="max-height: calc(100vh - 270px)">
        <div
          v-for="inc in incidents"
          :key="inc.id"
          :class="['p-2 rounded border-l-4 cursor-pointer hover:bg-dark-200', priorityColors[inc.priority]]"
        >
          <div class="flex items-center gap-2">
            <span class="text-xs text-gray-500 font-mono">{{ inc.id }}</span>
            <SeverityBadge :severity="inc.severity" />
            <span class="text-xs px-1.5 py-0.5 bg-dark-100 rounded">{{ inc.priority }}</span>
            <span class="text-xs px-1.5 py-0.5 bg-dark-100 rounded text-gray-400">{{ inc.status }}</span>
          </div>
          <div class="mt-1 text-sm text-gray-200">{{ inc.name }}</div>
          <div class="mt-1 flex gap-3 text-xs text-gray-500">
            <span>{{ inc.events }} events</span>
            <span>{{ inc.hosts }} hosts</span>
          </div>
        </div>
      </div>
    </ChartBlock>
  </div>
</template>
