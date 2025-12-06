<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import DataTable from '../components/DataTable.vue'

const countries = ref([
  { code: 'CN', name: 'China', count: 150, flag: '🇨🇳' },
  { code: 'RU', name: 'Russia', count: 89, flag: '🇷🇺' },
  { code: 'US', name: 'United States', count: 45, flag: '🇺🇸' },
  { code: 'BR', name: 'Brazil', count: 32, flag: '🇧🇷' },
  { code: 'IN', name: 'India', count: 28, flag: '🇮🇳' }
])

const columns = [
  { key: 'flag', label: '', width: '30px' },
  { key: 'name', label: 'Country' },
  { key: 'count', label: 'Events', width: '80px' }
]
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-3 gap-2">
      <ChartBlock title="World Map" subtitle="Attack Origins" :span="2" height="300px">
        <div class="w-full h-full flex items-center justify-center text-gray-500 text-xs">
          [Map visualization - requires echarts-gl or leaflet]
        </div>
      </ChartBlock>

      <ChartBlock title="Top Countries" height="300px">
        <DataTable :columns="columns" :rows="countries" max-height="260px">
          <template #count="{ value }">
            <span class="text-accent-red font-medium">{{ value }}</span>
          </template>
        </DataTable>
      </ChartBlock>
    </div>

    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Unique IPs" height="80px">
        <div class="text-2xl font-semibold text-accent-blue">342</div>
      </ChartBlock>
      <ChartBlock title="Countries" height="80px">
        <div class="text-2xl font-semibold text-accent-purple">47</div>
      </ChartBlock>
      <ChartBlock title="Tor Exits" height="80px">
        <div class="text-2xl font-semibold text-accent-yellow">12</div>
      </ChartBlock>
      <ChartBlock title="VPN/Proxy" height="80px">
        <div class="text-2xl font-semibold text-accent-red">28</div>
      </ChartBlock>
    </div>
  </div>
</template>
