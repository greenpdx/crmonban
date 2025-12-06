<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import DataTable from '../components/DataTable.vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, PieChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'

use([CanvasRenderer, BarChart, PieChart, GridComponent, TooltipComponent])

const columns = [
  { key: 'ip', label: 'Scanner IP', width: '140px' },
  { key: 'type', label: 'Scan Type', width: '100px' },
  { key: 'ports', label: 'Ports Scanned', width: '100px' },
  { key: 'time', label: 'Detected', width: '100px' },
  { key: 'action', label: 'Action', width: '80px' }
]

const scans = ref([
  { ip: '10.0.0.50', type: 'TCP SYN', ports: 1024, time: '5m ago', action: 'Banned' },
  { ip: '192.168.1.100', type: 'TCP NULL', ports: 256, time: '15m ago', action: 'Banned' },
  { ip: '172.16.0.20', type: 'UDP', ports: 512, time: '1h ago', action: 'Logged' }
])

const portBar = ref({
  backgroundColor: 'transparent',
  grid: { top: 5, right: 10, bottom: 20, left: 40 },
  xAxis: { type: 'value', splitLine: { lineStyle: { color: '#1e293b' } }, axisLabel: { color: '#9ca3af', fontSize: 10 } },
  yAxis: { type: 'category', axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: '#9ca3af', fontSize: 10 }, data: ['22', '80', '443', '3389', '445', '3306'] },
  series: [{ type: 'bar', barWidth: 12, itemStyle: { color: '#ef4444', borderRadius: 2 }, data: [450, 320, 280, 150, 120, 90] }]
})

const scanTypePie = ref({
  backgroundColor: 'transparent',
  tooltip: { backgroundColor: '#1a2332', borderColor: '#3b4a5a', textStyle: { color: '#e5e7eb', fontSize: 11 } },
  series: [{
    type: 'pie',
    radius: ['40%', '65%'],
    label: { show: true, color: '#9ca3af', fontSize: 10 },
    data: [
      { value: 65, name: 'SYN', itemStyle: { color: '#3b82f6' } },
      { value: 15, name: 'NULL', itemStyle: { color: '#22c55e' } },
      { value: 10, name: 'XMAS', itemStyle: { color: '#eab308' } },
      { value: 10, name: 'UDP', itemStyle: { color: '#a855f7' } }
    ]
  }]
})
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Scans Detected" height="80px">
        <div class="text-2xl font-semibold text-accent-red">156</div>
      </ChartBlock>
      <ChartBlock title="Unique Scanners" height="80px">
        <div class="text-2xl font-semibold text-accent-blue">42</div>
      </ChartBlock>
      <ChartBlock title="Banned" height="80px">
        <div class="text-2xl font-semibold text-accent-green">38</div>
      </ChartBlock>
      <ChartBlock title="Today" height="80px">
        <div class="text-2xl font-semibold text-accent-yellow">23</div>
      </ChartBlock>
    </div>

    <div class="grid grid-cols-2 gap-2">
      <ChartBlock title="Top Scanned Ports" height="180px">
        <v-chart :option="portBar" autoresize class="w-full h-full" />
      </ChartBlock>

      <ChartBlock title="Scan Types" height="180px">
        <v-chart :option="scanTypePie" autoresize class="w-full h-full" />
      </ChartBlock>
    </div>

    <ChartBlock title="Recent Scans" :clickable="false" height="calc(100vh - 400px)">
      <DataTable :columns="columns" :rows="scans" max-height="calc(100vh - 440px)">
        <template #ip="{ value }">
          <span class="font-mono text-accent-blue">{{ value }}</span>
        </template>
        <template #action="{ value }">
          <span :class="value === 'Banned' ? 'text-red-400' : 'text-gray-400'">{{ value }}</span>
        </template>
      </DataTable>
    </ChartBlock>
  </div>
</template>
