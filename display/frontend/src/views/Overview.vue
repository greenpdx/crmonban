<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import StatCard from '../components/StatCard.vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart, PieChart, BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent, DataZoomComponent } from 'echarts/components'

use([CanvasRenderer, LineChart, PieChart, BarChart, GridComponent, TooltipComponent, LegendComponent, DataZoomComponent])

const stats = ref({
  activeBans: 42,
  eventsToday: 1523,
  eventsHour: 89,
  pps: '12.5K',
  utilization: 45
})

const timeSeriesOption = ref({
  backgroundColor: 'transparent',
  grid: { top: 10, right: 10, bottom: 30, left: 40 },
  xAxis: { type: 'time', axisLine: { lineStyle: { color: '#3b4a5a' } }, axisLabel: { color: '#9ca3af', fontSize: 10 } },
  yAxis: { type: 'value', splitLine: { lineStyle: { color: '#1e293b' } }, axisLabel: { color: '#9ca3af', fontSize: 10 } },
  dataZoom: [{ type: 'inside' }, { type: 'slider', height: 15, bottom: 5 }],
  tooltip: { trigger: 'axis', backgroundColor: '#1a2332', borderColor: '#3b4a5a', textStyle: { color: '#e5e7eb', fontSize: 11 } },
  series: [{
    type: 'line',
    smooth: true,
    symbol: 'none',
    areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(59,130,246,0.3)' }, { offset: 1, color: 'rgba(59,130,246,0)' }] } },
    lineStyle: { color: '#3b82f6', width: 1.5 },
    data: Array.from({ length: 60 }, (_, i) => [Date.now() - (59 - i) * 60000, Math.floor(Math.random() * 50 + 20)])
  }]
})

const severityPieOption = ref({
  backgroundColor: 'transparent',
  tooltip: { backgroundColor: '#1a2332', borderColor: '#3b4a5a', textStyle: { color: '#e5e7eb', fontSize: 11 } },
  series: [{
    type: 'pie',
    radius: ['50%', '70%'],
    center: ['50%', '50%'],
    label: { show: false },
    data: [
      { value: 45, name: 'Low', itemStyle: { color: '#3b82f6' } },
      { value: 30, name: 'Medium', itemStyle: { color: '#eab308' } },
      { value: 18, name: 'High', itemStyle: { color: '#f97316' } },
      { value: 7, name: 'Critical', itemStyle: { color: '#ef4444' } }
    ]
  }]
})

const threatBarOption = ref({
  backgroundColor: 'transparent',
  grid: { top: 5, right: 10, bottom: 20, left: 80 },
  xAxis: { type: 'value', splitLine: { lineStyle: { color: '#1e293b' } }, axisLabel: { color: '#9ca3af', fontSize: 10 } },
  yAxis: { type: 'category', axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: '#9ca3af', fontSize: 10 }, data: ['PortScan', 'BruteForce', 'Exploit', 'DDoS', 'Malware'] },
  series: [{ type: 'bar', barWidth: 12, itemStyle: { color: '#3b82f6', borderRadius: 2 }, data: [45, 38, 25, 18, 12] }]
})

const handleBlockClick = (block) => {
  console.log('Navigate to detail:', block)
}
</script>

<template>
  <div class="space-y-2">
    <!-- Stats Row -->
    <div class="grid grid-cols-5 gap-2">
      <StatCard label="Active Bans" :value="stats.activeBans" color="red" :trend="8" />
      <StatCard label="Events Today" :value="stats.eventsToday" color="yellow" :trend="12" />
      <StatCard label="Events/Hour" :value="stats.eventsHour" color="blue" />
      <StatCard label="Packets/sec" :value="stats.pps" color="green" />
      <StatCard label="Worker Load" :value="`${stats.utilization}%`" color="purple" />
    </div>

    <!-- Main Charts Row -->
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Events Over Time" subtitle="1h" :span="2" height="180px" @click="handleBlockClick('events')">
        <v-chart :option="timeSeriesOption" autoresize class="w-full h-full" />
      </ChartBlock>

      <ChartBlock title="Severity Distribution" height="180px" @click="handleBlockClick('severity')">
        <v-chart :option="severityPieOption" autoresize class="w-full h-full" />
      </ChartBlock>

      <ChartBlock title="Top Threats" height="180px" @click="handleBlockClick('threats')">
        <v-chart :option="threatBarOption" autoresize class="w-full h-full" />
      </ChartBlock>
    </div>

    <!-- Bottom Row -->
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Recent Events" :span="2" height="160px" @click="handleBlockClick('events')">
        <div class="text-xs text-gray-400 space-y-1">
          <div class="flex items-center gap-2 py-0.5 border-b border-dark-100">
            <span class="text-red-400">CRIT</span>
            <span class="text-gray-300 flex-1 truncate">Brute force detected from 192.168.1.100</span>
            <span class="text-gray-500">2m ago</span>
          </div>
          <div class="flex items-center gap-2 py-0.5 border-b border-dark-100">
            <span class="text-orange-400">HIGH</span>
            <span class="text-gray-300 flex-1 truncate">Port scan from 10.0.0.50</span>
            <span class="text-gray-500">5m ago</span>
          </div>
          <div class="flex items-center gap-2 py-0.5 border-b border-dark-100">
            <span class="text-yellow-400">MED</span>
            <span class="text-gray-300 flex-1 truncate">Suspicious DNS query pattern</span>
            <span class="text-gray-500">8m ago</span>
          </div>
        </div>
      </ChartBlock>

      <ChartBlock title="Active Incidents" height="160px" @click="handleBlockClick('incidents')">
        <div class="text-xs space-y-1">
          <div class="p-1 bg-red-900/20 rounded border-l-2 border-red-500">
            <div class="font-medium text-red-300">P1: Ongoing Attack</div>
            <div class="text-gray-500">3 hosts affected</div>
          </div>
          <div class="p-1 bg-orange-900/20 rounded border-l-2 border-orange-500">
            <div class="font-medium text-orange-300">P2: Lateral Movement</div>
            <div class="text-gray-500">Investigation</div>
          </div>
        </div>
      </ChartBlock>

      <ChartBlock title="System Status" height="160px" @click="handleBlockClick('system')">
        <div class="text-xs space-y-1.5">
          <div class="flex justify-between"><span class="text-gray-500">Status</span><span class="text-green-400">● Running</span></div>
          <div class="flex justify-between"><span class="text-gray-500">Uptime</span><span class="text-gray-300">24h 15m</span></div>
          <div class="flex justify-between"><span class="text-gray-500">Active Flows</span><span class="text-gray-300">4,521</span></div>
          <div class="flex justify-between"><span class="text-gray-500">Memory</span><span class="text-gray-300">1.2 GB</span></div>
        </div>
      </ChartBlock>
    </div>
  </div>
</template>
