<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { RadarChart, LineChart, ScatterChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, RadarComponent } from 'echarts/components'

use([CanvasRenderer, RadarChart, LineChart, ScatterChart, GridComponent, TooltipComponent, RadarComponent])

const radarOption = ref({
  backgroundColor: 'transparent',
  tooltip: { backgroundColor: '#1a2332', borderColor: '#3b4a5a', textStyle: { color: '#e5e7eb', fontSize: 11 } },
  radar: {
    indicator: [
      { name: 'Duration', max: 1 },
      { name: 'FwdPkts', max: 1 },
      { name: 'BwdPkts', max: 1 },
      { name: 'FwdBytes', max: 1 },
      { name: 'BwdBytes', max: 1 },
      { name: 'PktRate', max: 1 },
      { name: 'IAT', max: 1 },
      { name: 'Flags', max: 1 }
    ],
    shape: 'polygon',
    splitNumber: 4,
    axisName: { color: '#9ca3af', fontSize: 10 },
    splitLine: { lineStyle: { color: '#1e293b' } },
    splitArea: { show: false },
    axisLine: { lineStyle: { color: '#3b4a5a' } }
  },
  series: [{
    type: 'radar',
    symbol: 'circle',
    symbolSize: 4,
    data: [
      { name: 'Current', value: [0.7, 0.5, 0.4, 0.8, 0.6, 0.3, 0.9, 0.5], itemStyle: { color: '#ef4444' }, areaStyle: { color: 'rgba(239,68,68,0.2)' }, lineStyle: { color: '#ef4444' } },
      { name: 'Baseline', value: [0.3, 0.3, 0.3, 0.4, 0.4, 0.2, 0.5, 0.3], itemStyle: { color: '#3b82f6' }, areaStyle: { color: 'rgba(59,130,246,0.1)' }, lineStyle: { color: '#3b82f6', type: 'dashed' } }
    ]
  }]
})

const scoreOption = ref({
  backgroundColor: 'transparent',
  grid: { top: 10, right: 10, bottom: 25, left: 35 },
  xAxis: { type: 'time', axisLine: { lineStyle: { color: '#3b4a5a' } }, axisLabel: { color: '#9ca3af', fontSize: 10 } },
  yAxis: { type: 'value', min: 0, max: 1, splitLine: { lineStyle: { color: '#1e293b' } }, axisLabel: { color: '#9ca3af', fontSize: 10 } },
  tooltip: { trigger: 'axis', backgroundColor: '#1a2332', borderColor: '#3b4a5a', textStyle: { color: '#e5e7eb', fontSize: 11 } },
  series: [
    { type: 'line', smooth: true, symbol: 'none', lineStyle: { color: '#3b82f6' }, data: Array.from({ length: 30 }, (_, i) => [Date.now() - (29 - i) * 60000, 0.2 + Math.random() * 0.3]) },
    { type: 'line', symbol: 'none', lineStyle: { color: '#ef4444', type: 'dashed' }, data: Array.from({ length: 30 }, (_, i) => [Date.now() - (29 - i) * 60000, 0.7]) }
  ]
})
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-4 gap-2">
      <ChartBlock title="Current Score" height="80px">
        <div class="flex items-baseline gap-2">
          <span class="text-2xl font-semibold text-accent-green">0.23</span>
          <span class="text-xs text-gray-500">/ 1.0</span>
        </div>
      </ChartBlock>
      <ChartBlock title="Threshold" height="80px">
        <div class="text-2xl font-semibold text-accent-red">0.70</div>
      </ChartBlock>
      <ChartBlock title="Anomalies Today" height="80px">
        <div class="text-2xl font-semibold text-accent-yellow">7</div>
      </ChartBlock>
      <ChartBlock title="Category" height="80px">
        <div class="text-lg font-semibold text-gray-300">Normal</div>
      </ChartBlock>
    </div>

    <div class="grid grid-cols-2 gap-2">
      <ChartBlock title="Feature Radar" subtitle="Current vs Baseline" height="280px">
        <v-chart :option="radarOption" autoresize class="w-full h-full" />
      </ChartBlock>

      <ChartBlock title="Anomaly Score Over Time" height="280px">
        <v-chart :option="scoreOption" autoresize class="w-full h-full" />
      </ChartBlock>
    </div>

    <ChartBlock title="Top Contributing Features" height="120px">
      <div class="space-y-1.5">
        <div class="flex items-center gap-2">
          <span class="text-xs text-gray-400 w-24">fwd_iat_mean</span>
          <div class="flex-1 h-3 bg-dark-200 rounded overflow-hidden">
            <div class="h-full bg-accent-red rounded" style="width: 85%"></div>
          </div>
          <span class="text-xs text-gray-300 w-10">0.85</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-xs text-gray-400 w-24">flow_duration</span>
          <div class="flex-1 h-3 bg-dark-200 rounded overflow-hidden">
            <div class="h-full bg-accent-yellow rounded" style="width: 65%"></div>
          </div>
          <span class="text-xs text-gray-300 w-10">0.65</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-xs text-gray-400 w-24">fwd_bytes</span>
          <div class="flex-1 h-3 bg-dark-200 rounded overflow-hidden">
            <div class="h-full bg-accent-blue rounded" style="width: 45%"></div>
          </div>
          <span class="text-xs text-gray-300 w-10">0.45</span>
        </div>
      </div>
    </ChartBlock>
  </div>
</template>
