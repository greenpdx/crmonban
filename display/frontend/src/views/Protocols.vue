<script setup>
import { ref } from 'vue'
import ChartBlock from '../components/ChartBlock.vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart, TreemapChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'

use([CanvasRenderer, PieChart, BarChart, TreemapChart, GridComponent, TooltipComponent])

const protocolPie = ref({
  backgroundColor: 'transparent',
  tooltip: { backgroundColor: '#1a2332', borderColor: '#3b4a5a', textStyle: { color: '#e5e7eb', fontSize: 11 } },
  series: [{
    type: 'pie',
    radius: ['40%', '65%'],
    label: { show: true, color: '#9ca3af', fontSize: 10 },
    data: [
      { value: 8500, name: 'TCP', itemStyle: { color: '#3b82f6' } },
      { value: 3200, name: 'UDP', itemStyle: { color: '#22c55e' } },
      { value: 150, name: 'ICMP', itemStyle: { color: '#eab308' } }
    ]
  }]
})

const appBar = ref({
  backgroundColor: 'transparent',
  grid: { top: 5, right: 10, bottom: 20, left: 60 },
  xAxis: { type: 'value', splitLine: { lineStyle: { color: '#1e293b' } }, axisLabel: { color: '#9ca3af', fontSize: 10 } },
  yAxis: { type: 'category', axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: '#9ca3af', fontSize: 10 }, data: ['HTTPS', 'HTTP', 'DNS', 'SSH', 'SMTP', 'Other'] },
  series: [{ type: 'bar', barWidth: 14, itemStyle: { color: '#3b82f6', borderRadius: 2 }, data: [4500, 3000, 2800, 400, 200, 500] }]
})
</script>

<template>
  <div class="space-y-2">
    <div class="grid grid-cols-2 gap-2">
      <ChartBlock title="Transport Protocols" height="220px">
        <v-chart :option="protocolPie" autoresize class="w-full h-full" />
      </ChartBlock>

      <ChartBlock title="Application Protocols" height="220px">
        <v-chart :option="appBar" autoresize class="w-full h-full" />
      </ChartBlock>
    </div>

    <div class="grid grid-cols-3 gap-2">
      <ChartBlock title="HTTP Stats" height="150px">
        <div class="text-xs space-y-1">
          <div class="flex justify-between"><span class="text-gray-500">GET</span><span class="text-gray-300">68%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">POST</span><span class="text-gray-300">25%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">Other</span><span class="text-gray-300">7%</span></div>
          <div class="border-t border-dark-100 pt-1 mt-2">
            <div class="flex justify-between"><span class="text-gray-500">2xx</span><span class="text-green-400">85%</span></div>
            <div class="flex justify-between"><span class="text-gray-500">4xx</span><span class="text-yellow-400">12%</span></div>
            <div class="flex justify-between"><span class="text-gray-500">5xx</span><span class="text-red-400">3%</span></div>
          </div>
        </div>
      </ChartBlock>

      <ChartBlock title="DNS Stats" height="150px">
        <div class="text-xs space-y-1">
          <div class="flex justify-between"><span class="text-gray-500">A</span><span class="text-gray-300">72%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">AAAA</span><span class="text-gray-300">15%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">TXT</span><span class="text-gray-300">8%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">MX</span><span class="text-gray-300">5%</span></div>
        </div>
      </ChartBlock>

      <ChartBlock title="TLS Versions" height="150px">
        <div class="text-xs space-y-1">
          <div class="flex justify-between"><span class="text-gray-500">TLS 1.3</span><span class="text-green-400">75%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">TLS 1.2</span><span class="text-gray-300">23%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">TLS 1.1</span><span class="text-yellow-400">1.5%</span></div>
          <div class="flex justify-between"><span class="text-gray-500">TLS 1.0</span><span class="text-red-400">0.5%</span></div>
        </div>
      </ChartBlock>
    </div>
  </div>
</template>
