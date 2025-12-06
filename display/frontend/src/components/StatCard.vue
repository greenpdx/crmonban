<script setup>
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], required: true },
  trend: { type: Number, default: 0 },
  color: { type: String, default: 'blue' }
})

const colorMap = {
  blue: 'text-accent-blue',
  green: 'text-accent-green',
  yellow: 'text-accent-yellow',
  red: 'text-accent-red',
  purple: 'text-accent-purple'
}
</script>

<template>
  <div class="bg-dark-300 rounded border border-dark-100 p-2">
    <div class="text-[10px] text-gray-500 uppercase tracking-wide">{{ label }}</div>
    <div class="flex items-baseline gap-1.5 mt-0.5">
      <span :class="['text-lg font-semibold', colorMap[color]]">{{ value }}</span>
      <span
        v-if="trend !== 0"
        :class="trend > 0 ? 'text-red-400' : 'text-green-400'"
        class="text-[10px]"
      >
        {{ trend > 0 ? '↑' : '↓' }} {{ Math.abs(trend) }}%
      </span>
    </div>
  </div>
</template>
