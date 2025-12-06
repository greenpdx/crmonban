<script setup>
defineProps({
  severity: { type: String, required: true }
})

const colors = {
  info: 'bg-gray-600 text-gray-200',
  low: 'bg-blue-900 text-blue-300',
  medium: 'bg-yellow-900 text-yellow-300',
  high: 'bg-orange-900 text-orange-300',
  critical: 'bg-red-900 text-red-300'
}
</script>

<template>
  <span
    :class="[
      'inline-block px-1.5 py-0.5 rounded text-[10px] font-medium uppercase',
      colors[severity.toLowerCase()] || colors.info
    ]"
  >
    {{ severity }}
  </span>
</template>
