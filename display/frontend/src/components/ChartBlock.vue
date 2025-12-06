<script setup>
import { ref } from 'vue'

const props = defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  span: { type: Number, default: 1 }, // grid columns to span (1-4)
  height: { type: String, default: 'auto' },
  clickable: { type: Boolean, default: true }
})

const emit = defineEmits(['click', 'expand'])
const isHovered = ref(false)

const handleClick = () => {
  if (props.clickable) {
    emit('click')
  }
}

const handleExpand = (e) => {
  e.stopPropagation()
  emit('expand')
}
</script>

<template>
  <div
    :class="[
      'chart-block bg-dark-300 rounded border border-dark-100 flex flex-col',
      clickable ? 'cursor-pointer' : '',
      `col-span-${span}`
    ]"
    :style="{ minHeight: height }"
    @click="handleClick"
    @mouseenter="isHovered = true"
    @mouseleave="isHovered = false"
  >
    <!-- Header -->
    <div class="flex items-center justify-between px-2 py-1 border-b border-dark-100 shrink-0">
      <div class="flex items-center gap-2 min-w-0">
        <h3 class="text-xs font-medium text-gray-200 truncate">{{ title }}</h3>
        <span v-if="subtitle" class="text-[10px] text-gray-500">{{ subtitle }}</span>
      </div>
      <button
        v-if="clickable && isHovered"
        @click="handleExpand"
        class="text-gray-500 hover:text-gray-300 text-xs p-0.5"
        title="Expand"
      >
        ⤢
      </button>
    </div>

    <!-- Content -->
    <div class="flex-1 p-1.5 min-h-0">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.col-span-1 { grid-column: span 1; }
.col-span-2 { grid-column: span 2; }
.col-span-3 { grid-column: span 3; }
.col-span-4 { grid-column: span 4; }
</style>
