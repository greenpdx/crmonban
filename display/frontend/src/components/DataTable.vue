<script setup>
defineProps({
  columns: { type: Array, required: true }, // [{key, label, width?}]
  rows: { type: Array, required: true },
  maxHeight: { type: String, default: '200px' }
})

defineEmits(['row-click'])
</script>

<template>
  <div class="overflow-auto" :style="{ maxHeight }">
    <table class="w-full text-xs">
      <thead class="sticky top-0 bg-dark-300">
        <tr class="border-b border-dark-100">
          <th
            v-for="col in columns"
            :key="col.key"
            class="text-left text-gray-500 font-medium px-1.5 py-1"
            :style="col.width ? { width: col.width } : {}"
          >
            {{ col.label }}
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="(row, i) in rows"
          :key="i"
          class="border-b border-dark-100 hover:bg-dark-200 cursor-pointer"
          @click="$emit('row-click', row)"
        >
          <td
            v-for="col in columns"
            :key="col.key"
            class="px-1.5 py-1 text-gray-300"
          >
            <slot :name="col.key" :value="row[col.key]" :row="row">
              {{ row[col.key] }}
            </slot>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
