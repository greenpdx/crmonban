<script setup>
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()

const tabs = [
  { path: '/overview', label: 'Overview', icon: '◉' },
  { path: '/events', label: 'Events', icon: '⚡' },
  { path: '/flows', label: 'Flows', icon: '⇄' },
  { path: '/anomaly', label: 'Anomaly', icon: '◈' },
  { path: '/geo', label: 'Geo', icon: '⊕' },
  { path: '/bans', label: 'Bans', icon: '⊘' },
  { path: '/incidents', label: 'Incidents', icon: '⚠' },
  { path: '/protocols', label: 'Protocols', icon: '▤' },
  { path: '/signatures', label: 'Signatures', icon: '✎' },
  { path: '/scans', label: 'Scans', icon: '⋯' },
  { path: '/mitre', label: 'MITRE', icon: '▦' },
  { path: '/system', label: 'System', icon: '⚙' }
]

const currentTab = computed(() => route.path)
const goTo = (path) => router.push(path)
</script>

<template>
  <div class="h-screen flex flex-col bg-dark-400">
    <!-- Header -->
    <header class="h-[36px] bg-dark-300 border-b border-dark-100 flex items-center px-3 shrink-0">
      <span class="font-semibold text-accent-blue text-sm">crmonban</span>
      <span class="text-gray-500 text-xs ml-2">NIDS Dashboard</span>
      <div class="ml-auto flex items-center gap-3 text-xs">
        <span class="text-green-400">● Online</span>
        <span class="text-gray-400">12.5K pps</span>
      </div>
    </header>

    <!-- Fixed Tabs -->
    <nav class="h-[32px] bg-dark-300 flex items-center px-1 border-b border-dark-100 shrink-0 overflow-x-auto">
      <button
        v-for="tab in tabs"
        :key="tab.path"
        @click="goTo(tab.path)"
        :class="[
          'h-full px-2.5 text-xs flex items-center gap-1 whitespace-nowrap transition-colors',
          currentTab === tab.path
            ? 'tab-active bg-dark-400 text-white'
            : 'text-gray-400 hover:text-gray-200 hover:bg-dark-200'
        ]"
      >
        <span class="opacity-60">{{ tab.icon }}</span>
        {{ tab.label }}
      </button>
    </nav>

    <!-- Main Content -->
    <main class="flex-1 overflow-auto p-2">
      <router-view />
    </main>
  </div>
</template>
