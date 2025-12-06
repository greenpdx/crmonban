import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/overview' },
  { path: '/overview', name: 'Overview', component: () => import('./views/Overview.vue') },
  { path: '/events', name: 'Events', component: () => import('./views/Events.vue') },
  { path: '/flows', name: 'Flows', component: () => import('./views/Flows.vue') },
  { path: '/anomaly', name: 'Anomaly', component: () => import('./views/Anomaly.vue') },
  { path: '/geo', name: 'Geo', component: () => import('./views/Geo.vue') },
  { path: '/bans', name: 'Bans', component: () => import('./views/Bans.vue') },
  { path: '/incidents', name: 'Incidents', component: () => import('./views/Incidents.vue') },
  { path: '/protocols', name: 'Protocols', component: () => import('./views/Protocols.vue') },
  { path: '/signatures', name: 'Signatures', component: () => import('./views/Signatures.vue') },
  { path: '/scans', name: 'Scans', component: () => import('./views/Scans.vue') },
  { path: '/mitre', name: 'MITRE', component: () => import('./views/Mitre.vue') },
  { path: '/system', name: 'System', component: () => import('./views/System.vue') }
]

export default createRouter({
  history: createWebHistory(),
  routes
})
