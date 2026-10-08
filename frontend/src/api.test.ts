import { describe,it,expect,vi,afterEach } from 'vitest'
import { request, percentage } from './api'
afterEach(()=>vi.unstubAllGlobals())
describe('API errors remain errors',()=>{
  it('refuses to interpret a failure as empty successful telemetry',async()=>{
    vi.stubGlobal('fetch',async()=>new Response(JSON.stringify({detail:'Analyst token required'}),{status:401}))
    await expect(request('/actions',{},'bad')).rejects.toThrow('Analyst token required')
  })
  it('does not present absent experiment metrics as zero performance',()=>{
    expect(percentage(undefined)).toBe('Not evaluated')
    expect(percentage(0)).toBe('0.0%')
  })
})
