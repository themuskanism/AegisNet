import { expect,it } from 'vitest'
import { provenance } from './components'
it('never relabels synthetic or unknown evidence as live',()=>{
 expect(provenance('live')).toBe('Live')
 expect(provenance('synthetic_fixture')).toBe('Synthetic fixture')
 expect(provenance('benchmark_replay')).toBe('Benchmark replay')
 expect(provenance('other')).toBe('Unknown origin: other')
})
