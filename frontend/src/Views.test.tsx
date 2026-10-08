// @vitest-environment jsdom
import { render,screen } from '@testing-library/react'
import { expect,it,vi } from 'vitest'
import Views from './Views'
it('retains historical evaluation when the active artifact is unavailable',()=>{
 const report={metadata:{model:'Random Forest',classes:[],limitations:[],experiment_date:'2026-10-07'},experiments:[{name:'Random Forest',test:{confusion_matrix:[],per_class:{}},latency:{}}],resources:{},research_status:{}}
 render(<Views page="Model & Research" data={{overview:{health:{}},model:{status:'unavailable',metadata:{},evaluation:report}}} setPage={vi.fn()} select={vi.fn()} disabled={false} mutate={vi.fn()} openAction={vi.fn()}/> )
 expect(screen.getByText('No active model')).toBeTruthy()
 expect(screen.getByText('Historical evaluation')).toBeTruthy()
})

