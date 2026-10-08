import { useEffect, useRef } from 'react'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
echarts.use([LineChart, GridComponent, TooltipComponent, CanvasRenderer])
export default function Chart({ option, label }: { option: echarts.EChartsCoreOption; label: string }) {
  const node = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const chart = echarts.init(node.current!)
    chart.setOption({ textStyle: { fontFamily: 'system-ui', color: '#a2b0b0' }, ...option })
    const observer = new ResizeObserver(() => chart.resize()); observer.observe(node.current!)
    return () => { observer.disconnect(); chart.dispose() }
  }, [option])
  return <div className="chart" role="img" aria-label={label} ref={node} />
}
