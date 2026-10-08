import { Panel, Empty } from './components'
import Chart from './Chart'
export default function IncidentSignals({incidents,risk}:{incidents:any[];risk:Record<string,number>}){
 const bins=new Map<number,number>()
 for(const incident of incidents){const minute=Math.floor(incident.ingested_at/60)*60;bins.set(minute,(bins.get(minute)||0)+1)}
 const times=[...bins.keys()].sort((a,b)=>a-b)
 return <div className="grid-main"><Panel title="Incident timeline" note="Latest 200 · by ingestion minute">{times.length?<Chart label="Persisted incident counts by observed ingestion minute" option={{grid:{left:42,right:18,top:24,bottom:30},tooltip:{trigger:'axis'},xAxis:{type:'category',data:times.map(t=>new Date(t*1000).toLocaleTimeString()),axisLine:{lineStyle:{color:'#344243'}}},yAxis:{type:'value',min:0,minInterval:1,splitLine:{lineStyle:{color:'#263233'}}},series:[{type:'line',data:times.map(t=>bins.get(t)),symbol:'circle',lineStyle:{color:'#efb86f'},itemStyle:{color:'#efb86f'}}]}}/>:<Empty title="No incident timeline yet"/>}<div className="panel-foot">Counts include all labelled origins. Only minutes represented in the most recent records are shown; gaps are not claimed as zero.</div></Panel><Panel title="Risk distribution" note="Triage priority, not probability"><div className="distribution">{['CRITICAL','HIGH','MEDIUM','LOW'].map(k=><div key={k}><div><span>{k}</span><b>{risk[k]||0}</b></div><meter min={0} max={Math.max(...Object.values(risk),1)} value={risk[k]||0}/></div>)}</div></Panel></div>
}
