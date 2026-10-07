"""Audited response state machine. Firewall access is opt-in and never uses a shell."""
import ipaddress
import platform
import subprocess
import threading
import time
import uuid
from sqlalchemy import select
from backend.store import Action, Source, Incident


def firewall_arguments(action,ip):
    address=str(ipaddress.ip_address(ip))
    name='AegisNet-'+address.replace(':','_').replace('.','_')
    if action=='block': return ['netsh','advfirewall','firewall','add','rule',f'name={name}','dir=in','action=block',f'remoteip={address}','enable=yes']
    if action=='unblock': return ['netsh','advfirewall','firewall','delete','rule',f'name={name}']
    raise ValueError('unsupported firewall action')


class ResponseService:
    def __init__(self,store,active_enabled=False,protected=()):
        self.store=store;self.active_enabled=False;self.protected=set(protected);self.lock=threading.RLock()
        # ACTIVE cannot be enabled until crash-safe intent/execution reconciliation is validated.

    def _validate(self,s,action,ip):
        address=ipaddress.ip_address(ip)
        if action=='block':
            if not address.is_global or address.is_multicast or str(address) in self.protected:
                raise ValueError('protected/local-critical address')
            if s.get(Source,(str(address),'whitelist')): raise ValueError('source is whitelisted')
        return str(address)

    def request(self,action,ip,reason,mode='SIMULATION',incident_id=None):
        if action not in ['block','unblock','whitelist','unwhitelist','acknowledge','ignore']: raise ValueError('unsupported action')
        if mode not in ['SIMULATION','MANUAL','ACTIVE']: raise ValueError('invalid mode')
        if not reason.strip() or len(reason)>500: raise ValueError('reason required (max 500 characters)')
        with self.lock:
            try:
                with self.store.transaction() as s:
                    if mode=='ACTIVE' and (not self.active_enabled or platform.system()!='Windows'): raise ValueError('active response disabled or unsupported')
                    ip=self._validate(s,action,ip)
                    if incident_id:
                        incident=s.get(Incident,incident_id)
                        if not incident or incident.source!=ip: raise ValueError('incident/source mismatch')
                    if action in ['acknowledge','ignore'] and not incident_id: raise ValueError('incident required')
                    a=Action(id=uuid.uuid4().hex,created=time.time(),status='pending',data={'action':action,'ip':ip,'reason':reason,'mode':mode,'incident_id':incident_id})
                    s.add(a);self.store.audit(s,'response.requested',{'action_id':a.id,**a.data})
                    if mode=='SIMULATION' or action in ['whitelist','unwhitelist','acknowledge','ignore']: self._apply(s,a)
                    result={'id':a.id,'status':a.status,**a.data}
                return result
            except ValueError as exc:
                self.store.event('response.refused',{'action':action,'ip':ip,'reason':str(exc)});raise

    def _apply(self,s,a):
        d=a.data;action=d['action'];ip=self._validate(s,action,d['ip'])
        if action=='whitelist':
            if s.get(Source,(ip,'blocked')): raise ValueError('unblock source before whitelisting')
            s.merge(Source(ip=ip,kind='whitelist',data={'reason':d['reason']}));a.status='applied'
        elif action=='unwhitelist':
            r=s.get(Source,(ip,'whitelist'))
            if r:s.delete(r)
            a.status='applied'
        elif action in ['acknowledge','ignore']:
            r=s.get(Incident,d['incident_id']);r.status='acknowledged' if action=='acknowledge' else 'ignored';a.status='applied'
        elif d['mode']=='ACTIVE':
            if not self.active_enabled or platform.system()!='Windows': raise ValueError('active response disabled or unsupported')
            result=subprocess.run(firewall_arguments(action,ip),shell=False,capture_output=True,text=True,timeout=15)
            if result.returncode: raise ValueError('firewall rejected action: '+result.stderr[:300])
            if action=='block': s.merge(Source(ip=ip,kind='blocked',data={'reason':d['reason'],'action_id':a.id}))
            else:
                r=s.get(Source,(ip,'blocked'))
                if r:s.delete(r)
            a.status='executed'
        else:a.status='simulated'
        self.store.audit(s,'response.'+a.status,{'action_id':a.id,**d})

    def decide(self,id,approve):
        with self.lock:
            try:
                with self.store.transaction() as s:
                    a=s.scalar(select(Action).where(Action.id==id).with_for_update())
                    if not a: raise KeyError('action not found')
                    if a.status=='pending':
                        if approve:self._apply(s,a)
                        else:a.status='rejected';self.store.audit(s,'response.rejected',{'action_id':id})
                    return {'id':a.id,'status':a.status,**a.data}
            except ValueError as exc:
                self.store.event('response.approval_refused',{'action_id':id,'reason':str(exc)});raise
