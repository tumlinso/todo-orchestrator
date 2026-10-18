#!/usr/bin/env python3
"""Offline bootstrap consistency checker. No writes or access to Todo authorities."""
from __future__ import annotations
import csv, hashlib, json, re, sys
from pathlib import Path

DOCS = ['START_HERE.md','PRODUCT_SPEC.md','ARCHITECTURE.md','DOMAIN_AND_INVARIANTS.md',
        'PLANNING_AND_INGESTION.md','WORKFLOW_AND_AUTHORITY.md','VERIFICATION_AND_RECOVERY.md',
        'INTEGRATION_AND_CUTOVER.md','ACCEPTANCE_AND_TESTS.md','MIGRATION_MAP.md',
        'RISKS_AND_OPEN_DESIGN.md','CODEX_HANDOFF.md']

def main(root: Path):
    errors=[]
    def expect(ok, why):
        if not ok: errors.append(why)
    def load(name):
        try: return json.loads((root/name).read_text(encoding='utf-8'))
        except Exception as e:
            errors.append(f'cannot read {name}: {e}');return {}
    for doc in DOCS: expect((root/doc).is_file(), f'missing document {doc}')
    p=load('machine/todo-orchestrator.todo-plan.json'); src=load('machine/proposed_todos.json')
    w=load('machine/workstreams.json'); lm=load('machine/lanes.json'); contracts=load('machine/contracts.json')
    expect(p.get('schema_version')==3,'expected native plan schema v3')
    runs=p.get('runs',[]); expect(len(runs)==1,'expected exactly one run')
    if not runs:return {'valid':False,'errors':errors}
    run=runs[0]; tasks=p.get('tasks',[]); tid=[x.get('id') for x in tasks]; byid={t.get('id'):t for t in tasks}
    expect(len(tid)==len(set(tid)) and all(tid),'missing or duplicate task ID')
    expect(run.get('root_task_id')=='TO-ROOT' and byid.get('TO-ROOT',{}).get('kind')=='epic','root mismatch')
    fs=src.get('tasks',[]); feature_ids={x.get('id') for x in fs}
    expect(len(fs)==len(feature_ids)==36,'expected 36 unique feature deliverables')
    expected_deps=set();expected_accept=set()
    for item in fs:
        ident=item['id']; task=byid.get(ident,{})
        expect(task.get('parent_id')==item.get('workstream'),f'wrong parent {ident}')
        nd={d.get('task_id') for d in task.get('depends_on',[]) if d.get('type')=='task'}
        expect(nd==set(item.get('dependencies',[])),f'dependency mismatch {ident}')
        expect(task.get('completion_contract',{}).get('assertions')==item.get('acceptance'),f'acceptance mismatch {ident}')
        expect(bool(task.get('scope',{}).get('exclusive_paths')),f'missing scope {ident}')
        expect((root/'task-sheets'/f'{ident}.md').is_file(),f'missing sheet {ident}')
        expected_deps.update((d,ident) for d in item.get('dependencies',[]))
        expected_accept.update((ident,j,a) for j,a in enumerate(item.get('acceptance',[]),1))
    ws={t['id'] for t in tasks if t.get('kind')=='workstream'}
    expect(len(ws)==8 and ws=={i['id'] for i in w.get('workstreams',[])},'workstreams mismatch')
    expect(contracts.get('status')=='proposed_design_not_native_todo_interfaces','contracts must be clearly advisory')
    lanes=run.get('lanes',[]);expect(len(lanes)==8 and lanes==lm.get('lanes'),'lane catalog mismatch')
    roots=[l for l in lanes if not l.get('parent_lane_id')]
    expect(len(roots)==1 and roots[0].get('id')=='L-FOUNDATION','root lane mismatch')
    laneids={l.get('id') for l in lanes};queued=[]
    for l in lanes:
        expect(not l.get('parent_lane_id') or l.get('parent_lane_id') in laneids,f'unknown lane parent {l.get("id")}')
        expect(l.get('role') in {'coordinator','implementer','specialist','integrator','validator'},f'invalid lane role {l.get("id")}')
        expect((root/'lanes'/f'{l.get("id")}.md').is_file(),f'missing lane brief {l.get("id")}')
        queued.extend(l.get('tasks',[]))
    expect(len(queued)==len(set(queued)) and set(queued)==set(tid),'tasks not assigned uniquely in run')
    # Complete direct task/parent topological check; future engine must support cross-type cycles too.
    outgoing={k:[] for k in tid}; incoming={k:0 for k in tid}
    for t in tasks:
        ident=t.get('id');deps=([t['parent_id']] if t.get('parent_id') else [])+[d.get('task_id') for d in t.get('depends_on',[]) if d.get('type')=='task']
        for d in deps:
            if d not in byid:errors.append(f'unknown task prerequisite {ident} -> {d}');continue
            outgoing[d].append(ident);incoming[ident]+=1
        for path in t.get('scope',{}).get('exclusive_paths',[]):
            expect(bool(path and not path.startswith('/') and '..' not in Path(path).parts and '\\' not in path),f'unsafe source scope {ident}: {path}')
    ready=[k for k,d in incoming.items() if d==0];count=0
    while ready:
        x=ready.pop();count+=1
        for y in outgoing[x]:
            incoming[y]-=1
            if incoming[y]==0:ready.append(y)
    expect(count==len(tid),'cycle in task/parent DAG')
    with (root/'machine/dependencies.csv').open(encoding='utf-8',newline='') as f:
        drows={(r['prerequisite_task'],r['dependent_task']) for r in csv.DictReader(f)}
    expect(drows==expected_deps,'dependencies.csv differs from task catalog')
    with (root/'machine/acceptance.csv').open(encoding='utf-8',newline='') as f:
        arows={(r['task_id'],int(r['assertion_number']),r['acceptance_assertion']) for r in csv.DictReader(f)}
    expect(arows==expected_accept,'acceptance.csv differs from task catalog')
    manifest=root/'MANIFEST.sha256'
    if manifest.is_file():
        refs={}
        for row in manifest.read_text(encoding='utf-8').splitlines():
            m=re.fullmatch('([0-9a-f]{64})  (.+)',row)
            if not m:errors.append('malformed manifest line');continue
            refs[m.group(2)]=m.group(1)
        actual={x.relative_to(root).as_posix() for x in root.rglob('*') if x.is_file() and x.name!='MANIFEST.sha256'}
        expect(set(refs)==actual,'manifest filenames mismatch')
        for rel,expected in refs.items():
            path=root/rel
            if path.is_file():expect(hashlib.sha256(path.read_bytes()).hexdigest()==expected,f'manifest digest mismatch {rel}')
    return {'valid':not errors,'errors':errors,'statistics':{'outcome_tasks':len(fs),'plan_records':len(tasks),'workstreams':len(ws),'lanes':len(lanes),'task_dependencies':len(expected_deps),'design_contracts':len(contracts.get('contracts',[]))},'live_todo_validation':'not_run_workspace_not_permitted','scope':'offline_package_consistency_only'}

if __name__=='__main__':
    directory=Path(sys.argv[1]).expanduser().resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[1]
    result=main(directory)
    print(json.dumps(result,indent=2,sort_keys=True))
    sys.exit(0 if result['valid'] else 1)
