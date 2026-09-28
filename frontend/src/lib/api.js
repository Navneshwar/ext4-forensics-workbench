const BASE="http://127.0.0.1:8000/api";
async function req(path,opt={}){const r=await fetch(BASE+path,{headers:{"Content-Type":"application/json",...(opt.headers||{})},...opt});const b=await r.json().catch(()=>({}));if(!r.ok)throw new Error(b.detail||`Request failed (${r.status})`);return b}
export const api={
 resources:()=>req("/system/resources"),
 createScan:p=>req("/scans",{method:"POST",body:JSON.stringify(p)}),
 scan:id=>req(`/scans/${id}`), findings:id=>req(`/scans/${id}/findings`),
 artifacts:id=>req(`/scans/${id}/artifacts`), refreshArtifacts:id=>req(`/scans/${id}/artifacts/refresh`,{method:"POST"}),
 integrity:id=>req(`/cases/${id}/integrity`),
 recover:(id,ids)=>req(`/scans/${id}/recover`,{method:"POST",body:JSON.stringify({finding_ids:ids})}),
 reportJson:id=>`${BASE}/scans/${id}/report.json`, reportDocx:id=>`${BASE}/scans/${id}/report.docx`, download:id=>`${BASE}/findings/${id}/download`
};
