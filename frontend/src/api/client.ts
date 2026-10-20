export async function api<T=any>(path:string, options:RequestInit={}):Promise<T>{
 const csrf=document.cookie.split('; ').find(x=>x.startsWith('sentinel_csrf='))?.split('=').slice(1).join('=');
 const response=await fetch('/api/v1'+path,{...options,credentials:'include',headers:{'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':decodeURIComponent(csrf)}:{}),...options.headers}});
 const data=await response.json().catch(()=>({detail:'Unexpected server response'})); if(!response.ok) throw new Error(data.detail||'Request failed'); return data;
}
