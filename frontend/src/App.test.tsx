// @vitest-environment jsdom
import {describe,it,expect,vi,afterEach} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import {MemoryRouter} from 'react-router-dom';
import App from './App';
const json=(body:any,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
afterEach(()=>{cleanup();vi.unstubAllGlobals()});

describe('SentinelAuth routes and authentication flows',()=>{
 it('shows sign in after the session lookup fails',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new Error('offline')));
  render(<MemoryRouter><App/></MemoryRouter>);
  expect(await screen.findByRole('heading',{name:'Welcome back'})).toBeTruthy();
  expect(screen.getByLabelText('Work email')).toBeTruthy();
  expect(screen.getByRole('button',{name:/sign in/i})).toBeTruthy();
 });
 it('submits registration to the API and displays the dev-only verification state',async()=>{
  const fetchMock=vi.fn(async(input:any,init:any)=>{
   const url=String(input);
   if(url.endsWith('/auth/me'))return json({detail:'Authentication required'},401);
   if(url.endsWith('/auth/register'))return json({id:7,email:'casey@example.com',name:'Casey Example',verified:false,message:'Account created. Check email for verification.',development_only_link:'/verify-email?token=development-token'},201);
   throw new Error('unexpected request '+url);
  });
  vi.stubGlobal('fetch',fetchMock);
  render(<MemoryRouter initialEntries={['/register']}><App/></MemoryRouter>);
  fireEvent.change(await screen.findByLabelText('Full name'),{target:{value:'Casey Example'}});
  fireEvent.change(screen.getByLabelText('Work email'),{target:{value:'casey@example.com'}});
  fireEvent.change(screen.getByLabelText('Password'),{target:{value:'a-long-safe-test-password'}});
  fireEvent.click(screen.getByRole('button',{name:/create account/i}));
  expect(await screen.findByText(/development verification link/i)).toBeTruthy();
  const call=fetchMock.mock.calls.find(([url])=>String(url).endsWith('/auth/register'));
  expect(JSON.parse(call![1]!.body as string)).toEqual({name:'Casey Example',email:'casey@example.com',password:'a-long-safe-test-password'});
 });
 it('moves from password login to the separate MFA challenge',async()=>{
  const fetchMock=vi.fn(async(input:any,init?:RequestInit)=>{
   const url=String(input);
   if(url.endsWith('/auth/me'))return json({detail:'Authentication required'},401);
   if(url.endsWith('/auth/login'))return json({mfa_required:true,challenge_id:'one-time-challenge'});
   throw new Error('unexpected request '+url);
  });
  vi.stubGlobal('fetch',fetchMock);
  render(<MemoryRouter><App/></MemoryRouter>);
  fireEvent.change(await screen.findByLabelText('Work email'),{target:{value:'casey@example.com'}});
  fireEvent.change(screen.getByLabelText('Password'),{target:{value:'some-password'}});
  fireEvent.click(screen.getByRole('button',{name:/sign in/i}));
  expect(await screen.findByRole('heading',{name:'Verify your identity'})).toBeTruthy();
  expect(screen.getByLabelText('Authenticator or recovery code')).toBeTruthy();
  const call=fetchMock.mock.calls.find(([url])=>String(url).endsWith('/auth/login'));
  expect(JSON.parse(call![1]!.body as string)).toEqual({email:'casey@example.com',password:'some-password'});
 });
});
