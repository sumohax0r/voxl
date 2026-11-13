// Voxl's optional Windows logon bridge. No credential is persisted to disk.
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <cstring>
#include <cwchar>
#include <wtsapi32.h>
#include <sddl.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <atomic>
#include <mutex>
#include <string>
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"wtsapi32.lib")
#pragma comment(lib,"secur32.lib")
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"uuid.lib")

// {A9876D86-53B1-4C76-A451-9682022BF25A}
static const CLSID CLSID_Voxl = {0xa9876d86,0x53b1,0x4c76,{0xa4,0x51,0x96,0x82,0x02,0x2b,0xf2,0x5a}};
static std::atomic<long> objects{0};
struct Request { DWORD version; WCHAR user[257]; WCHAR password[4097]; };
struct Handle {
    HANDLE h=nullptr;
    explicit Handle(HANDLE v=nullptr):h(v){}
    ~Handle(){if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h);}
    Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
};
static bool systemToken(HANDLE token) {
    BYTE data[512]; DWORD n=0;
    return GetTokenInformation(token,TokenUser,data,sizeof(data),&n) &&
        IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(data)->User.Sid,WinLocalSystemSid);
}
static bool isSystem() {
    Handle token; return OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.h) && systemToken(token.h);
}
// Fail closed on enumeration/query errors, including a newly connecting RDP session.
static bool rdpBusy() {
    PWTS_SESSION_INFOW sessions=nullptr; DWORD count=0;
    if(!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&sessions,&count)) return true;
    bool busy=false;
    for(DWORD i=0;i<count;i++) {
        if(sessions[i].State!=WTSActive && sessions[i].State!=WTSConnected && sessions[i].State!=WTSConnectQuery) continue;
        LPWSTR data=nullptr; DWORD size=0;
        if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,sessions[i].SessionId,WTSClientProtocolType,&data,&size)) {busy=true;break;}
        if(size<sizeof(USHORT) || *reinterpret_cast<USHORT*>(data)==2) busy=true;
        WTSFreeMemory(data);
        if(busy) break;
    }
    WTSFreeMemory(sessions); return busy;
}
static bool enableTcb() {
    Handle token; TOKEN_PRIVILEGES privileges{}; privileges.PrivilegeCount=1;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token.h) ||
       !LookupPrivilegeValueW(nullptr,SE_TCB_NAME,&privileges.Privileges[0].Luid)) return false;
    privileges.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(token.h,FALSE,&privileges,sizeof(privileges),nullptr,nullptr) && GetLastError()==ERROR_SUCCESS;
}
static bool onConsole() {
    DWORD id=0; return ProcessIdToSessionId(GetCurrentProcessId(),&id) && id==WTSGetActiveConsoleSessionId();
}
static std::wstring pipeName() {
    return L"\\\\.\\pipe\\VoxlLogon-"+std::to_wstring(WTSGetActiveConsoleSessionId());
}
static bool io(HANDLE pipe,void* data,DWORD size,bool write,DWORD timeout=5000) {
    Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    OVERLAPPED ov{}; ov.hEvent=event.h; DWORD done=0;
    BOOL ok=write?WriteFile(pipe,data,size,&done,&ov):ReadFile(pipe,data,size,&done,&ov);
    if(!ok && GetLastError()==ERROR_IO_PENDING) {
        if(WaitForSingleObject(event.h,timeout)!=WAIT_OBJECT_0) {
            CancelIoEx(pipe,&ov); GetOverlappedResult(pipe,&ov,&done,TRUE); return false;
        }
        ok=GetOverlappedResult(pipe,&ov,&done,FALSE);
    }
    return ok && done==size;
}
static bool validRequest(const Request& r) {
    return r.version==1 && r.user[0] && r.password[0] &&
        wmemchr(r.user,0,257) && wmemchr(r.password,0,4097);
}
static bool logonToken(const Request& r, HANDLE* token) {
    std::wstring user=r.user, domain=L".";
    auto slash=user.find(L'\\');
    if(slash!=std::wstring::npos){domain=user.substr(0,slash);user=user.substr(slash+1);}
    else if(user.find(L'@')!=std::wstring::npos) domain.clear();
    return LogonUserW(user.c_str(),domain.empty()?nullptr:domain.c_str(),r.password,
        LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,token)!=FALSE;
}
static bool sameUser(HANDLE a,HANDLE b) {
    BYTE aa[1024],bb[1024];DWORD n=0;
    return GetTokenInformation(a,TokenUser,aa,sizeof(aa),&n) && GetTokenInformation(b,TokenUser,bb,sizeof(bb),&n) &&
        EqualSid(reinterpret_cast<TOKEN_USER*>(aa)->User.Sid,reinterpret_cast<TOKEN_USER*>(bb)->User.Sid);
}
// Never migrate an existing user's session to the console. Besides displacing
// an RDP client, that can change the Windows session ID under the streamer.
static bool otherSession(HANDLE identity) {
    PWTS_SESSION_INFOW sessions=nullptr;DWORD count=0;
    if(!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&sessions,&count))return true;
    bool conflict=false;
    for(DWORD i=0;i<count;i++) {
        if(sessions[i].SessionId==WTSGetActiveConsoleSessionId() || sessions[i].SessionId==0)continue;
        Handle token;
        if(WTSQueryUserToken(sessions[i].SessionId,&token.h) && sameUser(identity,token.h)){conflict=true;break;}
    }
    WTSFreeMemory(sessions);return conflict;
}
static bool unlocked() {
    HDESK d=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS); if(!d) return false;
    WCHAR name[128]{};DWORD n=0;
    bool ok=GetUserObjectInformationW(d,UOI_NAME,name,sizeof(name),&n) && _wcsicmp(name,L"Default")==0;
    CloseDesktop(d);return ok;
}
// 0=ready, 1=RDP in use, 2=wrong host context, 3=authentication failure,
// 4=bridge unavailable, 5=Windows sign-in did not finish, 6=another console user.
extern "C" __declspec(dllexport) DWORD WINAPI VoxlSignIn(PCWSTR user,PCWSTR password) {
    if(!isSystem() || !onConsole() || !enableTcb()) return 2;
    if(rdpBusy()) return 1;
    Request r{};r.version=1;
    if(!user || !password || FAILED(StringCchCopyW(r.user,257,user)) || FAILED(StringCchCopyW(r.password,4097,password))) {SecureZeroMemory(&r,sizeof(r));return 3;}
    struct Wipe {Request& r;~Wipe(){SecureZeroMemory(&r,sizeof(r));}} wipe{r};
    Handle identity;if(!logonToken(r,&identity.h)) return 3;
    if(otherSession(identity.h)) return 6;
    Handle current;
    if(WTSQueryUserToken(WTSGetActiveConsoleSessionId(),&current.h)) {
        if(!sameUser(identity.h,current.h)) return 6;
        if(unlocked()) return 0;
    }
    Handle pipe(CreateFileW(pipeName().c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));
    if(pipe.h==INVALID_HANDLE_VALUE) return 4;
    ULONG pid=0; if(!GetNamedPipeServerProcessId(pipe.h,&pid)) return 4;
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid)),token;
    DWORD session=0;
    if(!process.h || !OpenProcessToken(process.h,TOKEN_QUERY,&token.h) || !systemToken(token.h) ||
        !ProcessIdToSessionId(pid,&session) || session!=WTSGetActiveConsoleSessionId()) return 4;
    DWORD response=4;
    if(!io(pipe.h,&r,sizeof(r),true) || !io(pipe.h,&response,sizeof(response),false)) return 4;
    SecureZeroMemory(&r,sizeof(r));
    if(response) return response;
    for(int i=0;i<150;i++) {
        if(rdpBusy()) return 1;
        Handle logged;
        if(WTSQueryUserToken(WTSGetActiveConsoleSessionId(),&logged.h) && sameUser(identity.h,logged.h) && unlocked()) return 0;
        Sleep(100);
    }
    return 5;
}
extern "C" __declspec(dllexport) DWORD WINAPI VoxlRdpBusy() {return rdpBusy()?1:0;}

class Provider;
class Credential final : public ICredentialProviderCredential {
    std::atomic<ULONG> refs{1};Request request{};std::mutex mutex;ULONGLONG expires=0;
public:
    Credential(){++objects;} ~Credential(){SecureZeroMemory(&request,sizeof(request));--objects;}
    bool pending(){std::lock_guard<std::mutex> l(mutex);if(GetTickCount64()>=expires)SecureZeroMemory(&request,sizeof(request));return request.version==1;}
    void clear(){std::lock_guard<std::mutex> l(mutex);SecureZeroMemory(&request,sizeof(request));expires=0;}
    bool offer(const Request& r){std::lock_guard<std::mutex> l(mutex);if(request.version && GetTickCount64()<expires)return false;request=r;expires=GetTickCount64()+15000;return true;}
    IFACEMETHODIMP QueryInterface(REFIID id,void** out) override {if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown || id==IID_ICredentialProviderCredential){*out=static_cast<ICredentialProviderCredential*>(this);AddRef();return S_OK;}return E_NOINTERFACE;}
    IFACEMETHODIMP_(ULONG) AddRef() override{return ++refs;}
    IFACEMETHODIMP_(ULONG) Release() override{ULONG n=--refs;if(!n)delete this;return n;}
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents*) override{return S_OK;}
    IFACEMETHODIMP UnAdvise() override{return S_OK;}
    IFACEMETHODIMP SetSelected(BOOL* autoLogon) override{*autoLogon=pending() && !rdpBusy();return S_OK;}
    IFACEMETHODIMP SetDeselected() override{clear();return S_OK;}
    IFACEMETHODIMP GetFieldState(DWORD id,CREDENTIAL_PROVIDER_FIELD_STATE* state,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override {if(id)return E_INVALIDARG;*state=CPFS_DISPLAY_IN_SELECTED_TILE;*interactive=CPFIS_NONE;return S_OK;}
    IFACEMETHODIMP GetStringValue(DWORD id,PWSTR* text) override {return id?E_INVALIDARG:SHStrDupW(L"Signing in with Voxl",text);}
    IFACEMETHODIMP GetBitmapValue(DWORD,HBITMAP*) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetCheckboxValue(DWORD,BOOL*,PWSTR*) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetComboBoxValueCount(DWORD,DWORD*,DWORD*) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetComboBoxValueAt(DWORD,DWORD,PWSTR*) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetSubmitButtonValue(DWORD,DWORD*) override{return E_NOTIMPL;}
    IFACEMETHODIMP SetStringValue(DWORD,PCWSTR) override{return E_NOTIMPL;}
    IFACEMETHODIMP SetCheckboxValue(DWORD,BOOL) override{return E_NOTIMPL;}
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD,DWORD) override{return E_NOTIMPL;}
    IFACEMETHODIMP CommandLinkClicked(DWORD) override{return E_NOTIMPL;}
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialized,PWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
        *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED;*serialized={};*text=nullptr;*icon=CPSI_NONE;
        std::lock_guard<std::mutex> l(mutex);
        if(!request.version || GetTickCount64()>=expires || rdpBusy() || !onConsole()) {SecureZeroMemory(&request,sizeof(request));return S_OK;}
        std::wstring name=request.user,domain=L".";auto slash=name.find(L'\\');
        if(slash!=std::wstring::npos){domain=name.substr(0,slash);name=name.substr(slash+1);}
        else if(name.find(L'@')!=std::wstring::npos)domain.clear();
        // Packed KERB_INTERACTIVE_LOGON offsets are interpreted by Negotiate.
        DWORD nb=static_cast<DWORD>(name.size()*sizeof(WCHAR)),db=static_cast<DWORD>(domain.size()*sizeof(WCHAR)),pb=static_cast<DWORD>(wcslen(request.password)*sizeof(WCHAR));
        DWORD size=sizeof(KERB_INTERACTIVE_LOGON)+nb+db+pb;
        auto buf=static_cast<BYTE*>(CoTaskMemAlloc(size));if(!buf)return E_OUTOFMEMORY;ZeroMemory(buf,size);
        auto logon=reinterpret_cast<KERB_INTERACTIVE_LOGON*>(buf);logon->MessageType=KerbInteractiveLogon;
        DWORD offset=sizeof(*logon);
        auto pack=[&](UNICODE_STRING& dst,const WCHAR* src,DWORD bytes){dst.Length=static_cast<USHORT>(bytes);dst.MaximumLength=dst.Length;dst.Buffer=reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(offset));memcpy(buf+offset,src,bytes);offset+=bytes;};
        pack(logon->LogonDomainName,domain.c_str(),db);pack(logon->UserName,name.c_str(),nb);pack(logon->Password,request.password,pb);
        SecureZeroMemory(&request,sizeof(request));expires=0;
        LSA_HANDLE lsa=nullptr;ULONG package=0;char negotiate[]="Negotiate";LSA_STRING label{9,10,negotiate};
        NTSTATUS status=LsaConnectUntrusted(&lsa);
        if(status==0){status=LsaLookupAuthenticationPackage(lsa,&label,&package);LsaDeregisterLogonProcess(lsa);}
        if(status!=0){SecureZeroMemory(buf,size);CoTaskMemFree(buf);return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));}
        serialized->ulAuthenticationPackage=package;serialized->clsidCredentialProvider=CLSID_Voxl;serialized->cbSerialization=size;serialized->rgbSerialization=buf;*response=CPGSR_RETURN_CREDENTIAL_FINISHED;return S_OK;
    }
    IFACEMETHODIMP ReportResult(NTSTATUS,NTSTATUS,PWSTR* text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override{clear();*text=nullptr;*icon=CPSI_NONE;return S_OK;}
};

class Provider final : public ICredentialProvider {
    std::atomic<ULONG> refs{1};Credential* credential=new Credential;HANDLE stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);bool started=false;
    IGlobalInterfaceTable* git=nullptr;DWORD cookie=0;UINT_PTR context=0;
    static DWORD WINAPI worker(void* raw) {
        auto self=static_cast<Provider*>(raw);CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        PSECURITY_DESCRIPTOR sd=nullptr;ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)",SDDL_REVISION_1,&sd,nullptr);
        SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
        if(sd) while(WaitForSingleObject(self->stop,0)==WAIT_TIMEOUT) {
            Handle pipe(CreateNamedPipeW(pipeName().c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,sizeof(DWORD),sizeof(Request),0,&sa));
            if(pipe.h==INVALID_HANDLE_VALUE) break;
            Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));OVERLAPPED ov{};ov.hEvent=event.h;
            BOOL connected=ConnectNamedPipe(pipe.h,&ov);DWORD err=connected?ERROR_SUCCESS:GetLastError();
            if(err==ERROR_IO_PENDING){HANDLE waits[]={self->stop,event.h};if(WaitForMultipleObjects(2,waits,FALSE,INFINITE)!=WAIT_OBJECT_0+1){CancelIoEx(pipe.h,&ov);DWORD n;GetOverlappedResult(pipe.h,&ov,&n,TRUE);break;}DWORD n;connected=GetOverlappedResult(pipe.h,&ov,&n,FALSE);}
            else connected=connected || err==ERROR_PIPE_CONNECTED;
            if(!connected)continue;
            Request request{};DWORD result=4;bool offered=false;
            if(io(pipe.h,&request,sizeof(request),false) && validRequest(request) && onConsole()) {
                if(rdpBusy())result=1;
                else {Handle token;if(logonToken(request,&token.h)){if(otherSession(token.h))result=6;else {offered=self->credential->offer(request);result=offered?0:4;}}else result=3;}
            }
            SecureZeroMemory(&request,sizeof(request));
            bool sent=io(pipe.h,&result,sizeof(result),true);
            if(offered && sent && WaitForSingleObject(self->stop,0)==WAIT_TIMEOUT){
                ICredentialProviderEvents* events=nullptr;
                if(SUCCEEDED(self->git->GetInterfaceFromGlobal(self->cookie,IID_PPV_ARGS(&events)))){events->CredentialsChanged(self->context);events->Release();}
            }else if(offered)self->credential->clear();
        }
        if(sd)LocalFree(sd);if(self->cookie)self->git->RevokeInterfaceFromGlobal(self->cookie);
        self->Release();CoUninitialize();return 0;
    }
public:
    Provider(){++objects;}~Provider(){credential->Release();if(git)git->Release();CloseHandle(stop);--objects;}
    IFACEMETHODIMP QueryInterface(REFIID id,void** out) override{if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown || id==IID_ICredentialProvider){*out=static_cast<ICredentialProvider*>(this);AddRef();return S_OK;}return E_NOINTERFACE;}
    IFACEMETHODIMP_(ULONG) AddRef() override{return ++refs;}
    IFACEMETHODIMP_(ULONG) Release() override{ULONG n=--refs;if(!n)delete this;return n;}
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD) override{return (scenario==CPUS_LOGON || scenario==CPUS_UNLOCK_WORKSTATION) && isSystem() && onConsole()?S_OK:E_NOTIMPL;}
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override{return E_NOTIMPL;}
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events,UINT_PTR value) override{
        if(started)return E_UNEXPECTED;
        HRESULT hr=CoCreateInstance(CLSID_StdGlobalInterfaceTable,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&git));if(FAILED(hr))return hr;
        hr=git->RegisterInterfaceInGlobal(events,IID_ICredentialProviderEvents,&cookie);if(FAILED(hr))return hr;
        context=value;started=true;AddRef();Handle thread(CreateThread(nullptr,0,worker,this,0,nullptr));if(!thread.h){Release();git->RevokeInterfaceFromGlobal(cookie);cookie=0;return E_FAIL;}return S_OK;
    }
    IFACEMETHODIMP UnAdvise() override{SetEvent(stop);credential->clear();return S_OK;}
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override{*count=1;return S_OK;}
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD id,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) override{
        if(id)return E_INVALIDARG;auto p=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));if(!p)return E_OUTOFMEMORY;
        *p={};p->dwFieldID=0;p->cpft=CPFT_LARGE_TEXT;HRESULT hr=SHStrDupW(L"Voxl",&p->pszLabel);if(FAILED(hr)){CoTaskMemFree(p);return hr;}*out=p;return S_OK;
    }
    IFACEMETHODIMP GetCredentialCount(DWORD* count,DWORD* selected,BOOL* automatic) override{bool ready=credential->pending() && !rdpBusy();*count=ready?1:0;*selected=ready?0:CREDENTIAL_PROVIDER_NO_DEFAULT;*automatic=ready;return S_OK;}
    IFACEMETHODIMP GetCredentialAt(DWORD id,ICredentialProviderCredential** out) override{if(id || !credential->pending())return E_INVALIDARG;*out=credential;credential->AddRef();return S_OK;}
};
class Factory final : public IClassFactory {
    std::atomic<ULONG> refs{1};
public:
    Factory(){++objects;}~Factory(){--objects;}
    IFACEMETHODIMP QueryInterface(REFIID id,void** out) override{if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown || id==IID_IClassFactory){*out=static_cast<IClassFactory*>(this);AddRef();return S_OK;}return E_NOINTERFACE;}
    IFACEMETHODIMP_(ULONG) AddRef() override{return ++refs;}
    IFACEMETHODIMP_(ULONG) Release() override{ULONG n=--refs;if(!n)delete this;return n;}
    IFACEMETHODIMP CreateInstance(IUnknown* outer,REFIID id,void** out) override{if(outer)return CLASS_E_NOAGGREGATION;auto p=new Provider;HRESULT hr=p->QueryInterface(id,out);p->Release();return hr;}
    IFACEMETHODIMP LockServer(BOOL lock) override{if(lock)++objects;else --objects;return S_OK;}
};
STDAPI DllGetClassObject(REFCLSID clsid,REFIID id,void** out){if(clsid!=CLSID_Voxl)return CLASS_E_CLASSNOTAVAILABLE;auto f=new Factory;HRESULT hr=f->QueryInterface(id,out);f->Release();return hr;}
STDAPI DllCanUnloadNow(){return objects==0?S_OK:S_FALSE;}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(instance);return TRUE;}
