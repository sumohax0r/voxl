#include "bridge.cpp"
#undef NDEBUG
#include <cassert>
int main() {
    Request request{};
    assert(!validRequest(request));
    request.version=1;StringCchCopyW(request.user,257,L"test");StringCchCopyW(request.password,4097,L"password");
    assert(validRequest(request));
    for(auto& c:request.password)c=L'x';
    assert(!validRequest(request));
    SecureZeroMemory(&request,sizeof(request));
    // COM activation/ownership works without registering the provider or changing LogonUI.
    IClassFactory* factory=nullptr;
    assert(SUCCEEDED(DllGetClassObject(CLSID_Voxl,IID_PPV_ARGS(&factory))));
    ICredentialProvider* provider=nullptr;
    assert(SUCCEEDED(factory->CreateInstance(nullptr,IID_PPV_ARGS(&provider))));
    DWORD count=99,selected=99;BOOL automatic=TRUE;
    assert(SUCCEEDED(provider->GetCredentialCount(&count,&selected,&automatic)));
    assert(count==0 && selected==CREDENTIAL_PROVIDER_NO_DEFAULT && !automatic);
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor=nullptr;
    assert(SUCCEEDED(provider->GetFieldDescriptorAt(0,&descriptor)));
    CoTaskMemFree(descriptor->pszLabel);CoTaskMemFree(descriptor);
    assert(provider->SetUsageScenario(CPUS_CREDUI,0)==E_NOTIMPL);
    provider->Release();factory->Release();
    assert(DllCanUnloadNow()==S_OK);
    // Non-SYSTEM callers cannot turn successful web authentication into desktop logon.
    if(!isSystem()) assert(VoxlSignIn(L"nobody",L"not-a-password")==2);
    return 0;
}
