#include "convenience.h"
#include "util.h"
#include "scopeguard.hpp"
#include "walk.h"
#include <windows.h>
#include <restartmanager.h>

#pragma comment(lib, "Rstrtmgr.lib")

Napi::Value IsThisWineWrap(const Napi::CallbackInfo &info) {
  HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
  FARPROC addr = GetProcAddress(ntdll, "wine_get_version");

  return Napi::Boolean::New(info.Env(), addr != nullptr);
}

struct Process {
  DWORD pid;
  std::wstring appName;
};

std::vector<Process> WhoIsLocking(const std::string &path)
{
  std::vector<Process> result;

  DWORD handle;
  WCHAR sessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
  DWORD res = RmStartSession(&handle, 0, sessionKey);
  if (res != ERROR_SUCCESS) {
    throw WinApiException(res, "RmStartSession", path.c_str());
  }

  ScopeGuard onExit([handle]() { RmEndSession(handle); });

  std::wstring pathW = toWC(path.c_str(), CodePage::UTF8, path.size());
  LPCWSTR pathP = pathW.c_str();
  res = RmRegisterResources(handle, 1, &pathP, 0, nullptr, 0, nullptr);
  if (res != ERROR_SUCCESS) {
    throw WinApiException(res, "RmRegisterResources", path.c_str());
  }

  UINT numInfoNeeded = 0;
  UINT numInfo = 2;
  std::vector<RM_PROCESS_INFO> info(numInfo);
  DWORD reason;

  res = RmGetList(handle, &numInfoNeeded, &numInfo, &info[0], &reason);
  // it's possible, although very unlikely that between two calls of getlist the number of
  // processes changes. Hence repeat until we actually get everything
  while (res == ERROR_MORE_DATA) {
    numInfo = numInfoNeeded;
    info.resize(numInfo);
    res = RmGetList(handle, &numInfoNeeded, &numInfo, &info[0], &reason);
  }

  if (res != ERROR_SUCCESS) {
    if (res == ERROR_ACCESS_DENIED) {
      // the restart manager api supports only files and reports access denied for directories.
      // We could see if any file in the directory is locked but that would be slow and still
      // wouldn't be too reliable as applications with their cwd on the directory lock it as well
      numInfo = 0;
    }
    else {
      throw WinApiException(res, "RmGetList", path.c_str());
    }
  }

  for (UINT i = 0; i < numInfo; ++i) {
    Process proc = { info[i].Process.dwProcessId, info[i].strAppName };
    result.push_back(proc);
  }

  return result;
}

Napi::Object convert(const Napi::Env &env, const Process &proc) {
  Napi::Object result = Napi::Object::New(env);
  result.Set("appName", toNapi(env, proc.appName.c_str()));
  result.Set("pid", Napi::Number::New(env, proc.pid));
  return result;
}

Napi::Value WhoLocks(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw std::exception("Expected 1 parameter (filePath)");
    }

    std::string path(info[0].ToString());


    std::vector<Process> processes = WhoIsLocking(info[0].ToString());
    Napi::Array retValue = Napi::Array::New(info.Env());
    for (int i = 0; i < processes.size(); ++i) {
      retValue.Set(i, convert(info.Env(), processes[i]));
    }
    return retValue;
  }
  catch (const std::exception &err) {
    return Rethrow(info.Env(), err);
  }
}

bool get(const Napi::Object &obj, const char* key, const bool &def) {
  return obj.Has(key)
    ? obj.Get(key).As<Napi::Boolean>()
    : def;
}

uint32_t get(const Napi::Object &obj, const char* key, const uint32_t &def) {
  return obj.Has(key)
    ? obj.Get(key).As<Napi::Number>().Uint32Value()
    : def;
}

Napi::Object convert(const Napi::Env &env, const Entry &input) {
  Napi::Object result = Napi::Object::New(env);
  result.Set("filePath", Napi::String::New(env, toMB(input.filePath.c_str(), CodePage::UTF8, input.filePath.size())));
  result.Set("isDirectory", Napi::Boolean::New(env, (input.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0));
  result.Set("isReparsePoint", Napi::Boolean::New(env, (input.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0));
  result.Set("size", Napi::Number::New(env, static_cast<double>(input.size)));
  result.Set("mtime", Napi::Number::New(env, input.mtime));
  result.Set("isTerminator", Napi::Boolean::New(env, (input.attributes & FILE_ATTRIBUTE_TERMINATOR) != 0));

  if (input.linkCount.has_value()) {
    result.Set("linkCount", Napi::Number::New(env, *input.linkCount));
  }
  if (input.id.has_value()) {
    result.Set("id", Napi::Number::New(env, static_cast<double>(*input.id)));
    result.Set("idStr", Napi::String::New(env, *input.idStr));
  }

  return result;
}

Napi::Array convert(const Napi::Env &env, const Entry *input, size_t count) {
  Napi::Array result = Napi::Array::New(env);
  for (size_t i = 0; i < count; ++i) {
    result.Set(i, convert(env, input[i]));
  }
  return result;
}

class WalkWorker : public Napi::AsyncProgressQueueWorker<Entry> {
public:
  WalkWorker(const Napi::Function &callback, const Napi::Function &progress, const std::wstring &basePath, const WalkOptions &options)
    : Napi::AsyncProgressQueueWorker<Entry>(callback)
    , mProgress(Napi::Persistent(progress))
    , mBasePath(basePath)
    , mCancelled(false)
    , mOptions(options)
    , mErrorCode(0)
    , mErrorFunc()
    , mErrorPath()
  {}

  ~WalkWorker() {
  }

  virtual void Execute(const ExecutionProgress &progress) override {
    mCancelled = false;
    try {
      walk(mBasePath, [&progress, this](const std::vector<Entry>& entries) -> bool {
        progress.Send(&entries[0], entries.size());
        return !mCancelled;
        }, mOptions);
    }
    catch (const WinApiException& e) {
      mErrorCode = e.getCode();
      mErrorFunc = e.getFunc();
      mErrorPath = e.getPath();
      SetError(e.what());
    }
    catch (const std::exception& e) {
      SetError(e.what());
    }
  }

  virtual void OnProgress(const Entry* data, size_t size) override {
    try {
      Napi::Value res = mProgress.Call(Receiver().Value(), std::initializer_list<napi_value>{ convert(Env(), data, size) });
      if (!res.ToBoolean()) {
        mCancelled = true;
      }
    }
    catch (const std::exception& e) {
      SetError(e.what());
    }
  }

  virtual void OnOK() override {
    Callback().Call(Receiver().Value(), std::initializer_list<napi_value>{ Env().Null() });
  }

  virtual void OnError(const Napi::Error &e) override {
    Callback().Call(Receiver().Value(), std::initializer_list<napi_value>{
      mErrorCode != 0
        ? MakeWinApiException(Env(), mErrorCode, mErrorFunc.c_str(), mErrorPath.c_str())
        : e.Value()
    });
  }

private:
  Napi::FunctionReference mProgress;
  std::wstring mBasePath;
  bool mCancelled;
  WalkOptions mOptions;
  uint32_t mErrorCode;
  std::string mErrorFunc;
  std::string mErrorPath;
};

Napi::Value WalkDir(const Napi::CallbackInfo& info) {
  try {
    if ((info.Length() < 3) || (info.Length() > 4)) {
      throw std::exception("Expected 3 or 4 arguments (searchPath, progressCB, options?, resultsCB)");
    }

    WalkOptions options;
    if (info.Length() > 3) {
      Napi::Object optionsIn = info[2].ToObject();
      options.details = get(optionsIn, "details", false);
      options.terminators = get(optionsIn, "terminators", false);
      options.threshold = get(optionsIn, "threshold", 1024u);
      options.recurse = get(optionsIn, "recurse", true);
      options.skipLinks = get(optionsIn, "skipLinks", true);
      options.skipHidden = get(optionsIn, "skipHidden", true);
      options.skipInaccessible = get(optionsIn, "skipInaccessible", true);
    }

    Napi::Function progress = info[1].As<Napi::Function>();
    Napi::Function callback = info[info.Length() - 1].As<Napi::Function>();

    auto worker = new WalkWorker(callback, progress, toWC(info[0]), options);

    worker->Queue();
    return info.Env().Undefined();
  }
  catch (const std::exception& err) {
    return Rethrow(info.Env(), err);
  }
}

Napi::Value CrashProcess(const Napi::CallbackInfo& info) {
  *(char*)0 = 0;
  return info.Env().Undefined();
}

namespace Convenience {
  void Init(Napi::Env env, Napi::Object exports) {
    exports.Set("WhoLocks", Napi::Function::New(env, WhoLocks));
    exports.Set("IsThisWine", Napi::Function::New(env, IsThisWineWrap));
    exports.Set("WalkDir", Napi::Function::New(env, WalkDir));
    exports.Set("__CrashProcess", Napi::Function::New(env, CrashProcess));
  }
}
