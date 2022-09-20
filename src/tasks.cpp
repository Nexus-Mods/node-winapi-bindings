#include "tasks.h"
#include "util.h"
#ifdef _WIN32
#include <atlbase.h>
#include <comdef.h>
#include <taskschd.h>
#include <windows.h>
#pragma comment(lib, "taskschd.lib")
#endif
#include <unordered_map>
#ifdef _WIN32
ITaskService *getScheduler(const Napi::Env &env) {
  ITaskService *sched;
  HRESULT res = CoCreateInstance(CLSID_TaskScheduler,
    nullptr,
    CLSCTX_INPROC_SERVER,
    IID_ITaskService,
    (void **)&sched);

  if (FAILED(res)) {
    ThrowHResultException(env, res, "CoCreateInstance");
    return nullptr;
  }

  res = sched->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

  if (FAILED(res)) {
    ThrowHResultException(env, res, "ITaskService::Connect");
    return nullptr;
  }

  return sched;
}

#define ASSIGN(env, obj, params, fieldName, convFunc) {\
  Napi::Value val = params.Get(# fieldName);\
  if (!val.IsNull() && !val.IsUndefined()) {\
    obj->put_ ## fieldName ## (convFunc(env, val));\
  }\
}

bool addAction(const Napi::Env &env, ITaskDefinition *task, const Napi::Object &settings) {
  clean_ptr<IActionCollection> actions(nullptr, CoRelease<IActionCollection>);
  if (!clean_ptr_assign(actions, [&](IActionCollection **out) {
    return task->get_Actions(out);
    }, "IActionCollection::get_Actions")) {
    return false;
  }

  clean_ptr<IAction> action(nullptr, CoRelease<IAction>);
  if (!clean_ptr_assign(action, [&](IAction **out) {
    return actions->Create(TASK_ACTION_EXEC, out);
    }, "IActions::Create")) {
    return false;
  }

  clean_ptr<IExecAction> exec(nullptr, CoRelease<IExecAction>);
  if (!clean_ptr_assign(exec, [&](IExecAction **out) {
    return action->QueryInterface(IID_IExecAction, (void**)out);
    }, "IAction::QueryInterface")) {
    return false;
  }

  ASSIGN(env, exec, settings, Path, TOBSTRING);
  ASSIGN(env, exec, settings, Arguments, TOBSTRING);
  ASSIGN(env, exec, settings, Id, TOBSTRING);
  ASSIGN(env, exec, settings, WorkingDirectory, TOBSTRING);

  return true;
}

TASK_LOGON_TYPE convLogonType(const Napi::Env &env, const Napi::Value &input) {
  static const std::unordered_map<std::string, TASK_LOGON_TYPE> logonTypeMap{
      { "none", TASK_LOGON_NONE },
      { "password", TASK_LOGON_PASSWORD },
      { "s4u", TASK_LOGON_S4U },
      { "interactive_token", TASK_LOGON_INTERACTIVE_TOKEN },
      { "group", TASK_LOGON_GROUP },
      { "service_account", TASK_LOGON_SERVICE_ACCOUNT },
      { "interactive_token_or_password", TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD },
  };

  std::string inputStr(input.ToString());

  auto iter = logonTypeMap.find(inputStr);
  if (iter != logonTypeMap.end()) {
    return iter->second;
  }
  else {
    return TASK_LOGON_NONE;
  }
}

TASK_RUNLEVEL_TYPE convRunLevel(const Napi::Env &env, const Napi::Value &input) {
  static const std::unordered_map<std::string, TASK_RUNLEVEL_TYPE> logonTypeMap{
      { "lua", TASK_RUNLEVEL_LUA },
      { "highest", TASK_RUNLEVEL_HIGHEST },
  };

  std::string inputStr(input.ToString());

  auto iter = logonTypeMap.find(inputStr);
  if (iter != logonTypeMap.end()) {
    return iter->second;
  }
  else {
    return TASK_RUNLEVEL_LUA;
  }
}
#endif
Napi::Object getObject(const Napi::Env &env, const Napi::Object &obj, const char *key) {
  Napi::Value temp = obj.Get(key);
  if (temp.IsNull() || temp.IsUndefined()) {
    return Napi::Object::New(env);
  }
  return temp.ToObject();
}

bool toBool(const Napi::Env &env, const Napi::Value &input) {
  return input.ToBoolean().Value();
}

Napi::Value CreateTaskWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 2) {
      throw Napi::Error::New(info.Env(), "Expected 2 parameters (task name, task settings)");
    }
    #ifdef _WIN32
    clean_ptr<ITaskService> sched(getScheduler(info.Env()),
      [](ITaskService *ptr) { ptr->Release(); });

    if (sched == nullptr) {
      return info.Env().Undefined();
    }

    Napi::Object parameters = info[1].ToObject();

    clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
    if (!clean_ptr_assign(rootFolder, [&](ITaskFolder **out) {
      // TODO: allow tasks in folders
      return sched->GetFolder(_bstr_t("\\"), out);
      }, "ITaskService::GetFolder")) {
      return info.Env().Undefined();
    }

    clean_ptr<ITaskDefinition> task(nullptr, CoRelease<ITaskDefinition>);
    if (!clean_ptr_assign(task, [&](ITaskDefinition **out) {
      return sched->NewTask(0, out);
      }, "ITaskScheduler::NewTask")) {
      return info.Env().Undefined();
    }

    Napi::Object registrationInfoConf = getObject(info.Env(), parameters, "registrationInfo");
    if (!registrationInfoConf.IsEmpty()) {
      clean_ptr<IRegistrationInfo> registrationInfo(nullptr, CoRelease<IRegistrationInfo>);
      if (!clean_ptr_assign(registrationInfo, [&](IRegistrationInfo **out) {
        return task->get_RegistrationInfo(out);
        }, "ITaskDefinition::get_RegistrationInfo")) {
        return info.Env().Undefined();
      }

      ASSIGN(info.Env(), registrationInfo, registrationInfoConf, Author, TOBSTRING);
      ASSIGN(info.Env(), registrationInfo, registrationInfoConf, Date, TOBSTRING);
      ASSIGN(info.Env(), registrationInfo, registrationInfoConf, Description, TOBSTRING);
      ASSIGN(info.Env(), registrationInfo, registrationInfoConf, Documentation, TOBSTRING);
      ASSIGN(info.Env(), registrationInfo, registrationInfoConf, Source, TOBSTRING);
      ASSIGN(info.Env(), registrationInfo, registrationInfoConf, URI, TOBSTRING);
    }


    Napi::Object taskSettingsConf = getObject(info.Env(), parameters, "taskSettings");
    if (!taskSettingsConf.IsEmpty()) {
      clean_ptr<ITaskSettings> taskSettings(nullptr, CoRelease<ITaskSettings>);
      if (!clean_ptr_assign(taskSettings, [&](ITaskSettings **out) {
        return task->get_Settings(out);
        }, "ITaskDefinition::get_Settings")) {
        return info.Env().Undefined();
      }
      ASSIGN(info.Env(), taskSettings, taskSettingsConf, AllowDemandStart, toBool);
    }

    Napi::Object principalConf = getObject(info.Env(), parameters, "principal");
    if (!principalConf.IsEmpty()) {
      clean_ptr<IPrincipal> principal(nullptr, CoRelease<IPrincipal>);
      if (!clean_ptr_assign(principal, [&](IPrincipal **out) {
        return task->get_Principal(out);
        }, "ITaskDefinition::get_Principal")) {
        return info.Env().Undefined();
      }
      ASSIGN(info.Env(), principal, principalConf, DisplayName, TOBSTRING);
      ASSIGN(info.Env(), principal, principalConf, GroupId, TOBSTRING);
      ASSIGN(info.Env(), principal, principalConf, Id, TOBSTRING);
      ASSIGN(info.Env(), principal, principalConf, UserId, TOBSTRING);
      ASSIGN(info.Env(), principal, principalConf, LogonType, convLogonType);
      ASSIGN(info.Env(), principal, principalConf, RunLevel, convRunLevel);
    }

    Napi::Value actionsVal = parameters.Get("actions");
    if (!actionsVal.IsNull() && !actionsVal.IsUndefined()) {
      int idx = 0;
      Napi::Object actions = actionsVal.ToObject();
      while (true) {
        Napi::Value action = actions.Get(idx++);
        if (action.IsNull() || action.IsUndefined()) {
          break;
        }
        if (!addAction(info.Env(), task.get(), action.ToObject())) {
          return info.Env().Undefined();
        }
      }
    }

    // TODO: Add support for triggers

    clean_ptr<IRegisteredTask> registeredTask(nullptr, CoRelease<IRegisteredTask>);
    if (!clean_ptr_assign(registeredTask, [&](IRegisteredTask **out) {
      std::wstring taskName = toWC(info[0]);
      std::wstring userName = toWC(parameters.Get("user"));
      return rootFolder->RegisterTaskDefinition(_bstr_t(taskName.c_str()), task.get(), TASK_CREATE_OR_UPDATE,
        _variant_t(userName.c_str()), _variant_t(), TASK_LOGON_NONE, _variant_t(L""), out);
      }, "ITaskFolder::RegisterTaskDefinition")) {
    }
    #endif
    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value GetTasksWrap(const Napi::CallbackInfo &info) {
  #ifdef _WIN32
  static const int TASKS_TO_RETRIEVE = 5;
  #endif

  try {
    if (info.Length() > 1) {
      throw Napi::Error::New(info.Env(), "Expected zero or one parameters (if set, the specified folder will be listed instead of the rrot)");
    }
    #ifdef _WIN32
    clean_ptr<ITaskService> sched(getScheduler(info.Env()), [](ITaskService *ptr) { ptr->Release(); });
    if (sched == nullptr) {
      return info.Env().Undefined();
    }

    clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
    if (!clean_ptr_assign(rootFolder, [&](ITaskFolder **out) {
      std::wstring folder = info.Length() == 0 ? L"\\" : toWC(info[0]);
      return sched->GetFolder(_bstr_t(folder.c_str()), out);
      }, "ITaskService::GetFolder")) {
      return info.Env().Undefined();
    }

    clean_ptr<IRegisteredTaskCollection> tasks(nullptr, CoRelease<IRegisteredTaskCollection>);
    if (!clean_ptr_assign(tasks, [&](IRegisteredTaskCollection **out) {
      return rootFolder->GetTasks(0, out);
      }, "ITaskFolder->GetTasks")) {
      return info.Env().Undefined();
    }

    LONG count;
    tasks->get_Count(&count);

    Napi::Array result = Napi::Array::New(info.Env());
    int32_t resultIdx = 0;

    for (LONG i = 0; i < count; ++i) {
      DWORD numFetched = 0;
      clean_ptr<IRegisteredTask> task(nullptr, CoRelease<IRegisteredTask>);
      if (clean_ptr_assign(task, [&](IRegisteredTask **out) {
        // 1-based indices? WTF is this madness
        return tasks->get_Item(_variant_t(i + 1, VT_I4), out);
        }, "IRegisteredTaskCollection::get_Item", false)) {
        Napi::Object item = Napi::Object::New(info.Env());
        COMTOV8(info.Env(), task, item, Name, CComBSTR);
        COMTOV8(info.Env(), task, item, Enabled, VARIANT_BOOL);
        COMTOV8(info.Env(), task, item, LastTaskResult, LONG);

        result.Set(resultIdx++, item);
      }
    }
    return result;
    #else
    return info.Env().Undefined();
    #endif
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value DeleteTaskWrap(const Napi::CallbackInfo &info) {
  #ifdef _WIN32
  static const int TASKS_TO_RETRIEVE = 5;
  #endif

  try {

    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (the task name)");
    }
    #ifdef _WIN32
    clean_ptr<ITaskService> sched(getScheduler(info.Env()), [](ITaskService *ptr) { ptr->Release(); });

    if (sched == nullptr) {
      return info.Env().Undefined();
    }

    clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
    if (!clean_ptr_assign(rootFolder, [&](ITaskFolder **out) {
      // TODO: allow tasks in folders
      return sched->GetFolder(_bstr_t("\\"), out);
      }, "ITaskService::GetFolder")) {
      return info.Env().Undefined();
    }

    std::wstring taskName = toWC(info[0]);
    HRESULT res = rootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);

    if (FAILED(res)) {
      return ThrowHResultException(info.Env(), res, "ITaskFolder::Delete");
    }
    #endif
    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

#ifdef _WIN32
void withTask(const Napi::Env &env, const std::wstring &taskName, std::function<void(IRegisteredTask *)> cb) {
  clean_ptr<ITaskService> sched(getScheduler(env), [](ITaskService *ptr) { ptr->Release(); });
  if (sched == nullptr) {
    return;
  }

  clean_ptr<ITaskFolder> rootFolder(nullptr, CoRelease<ITaskFolder>);
  if (!clean_ptr_assign(rootFolder, [&](ITaskFolder **out) {
    // TODO: allow tasks in folders
    return sched->GetFolder(_bstr_t("\\"), out);
    }, "ITaskService::GetFolder")) {
    return;
  }

  clean_ptr<IRegisteredTask> task(nullptr, CoRelease<IRegisteredTask>);
  if (!clean_ptr_assign(task, [&](IRegisteredTask **out) {
    return rootFolder->GetTask(_bstr_t(taskName.c_str()), out);
    }, "ITaskFolder::GetTask")) {
  }

  cb(task.get());
}
#endif

Napi::Value RunTaskWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (the task name)");
    }

    #ifdef _WIN32
    Napi::Env env = info.Env();
    std::wstring taskName = toWC(info[0]);
    withTask(env, taskName, [env](IRegisteredTask *task) {
      clean_ptr<IRunningTask> running(nullptr, CoRelease<IRunningTask>);
      if (!clean_ptr_assign(running, [&](IRunningTask **out) {
        return task->Run(CComVariant(), out);
        }, "IRegisteredTask::Run")) {
      }
    });
    #endif

    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

Napi::Value StopTaskWrap(const Napi::CallbackInfo &info) {
  try {
    if (info.Length() != 1) {
      throw Napi::Error::New(info.Env(), "Expected 1 parameter (the task name)");
    }

    #ifdef _WIN32
    Napi::Env env = info.Env();
    std::wstring taskName = toWC(info[0]);
    withTask(env, taskName, [env](IRegisteredTask *task) {
      clean_ptr<IRunningTask> running(nullptr, CoRelease<IRunningTask>);
      if (!clean_ptr_assign(running, [&](IRunningTask **out) {
        return task->Stop(0);
        }, "IRegisteredTask::Stop")) {
        return;
      }
    });
    #endif
    return info.Env().Undefined();
  }
  catch (const std::exception &e) {
    return Rethrow(info.Env(), e);
  }
}

namespace Tasks {
  void Init(Napi::Env env, Napi::Object exports) {
    exports.Set("CreateTask", Napi::Function::New(env, CreateTaskWrap));
    exports.Set("GetTasks", Napi::Function::New(env, GetTasksWrap));
    exports.Set("DeleteTask", Napi::Function::New(env, DeleteTaskWrap));
    exports.Set("RunTask", Napi::Function::New(env, RunTaskWrap));
    exports.Set("StopTask", Napi::Function::New(env, StopTaskWrap));
  }
}
