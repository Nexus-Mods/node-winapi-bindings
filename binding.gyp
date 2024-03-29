{
    "targets": [
        {
            "target_name": "winapi",
            "includes": [
                "auto.gypi"
            ],
            "conditions": [
                ['OS=="win"', {
                    "sources": [
                        "src/scopeguard.hpp",
                        "src/UnicodeString.h",
                        "src/UnicodeString.cpp",
                        "src/string_cast.h",
                        "src/string_cast.cpp",
                        "src/util.cpp",
                        "src/util.h",
                        "src/registry.cpp",
                        "src/registry.h",
                        "src/processes.cpp",
                        "src/processes.h",
                        "src/fs.cpp",
                        "src/fs.h",
                        "src/ini.cpp",
                        "src/ini.h",
                        "src/shell.cpp",
                        "src/shell.h",
                        "src/system.cpp",
                        "src/system.h",
                        "src/tasks.cpp",
                        "src/tasks.h",
                        "src/walk.cpp",
                        "src/walk.h",
                        "src/permissions.cpp",
                        "src/permissions.h",
                        "src/convenience.cpp",
                        "src/convenience.h",
                        "src/winapi.cpp"
                    ],
                    "libraries": [
                      "-DelayLoad:node.exe"
                    ]
                }]
            ],
            "include_dirs": [
              "<!(node -p \"require('node-addon-api').include_dir\")"
            ],
            "dependencies": [
              "<!(node -p \"require('node-addon-api').gyp\")"
            ],
            "cflags!": ["-fno-exceptions"],
            "cflags_cc!": ["-fno-exceptions"],
            "defines": [
                "UNICODE",
                "_UNICODE",
                "NAPI_EXPERIMENTAL",
                "NAPI_VERSION=<(napi_build_version)"
            ],
            "msvs_settings": {
                "VCCLCompilerTool": {
                    "ExceptionHandling": 1,
                    "RuntimeLibrary": 0
                }
            },
            "msbuild_settings": {
              "ClCompile": {
                "AdditionalOptions": ["-std:c++17", "/MT"],
                "RuntimeLibrary": "MultiThreaded"
              }
            }
        }
    ],
    "includes": [
        "auto-top.gypi"
    ]
}
