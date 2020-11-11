#pragma once

#include <string>
#include <vector>
#include <functional>
#include <optional>

static uint32_t FILE_ATTRIBUTE_TERMINATOR = 0x80000000;

struct Entry {
  std::wstring filePath;
  uint32_t attributes;
  uint64_t size;
  uint32_t mtime;
  std::optional<uint32_t> linkCount;
  std::optional<uint64_t> id;
  std::optional<std::string> idStr;
};

struct WalkOptions {
  std::optional<uint32_t> threshold;
  std::optional<bool> terminators;
  std::optional<bool> details;
  std::optional<bool> recurse;
  std::optional<bool> skipHidden;
  std::optional<bool> skipLinks;
  std::optional<bool> skipInaccessible;
};

void walk(const std::wstring &basePath,
          std::function<bool(const std::vector<Entry> &results)> cb,
          const WalkOptions &options);
