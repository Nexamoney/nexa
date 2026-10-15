// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "leveldb/env.h"

#include "port/port.h"
#include "util/testharness.h"

#include <algorithm>

#if defined(LEVELDB_PLATFORM_WINDOWS)
#include <windows.h>
#undef DeleteFile
#endif

namespace leveldb {

static const int kDelayMicros = 100000;
static const int kReadOnlyFileLimit = 4;
static const int kMMapLimit = 4;

class EnvTest {
 private:
  port::Mutex mu_;
  std::string events_;

 public:
  Env* env_;
  EnvTest() : env_(Env::Default()) { }
};

static void SetBool(void* ptr) {
  reinterpret_cast<port::AtomicPointer*>(ptr)->NoBarrier_Store(ptr);
}

TEST(EnvTest, Utf8Paths) {
  std::string root;
  ASSERT_OK(env_->GetTestDirectory(&root));
  std::string dir = root + "/utf8-\xed\x95\x9c\xea\xb8\x80";
  std::string name = "file-\xed\x95\x9c\xea\xb8\x80";
#if defined(LEVELDB_PLATFORM_WINDOWS)
  // Windows counts native characters, not UTF-8 bytes, toward its path limit.
  for (int i = 0; i < 30; ++i) dir += "\xed\x95\x9c";
  for (int i = 0; i < 60; ++i) name += "\xed\x95\x9c";
#endif
  const std::string file = dir + "/" + name;
  const std::string renamed = dir + "/renamed-\xea\xb8\x80";
  if (!env_->FileExists(root)) ASSERT_OK(env_->CreateDir(root));
  ASSERT_OK(env_->CreateDir(dir));
#if defined(LEVELDB_PLATFORM_WINDOWS)
  // A round trip through the same wrong encoding could hide a renamed path.
  std::wstring nativeDir(dir.size() + 1, L'\0');
  ASSERT_TRUE(MultiByteToWideChar(CP_UTF8, 0, dir.c_str(), -1,
                                &nativeDir[0], nativeDir.size()) > 0);
  ASSERT_TRUE(GetFileAttributesW(nativeDir.c_str()) != INVALID_FILE_ATTRIBUTES);
#endif
  WritableFile* output;
  ASSERT_OK(env_->NewWritableFile(file, &output));
  ASSERT_OK(output->Append("unicode path"));
  ASSERT_OK(output->Close());
  delete output;
  ASSERT_TRUE(env_->FileExists(file));
  uint64_t size;
  ASSERT_OK(env_->GetFileSize(file, &size));
  ASSERT_EQ(12, size);
  std::vector<std::string> children;
  ASSERT_OK(env_->GetChildren(dir, &children));
  ASSERT_TRUE(std::find(children.begin(), children.end(), name) != children.end());
  SequentialFile* input;
  ASSERT_OK(env_->NewSequentialFile(file, &input));
  char buffer[32];
  Slice contents;
  ASSERT_OK(input->Read(sizeof(buffer), &contents, buffer));
  ASSERT_EQ("unicode path", contents.ToString());
  delete input;
  ASSERT_OK(env_->RenameFile(file, renamed));
  ASSERT_TRUE(env_->FileExists(renamed));
  ASSERT_OK(env_->DeleteFile(renamed));
  ASSERT_OK(env_->DeleteDir(dir));
}

TEST(EnvTest, RunImmediately) {
  port::AtomicPointer called (NULL);
  env_->Schedule(&SetBool, &called);
  env_->SleepForMicroseconds(kDelayMicros);
  ASSERT_TRUE(called.NoBarrier_Load() != NULL);
}

TEST(EnvTest, RunMany) {
  port::AtomicPointer last_id (NULL);

  struct CB {
    port::AtomicPointer* last_id_ptr;   // Pointer to shared slot
    uintptr_t id;             // Order# for the execution of this callback

    CB(port::AtomicPointer* p, int i) : last_id_ptr(p), id(i) { }

    static void Run(void* v) {
      CB* cb = reinterpret_cast<CB*>(v);
      void* cur = cb->last_id_ptr->NoBarrier_Load();
      ASSERT_EQ(cb->id-1, reinterpret_cast<uintptr_t>(cur));
      cb->last_id_ptr->Release_Store(reinterpret_cast<void*>(cb->id));
    }
  };

  // Schedule in different order than start time
  CB cb1(&last_id, 1);
  CB cb2(&last_id, 2);
  CB cb3(&last_id, 3);
  CB cb4(&last_id, 4);
  env_->Schedule(&CB::Run, &cb1);
  env_->Schedule(&CB::Run, &cb2);
  env_->Schedule(&CB::Run, &cb3);
  env_->Schedule(&CB::Run, &cb4);

  env_->SleepForMicroseconds(kDelayMicros);
  void* cur = last_id.Acquire_Load();
  ASSERT_EQ(4, reinterpret_cast<uintptr_t>(cur));
}

struct State {
  port::Mutex mu;
  int val;
  int num_running;
};

static void ThreadBody(void* arg) {
  State* s = reinterpret_cast<State*>(arg);
  s->mu.Lock();
  s->val += 1;
  s->num_running -= 1;
  s->mu.Unlock();
}

TEST(EnvTest, StartThread) {
  State state;
  state.val = 0;
  state.num_running = 3;
  for (int i = 0; i < 3; i++) {
    env_->StartThread(&ThreadBody, &state);
  }
  while (true) {
    state.mu.Lock();
    int num = state.num_running;
    state.mu.Unlock();
    if (num == 0) {
      break;
    }
    env_->SleepForMicroseconds(kDelayMicros);
  }
  ASSERT_EQ(state.val, 3);
}

}  // namespace leveldb

int main(int argc, char** argv) {
  return leveldb::test::RunAllTests();
}
