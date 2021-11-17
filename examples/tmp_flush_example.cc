// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include <cstdio>
#include <string>
#include <iostream>
#include <random>
#include <algorithm>

#include "rocksdb/db.h"
#include "rocksdb/slice.h"
#include "rocksdb/options.h"
#include "rocksdb/system_clock.h"

using namespace ROCKSDB_NAMESPACE;

#if defined(OS_WIN)
std::string kDBPath = "C:\\Windows\\TEMP\\rocksdb_flush_example";
#else
std::string kDBPath = "/tmp/rocksdb_flush_example";
#endif
bool IsLittleEndian() {
  int n = 1;
  return *(char *)&n ==1;
}

Slice StripTimestampFromUserKey(const Slice& user_key, size_t ts_sz) {
  assert(user_key.size() >= ts_sz);
  return Slice(user_key.data(), user_key.size() - ts_sz);
}

Slice ExtractTimestampFromUserKey(const Slice& user_key, size_t ts_sz) {
  assert(user_key.size() >= ts_sz);
  return Slice(user_key.data() + user_key.size() - ts_sz, ts_sz);
}

uint32_t DecodeFixed32(const char* ptr) {
  if (IsLittleEndian()) {
    // Load the raw bytes
    uint32_t result;
    memcpy(&result, ptr, sizeof(result));  // gcc optimizes this to a plain load
    return result;
  } else {
    return ((static_cast<uint32_t>(static_cast<unsigned char>(ptr[0]))) |
            (static_cast<uint32_t>(static_cast<unsigned char>(ptr[1])) << 8) |
            (static_cast<uint32_t>(static_cast<unsigned char>(ptr[2])) << 16) |
            (static_cast<uint32_t>(static_cast<unsigned char>(ptr[3])) << 24));
  }
}

uint64_t DecodeFixed64(const char* ptr) {
  if (IsLittleEndian()) {
    // Load the raw bytes
    uint64_t result;
    memcpy(&result, ptr, sizeof(result));  // gcc optimizes this to a plain load
    return result;
  } else {
    uint64_t lo = DecodeFixed32(ptr);
    uint64_t hi = DecodeFixed32(ptr + 4);
    return (hi << 32) | lo;
  }
}

void EncodeFixed64(char* buf, uint64_t value) {
  if (IsLittleEndian()) {
    memcpy(buf, &value, sizeof(value));
  } else {
    buf[0] = value & 0xff;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 24) & 0xff;
    buf[4] = (value >> 32) & 0xff;
    buf[5] = (value >> 40) & 0xff;
    buf[6] = (value >> 48) & 0xff;
    buf[7] = (value >> 56) & 0xff;
  }
}

std::string RandomStr(int size)
{
     std::string str("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
     std::random_device rd;
     std::mt19937 generator(rd());
     std::shuffle(str.begin(), str.end(), generator);
     return str.substr(0, size); 
}

class ComparatorForU64Ts : public Comparator {
 public:
  ComparatorForU64Ts(bool enable)
      : Comparator(/*ts_sz=*/sizeof(uint64_t)),
        enable_(enable) {}
  const char* Name() const override { return "ComparatorForU64Ts"; }
  void FindShortSuccessor(std::string*) const override {}
  void FindShortestSeparator(std::string*, const Slice&) const override {}
  int Compare(const Slice& a, const Slice& b) const override {
    int ret = CompareWithoutTimestamp(a, b);
    size_t ts_sz = timestamp_size();
    if (ret != 0) {
      return ret;
    }
    // Compare timestamp.
    // For the same user key with different timestamps, larger (newer) timestamp
    // comes first.
    return -CompareTimestamp(ExtractTimestampFromUserKey(a, ts_sz),
                             ExtractTimestampFromUserKey(b, ts_sz));
  }
  using Comparator::CompareWithoutTimestamp;
  int CompareWithoutTimestamp(const Slice& a, bool a_has_ts, const Slice& b,
                              bool b_has_ts) const override {
    const size_t ts_sz = timestamp_size();
    assert(!a_has_ts || a.size() >= ts_sz);
    assert(!b_has_ts || b.size() >= ts_sz);
    Slice lhs = a_has_ts ? StripTimestampFromUserKey(a, ts_sz) : a;
    Slice rhs = b_has_ts ? StripTimestampFromUserKey(b, ts_sz) : b;
    return lhs.compare(rhs);
  }
  int CompareTimestamp(const Slice& ts1, const Slice& ts2) const override {
    assert(ts1.size() == sizeof(uint64_t));
    assert(ts2.size() == sizeof(uint64_t));
    uint64_t lhs = DecodeFixed64(ts1.data());
    uint64_t rhs = DecodeFixed64(ts2.data());
    if (lhs < rhs) {
      return -1;
    } else if (lhs > rhs) {
      return 1;
    } else {
      return 0;
    }
  }
  bool Enabled() const override {
    return enable_;
  }
 private:
  const bool enable_;
};


int main() {
  DB* db = nullptr;
  Options options;
  options.create_if_missing = true;
  options.disable_auto_compactions = true;
  options.level0_stop_writes_trigger = 1 << 10;
  options.level0_slowdown_writes_trigger = 1 << 10;
  options.max_background_flushes = 1;
  std::unique_ptr<Env> env{NewMemEnv(Env::Default())};
  options.env = env.get();
  int sample_count = 10;
  int flush_file_num = 100;
  std::vector<int> test_value_size = {10, 100, 1000};
  std::vector<bool> need_collect_ts_v = {true, false};
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;
  for (auto need_c : need_collect_ts_v) {
    options.comparator = dynamic_cast<Comparator*>(new ComparatorForU64Ts(need_c));
    for (auto v_size : test_value_size) {
      uint64_t total_time = 0;
      for (int i = 0; i < sample_count; i++) {
        delete db;
	db = nullptr;
	Status s = DestroyDB(kDBPath, options);
	assert(s.ok());
	s = DB::Open(options, kDBPath, &db);
	assert(s.ok());
        int current_size = 0;
        WriteOptions write_opts;
        char buf[sizeof(uint64_t)];
        int expect_mem_size = 32 * 1024 * 1024;
        while (current_size < expect_mem_size) {
          EncodeFixed64(buf, dis(gen));
          Slice ts(buf, sizeof(uint64_t));
          write_opts.timestamp = &ts;
          s = db->Put(write_opts, RandomStr(10),
                             RandomStr(v_size));
	  assert(s.ok());
          current_size = current_size + 10 /* test_key_size*/ +
                         8 /* lsn size */ + 8 /* ts size */ + v_size;
        }
        auto clock = SystemClock::Default();
	auto start = clock->NowMicros();
        s = db->Flush(FlushOptions());
	assert(s.ok());
        total_time += (clock->NowMicros() - start);
      }

      std::cout << "\nCurrent ts collect enabled: "
                << (need_c ? "TRUE" : "FALSE")
                << "\nInternal Key size: " << 10 + 8 + 8 + v_size
                << "\nsample iteration: " << sample_count
                << "\nTotally cost time micro secs: " << total_time << "\n";
    }
  }
  delete db;
  db = nullptr;
  DestroyDB(kDBPath, options);
  return 0;
}
