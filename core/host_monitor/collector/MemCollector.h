/*
 * Copyright 2025 iLogtail Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <vector>

#include "host_monitor/collector/BaseCollector.h"
#include "host_monitor/collector/MetricCalculate.h"

namespace logtail {

// memory information in byte
struct MemoryInformation {
    uint64_t ram = 0;
    uint64_t total = 0;
    uint64_t used = 0;
    uint64_t free = 0;
    uint64_t actualUsed = 0;
    uint64_t actualFree = 0;
    double usedPercent = 0.0;
    double freePercent = 0.0;
};

struct SwapInformation {
    uint64_t total = 0;
    uint64_t used = 0;
    uint64_t free = 0;
    uint64_t pageIn = 0;
    uint64_t pageOut = 0;
};

class MemCollector : public BaseCollector {
public:
    MemCollector();

    int Init(int totalCount = 3);
    ~MemCollector() override = default;

    bool Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) override;

    static const std::string sName;
    const std::string& Name() const override { return sName; }

private:
    bool GetHostMeminfoStat(MemoryInformation& memStat, SwapInformation& swapStat);
    bool GetMemoryStat(MemoryInformation& information, std::vector<std::string>& memoryLines);
    uint64_t GetMemoryValue(char unit, uint64_t value);
    void completeMemoryInformation(MemoryInformation &memInfo,
                                  uint64_t buffers,
                                  uint64_t cached,
                                  uint64_t available);
    uint64_t parseProcMtrr(const std::vector<std::string> &lines);
    bool GetMemoryRam(uint64_t &ram);

private:
    int mTotalCount = 0;
    int mCount = 0;
    MetricCalculate<MemoryInformation> mCalculateMeminfo;
    MetricCalculate<SwapInformation> mCalculateSwap;
};

} // namespace logtail
