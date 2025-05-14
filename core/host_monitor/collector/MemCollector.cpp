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

#include "host_monitor/collector/MemCollector.h"

#include <filesystem>
#include <string>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
// #include "host_monitor/Constants.h"
#include "host_monitor/SystemInformationTools.h"
#include "logger/Logger.h"

#define Diff(a, b)  a-b>0 ? a-b : 0;

namespace logtail {

const std::string MemCollector::sName = "mem";
const std::string kMetricLabelLoad = "mem";
const std::string kMetricLabelMode = "mode";

MemCollector::MemCollector(){
    Init();
}

int MemCollector::Init(int totalCount) {
    mTotalCount = totalCount;
    mCount = 0;
    return 0;
}

bool MemCollector::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
    if (group == nullptr) {
        return false;
    }
    std::cout << "MemCollector" << std::endl;
    MemoryInformation memStat;
    SwapInformation swapStat;
    if (!GetHostMeminfoStat(memStat, swapStat)) {
        return false;
    }
    
    const time_t now = time(nullptr);
    constexpr struct MetricDef {
        const char* name;
        const char* mode;
        double memStat::*value;
    } metrics[] = {
        {"node_mem_total", "user", &CPUStat::user},
    };
    for (const auto& cpu : cpus) {
        if (cpu.index == -1) {
            continue;
        }
        for (const auto& def : metrics) {
            auto* metricEvent = group->AddMetricEvent(true);
            if (!metricEvent) {
                continue;
            }
            metricEvent->SetName(def.name);
            metricEvent->SetTimestamp(now, 0);
            metricEvent->SetValue<UntypedSingleValue>(cpu.*(def.value) / SYSTEM_HERTZ);
            metricEvent->SetTag(kMetricLabelCPU, std::to_string(cpu.index));
            metricEvent->SetTagNoCopy(kMetricLabelMode, def.mode);
        }
    }

    return true;
}

bool MemCollector::GetHostMeminfoStat(MemoryInformation& memStat, SwapInformation& swapStat) {
    std::vector<std::string> loadLines;
    std::string errorMessage;

    if (!GetHostSystemStatWithPath(loadLines, errorMessage, "/proc/meminfo")) {
        if (mValidState) {
            LOG_WARNING(sLogger, ("failed to get system load", "invalid System collector")("error msg", errorMessage));
            mValidState = false;
        }
        return false;
    }

    mValidState = true;

    if (!GetMemoryStat(memStat, loadLines)) {
        return false;
    }

    std::cout << memStat.ram << std::endl;
    std::cout << memStat.total << std::endl;
    std::cout << memStat.used << std::endl;

    return true;
}

/*
样例: /proc/meminfo:
MemTotal:        4026104 kB
MemFree:         2246280 kB
MemAvailable:    3081592 kB // 低版本Linux内核上可能没有该行
Buffers:          124380 kB
Cached:          1216756 kB
SwapCached:            0 kB
Active:           417452 kB
Inactive:        1131312 kB
 */
bool MemCollector::GetMemoryStat(MemoryInformation& information, std::vector<std::string>& memoryLines) {
    int ret = false;

    if (memoryLines.empty()) {
        return ret;
    }

    uint64_t available=0, buffers = 0, cached = 0;

    std::unordered_map<std::string, uint64_t &> memoryProc{
            {"MemTotal:",     information.total},
            {"MemFree:",      information.free},
            {"MemAvailable:", information.available},
            {"Buffers:",      information.buffers},
            {"Cached:",       information.cached},
    };
    /* 字符串处理，处理成对应的类型以及值*/
    for (size_t i = 0; i < memoryLines.size() && !memoryProc.empty(); i++) {
        std::vector<std::string> words = split(memoryLines[i], ' ', true);
        // words-> MemTotal: / 12344 / kB

        auto entry = memoryProc.find(words[0]);
        if (entry != memoryProc.end()) {
            entry->second = GetMemoryValue(words.back()[0], std::stoi(words[1]));
            memoryProc.erase(entry);
        }
    }
    information.used = Diff(information.total, information.free);
    completeMemoryInformation(information, buffers, cached, available);

    return true;
}

uint64_t MemCollector::GetMemoryValue(char unit, uint64_t value) {
    if (unit == 'k' || unit == 'K') {
        value *= 1024;
    } else if (unit == 'm' || unit == 'M') {
        value *= 1024 * 1024;
    }
    return value;
}

void MemCollector::completeMemoryInformation(MemoryInformation &memInfo,
                                  uint64_t buffers,
                                  uint64_t cached,
                                  uint64_t available) {
    const uint64_t mb = 1024 * 1024;
    // 不需要考虑MemAvailable不存在的情况
    memInfo.actualUsed = Diff(memInfo.total, available);
    memInfo.actualFree = available;
    memInfo.usedPercent =
            memInfo.total > 0 ? static_cast<double>(memInfo.actualUsed) * 100 / memInfo.total : 0.0;
    memInfo.freePercent =
            memInfo.total > 0 ? static_cast<double>(memInfo.actualFree) * 100 / memInfo.total : 0.0;
    memInfo.ram = memInfo.total / mb;

    uint64_t diff = Diff(memInfo.total, memInfo.actualFree);
    memInfo.usedPercent = memInfo.total > 0 ? static_cast<double>(diff) * 100 / memInfo.total : 0.0;
    diff = Diff(memInfo.total, memInfo.actualUsed);
    memInfo.freePercent = memInfo.total > 0 ? static_cast<double>(diff) * 100 / memInfo.total : 0.0;
}


} // namespace logtail
