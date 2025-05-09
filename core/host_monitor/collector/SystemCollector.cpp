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

#include "host_monitor/collector/SystemCollector.h"

#include <filesystem>
#include <string>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
// #include "host_monitor/Constants.h"
#include "host_monitor/SystemInformationTools.h"
#include "logger/Logger.h"

namespace logtail {

const std::string SystemCollector::sName = "system";
const std::string kMetricLabelLoad = "system";
const std::string kMetricLabelMode = "mode";

const FieldName<SystemStat> systemLoadMeta[] = {
    FIELD_ENTRY(SystemStat, load1),
    FIELD_ENTRY(SystemStat, load5),
    FIELD_ENTRY(SystemStat, load15),
    FIELD_ENTRY(SystemStat, load1_per_core),
    FIELD_ENTRY(SystemStat, load5_per_core),
    FIELD_ENTRY(SystemStat, load15_per_core),
};
const size_t systemLoadMetaSize = sizeof(systemLoadMeta) / sizeof(systemLoadMeta[0]);
const FieldName<SystemStat>* const systemLoadMetaEnd = systemLoadMeta + systemLoadMetaSize;
static_assert(systemLoadMetaSize == sizeof(SystemStat) / sizeof(double), "systemLoadMeta unexpected");
void enumerate(const std::function<void(const FieldName<SystemStat>&)>& callback) {
    for (auto it = systemLoadMeta; it < systemLoadMetaEnd; ++it) {
        callback(*it);
    }
}

SystemCollector::SystemCollector(){
    Init();
}
int SystemCollector::Init(int totalCount) {
    mTotalCount = totalCount;
    mCount = 0;
    return 0;
}
bool SystemCollector::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
    if (group == nullptr) {
        return false;
    }
    SystemStat load;
    if (!GetHostSystemLoadStat(load)) {
        return false;
    }

    mCalculate.AddValue(load);

    mCount++;
    if (mCount < mTotalCount) {
        return true;
    }

    SystemStat minSys, maxSys, avgSys, lastSys;
    mCalculate.Stat(maxSys, minSys, avgSys, &lastSys);
    
    mCount=0;
    mCalculate.Reset();

    const time_t now = time(nullptr);

    //数据整理
    struct MetricDef {
        const char* name;
        const char* mode;
        double *value;
    } metrics[] = {
        {"node_system_load_1m", "min", &minSys.load1},
        {"node_system_load_1m", "max", &maxSys.load1},
        {"node_system_load_1m", "avg", &avgSys.load1},
        {"node_system_load_5m", "min", &minSys.load5},
        {"node_system_load_5m", "max", &maxSys.load5},
        {"node_system_load_5m", "avg", &avgSys.load5},
        {"node_system_load_15m", "min", &minSys.load15},
        {"node_system_load_15m", "max", &maxSys.load15},
        {"node_system_load_15m", "avg", &avgSys.load15},
        {"node_system_load_1m_per_core", "min", &minSys.load1_per_core},
        {"node_system_load_1m_per_core", "max", &maxSys.load1_per_core},
        {"node_system_load_1m_per_core", "avg", &avgSys.load1_per_core},
        {"node_system_load_5m_per_core", "min", &minSys.load5_per_core},
        {"node_system_load_5m_per_core", "max", &maxSys.load5_per_core},
        {"node_system_load_5m_per_core", "avg", &avgSys.load5_per_core},
        {"node_system_load_15m_per_core", "min", &minSys.load15_per_core},
        {"node_system_load_15m_per_core", "max", &maxSys.load15_per_core},
        {"node_system_load_15m_per_core", "avg", &avgSys.load15_per_core},
    };

    for (const auto& def : metrics) {
        auto* metricEvent = group->AddMetricEvent(true);
        if (!metricEvent) {
            continue;
        }
        metricEvent->SetName(def.name);
        metricEvent->SetTimestamp(now, 0);
        metricEvent->SetValue<UntypedSingleValue>(*def.value);
        metricEvent->SetTag(kMetricLabelMode, def.mode);
    }
    
    return true;
}

bool SystemCollector::GetHostSystemLoadStat(SystemStat& systemload) {
    std::vector<std::string> loadLines;
    std::string errorMessage;
    if (!GetHostSystemStatWithPath(loadLines, errorMessage, "/proc/loadavg")) {
        if (mValidState) {
            LOG_WARNING(sLogger, ("failed to get system load", "invalid System collector")("error msg", errorMessage));
            mValidState = false;
        }
        return false;
    }

    mValidState = true;
    // cat /proc/loadavg
    // 0.10 0.07 0.03 1/561 78450
    std::vector<std::string> loadMetric;
    boost::split(loadMetric, loadLines[0], boost::is_any_of(" "), boost::token_compress_on);

    systemload.load1 = std::atof(loadMetric[0].c_str());
    systemload.load5 = std::atof(loadMetric[1].c_str());
    systemload.load15 = std::atof(loadMetric[2].c_str());

    auto cpuCoreCount = static_cast<double>(std::thread::hardware_concurrency());
    cpuCoreCount = cpuCoreCount < 1 ? 1 : cpuCoreCount;

    systemload.load1_per_core = systemload.load1 / cpuCoreCount;
    systemload.load5_per_core = systemload.load5 / cpuCoreCount;
    systemload.load15_per_core = systemload.load15 / cpuCoreCount;

    return true;
}

} // namespace logtail
