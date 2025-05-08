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
#include "host_monitor/collector/CPUCollector.h"

#include <string>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
#include "host_monitor/Constants.h"
#include "host_monitor/SystemInformationTools.h"
#include "logger/Logger.h"

#include <limits>
#include <iostream>
#include <random>

namespace logtail {

const std::string MemCollector::sName = "mem";
const std::string kMetricLabelMem = "mem";
const std::string kMetricLabelMode = "mode";

#include <execinfo.h>  // 调用栈相关头文件
#include <unistd.h>

bool MemCollector::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
    std::cout << "inside mem collector" << std::endl;
    if (group == nullptr) {
        return false;
    }
    const time_t now = time(nullptr);

    int random_number=1;

    struct MetricDef {
        const char* name;
        const char* mode;
        int value;
    } metrics[] = {
        {"xixihaha_mem_A", "TOTAL", random_number},
        {"xixihaha_mem_B", "Free", random_number+1},
        {"xixihaha_mem_C", "Swap", random_number+5},
    };

    for (const auto& def : metrics) {
            auto* metricEvent = group->AddMetricEvent(true);
            if (!metricEvent) {
                continue;
            }
            metricEvent->SetName(def.name);
            metricEvent->SetTimestamp(now, 0);
            metricEvent->SetValue<UntypedSingleValue>(def.value);
            metricEvent->SetTag(kMetricLabelMem, "aaaaainstanceid");
            metricEvent->SetTagNoCopy(kMetricLabelMode, def.mode);
    }
    return true;
}

}