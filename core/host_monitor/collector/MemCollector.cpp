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

#include <string>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
#include "host_monitor/Constants.h"
#include "host_monitor/SystemInformationTools.h"
#include "host_monitor/collector/MemCollector.h"
#include "logger/Logger.h"

namespace logtail {

const std::string MemCollector::sName = "mem";
const std::string kMetricLabelMem = "mem";
const std::string kMetricLabelMode = "mode";

bool MemCollector::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
    if (group == nullptr) {
        return false;
    }
    std::string errorMessage;
    std::vector<std::string> meminfo_lines;
    if (!GetHostMeminfo(meminfo_lines, errorMessage)) {
        if (mValidState) {
            LOG_WARNING(sLogger, ("failed to get system cpu", "invalid CPU collector")("error msg", errorMessage));
            mValidState = false;
        }
        return false;
    }
    mValidState = true;

    return true;
}

bool MemCollector::GetHostMeminfo(std::vector<std::string>& lines, std::string& errorMessage) { 
    if (!GetHostMeminfoStat(lines, errorMessage)) {
        if (mValidState) {
            LOG_WARNING(sLogger, ("failed to get system cpu", "invalid CPU collector")("error msg", errorMessage));
            mValidState = false;
        }
        return false;
    }
    return true;
}

}