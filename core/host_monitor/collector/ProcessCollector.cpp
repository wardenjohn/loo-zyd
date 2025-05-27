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

#include "host_monitor/collector/ProcessCollector.h"

#include <filesystem>
#include <string>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
#include "host_monitor/Constants.h"
#include "host_monitor/SystemInformationTools.h"
#include "logger/Logger.h"

#define Diff(a, b)  a-b>0 ? a-b : 0;

namespace logtail {

const std::string ProcessCollector::sName = "process";
const std::string kMetricLabelProcess = "valueTag";
const std::string kMetricLabelMode = "mode";


ProcessCollector::ProcessCollector(){
    Init();
}

int ProcessCollector::Init(int totalCount) {
    mTotalCount = totalCount;
    mCount = 0;
    return 0;
}

bool ProcessCollector::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
    if (group == nullptr) {
        return false;
    }
    std::cout << "inside process collector" << std::endl;

    return true;
}

} // namespace logtail
