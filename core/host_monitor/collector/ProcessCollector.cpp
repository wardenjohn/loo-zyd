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
    return EXECUTE_SUCCESS;
}

bool ProcessCollector::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
    if (group == nullptr) {
        return false;
    }
    if (!GetPids(pids)) {
        return false;
    }

    const time_t now = time(nullptr);

    struct MetricDef {
        const char* name;
        const char* mode;
        double value;
    } metrics[] = {
        {"process.number", "Average", 1.1},
        {"process.number", "Maximum", 1.1},
        {"process.number", "Minimum", 1.1},
        {"vm.ProcessCount", "Average", 1.2},
        {"vm.ProcessCount", "Maximum", 1.1},
        {"vm.ProcessCount", "Minimum", 1.1},
        {"process.openfile", "Average", 1.31},
        {"process.openfile", "Maximum", 1.351},
        {"process.openfile", "Minimum", 1.16},
        {"process.cpu", "Average", 1.71},
        {"process.cpu", "Maximum", 1.81},
        {"process.cpu", "Minimum", 1.19},
        {"process.memory", "Average", 1.10},
        {"process.memory", "Maximum", 1.14},
        {"process.memory", "Minimum", 1.7},
        {"process.expend", "Average", 1.18},
        {"process.expend", "Maximum", 1.91},
        {"process.expend", "Minimum", 1.13},
    };

    std::cout << "inside process collector : " << pids.size()  << std::endl;
    // 排除自身干扰
    GetSelfPid(mSelfPid, mParentPid);
    RemovePid(pids, mSelfPid, mParentPid);

    // for (const auto& def : metrics) {
    //     auto* metricEvent = group->AddMetricEvent(true);
    //     if (!metricEvent) {
    //         continue;
    //     }
    //     metricEvent->SetName(def.name);
    //     metricEvent->SetTimestamp(now, 0);
    //     metricEvent->SetValue<UntypedSingleValue>(def.value);
    //     metricEvent->SetTag(kMetricLabelProcess, def.mode);
    // }
    return true;
}

bool ProcessCollector::GetPids(std::vector<pid_t>& pids) {
    pids.clear();
    bool ret;
    ret = WalkAllDigitDirs(PROCESS_DIR, [&](const std::string &dirName) {
            pid_t pid{};
            if (!StringTo(dirName, pid)) {
                return;
            }
            if (pid != 0) {
                pids.push_back(pid);
            }
        });

    return ret;
}

bool ProcessCollector::WalkAllDigitDirs(const std::filesystem::path& root, const std::function<void(const std::string&)>& callback) {
    if (!std::filesystem::exists(root) || !std::filesystem::is_directory(root)) {
        if (mValidState) {
            mValidState = false;
        }
        return false;
    }
    mValidState = true;

    for (const auto& dirEntry :
         std::filesystem::directory_iterator{root, std::filesystem::directory_options::skip_permission_denied}) {
        std::string filename = dirEntry.path().filename().string();
        if (IsInt(filename)) {
            callback(filename);
        }
    }
    return true;
}

// pid - self
// pid - parent id
void ProcessCollector::RemovePid(std::vector<pid_t> &pids, pid_t pid, pid_t ppid) {
    size_t count = pids.size();
    for (size_t i = 0; i < count;) {
        pid_t curPid = pids[i];
        if (curPid == pid || curPid == ppid) {
            count--;
            pids[i] = pids[count];
        } else {
            ++i;
        }
    }
    if (count != pids.size()) {
        pids.resize(count);
    }
}

void ProcessCollector::GetSelfPid(pid_t &pid, pid_t &ppid) {
    pid = getpid();
    ppid = getppid();
}

} // namespace logtail
