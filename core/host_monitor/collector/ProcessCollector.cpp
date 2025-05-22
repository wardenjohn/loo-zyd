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
#include "host_monitor/collector/MemCollector.h"

#include <filesystem>
#include <string>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
#include "host_monitor/SystemInformationTools.h"
#include "logger/Logger.h"
#include "common/TimeProfile.h"

namespace logtail {

    const std::string ProcessCollector::sName = "Process";
    const std::string kMetricLabelMem = "valueTag";
    const std::string kMetricLabelMode = "mode";

    ProcessCollect::~ProcessCollect() {
        LogInfo("unload {}", mModuleName);
    }

    ProcessCollect::ProcessCollect() : mModuleName{"process"}, mSelfPid{GetPid()}, mParentPid{GetParentPid()} {
        
    }

    uint64_t ProcessCollect::GetPid() {
        return getpid();
    }

    uint64_t ProcessCollect::GetParentPid() {
        return getppid();
    }

    bool ProcessCollect::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
        std::string errorMessage;
        if (group == nullptr) {
            return false;
        }
        TimeProfile tpCost;
        mCount++;
        steady_clock::time_point startTime = tpCost.lastTime();
        //更新总内存
        TimeProfile tp;
        if (UpdateTotalMemory(mTotalMemory) != 0) {
            return -1;
        }

        //采集所有的进程pid列表
        vector<pid_t> pids;
        bool isOverflow = false;

        // 溢出时依然返回0
        if (GetProcessPids(pids, maxProcessCount, &isOverflow) != 0) {
            return -1;
        }

        if (isOverflow) {
            errorMessage = "GetProcessPids overflow"
            LOG_WARNING(sLogger, ("failed to get process state", "invalid process collector")("error msg", errorMessage));
            return -1;
        }

        removePid(pids, mSelfPid, mParentPid);


    }

    int ProcessCollect::UpdateTotalMemory(uint64_t &totalMemory) {
        //更新下totalMemory
        MemoryInformation memoryStat;
        if (GetMemoryStat(memoryStat) != 0) {
            return -1;
        }
        totalMemory = memoryStat.total;

        return 0;
    }

    int ProcessCollect::GetProcessPids(vector<pid_t> &pids, int maxCount, bool *isOverflow) {
        SicProcessList pidList;
        bool tmpOverflow = false;
        overflow = overflow ? overflow : &tmpOverflow;
        int F(SicGetProcessList, pidList, limit, *overflow)

        pids = std::move(pidList.pids);

        return 0;
    }

    // pid  - loongcollector 自身
    // ppid - loongcollector -d 进程
    static void removePid(std::vector<pid_t> &pids, pid_t pid, pid_t ppid) {
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

    // 采集Top N进程
    void ProcessCollect::collectTopN(const std::vector<pid_t> &pids, common::CollectData &collectData) {
        vector<pid_t> sortPids;

    }

    void ProcessCollect::CopyAndSortByCpu(const std::vector<pid_t> &pids, std::vector<pid_t> &sortPids) {
        steady_clock::time_point now = steady_clock::now();
        if (mProcessSortCollectTime + ProcessSortInterval > now) {
            sortPids = mSortPids;
            return;
        }

        TimeProfile tpTotal;
        vector<tagPidTotal> sortPidInfos;
        TimeProfile tp;
        {
            auto currentPidMap = std::make_shared<map<pid_t, uint64_t>>();
            fnGetPidsMetric(pids, *currentPidMap);

            if (!mLastPidCpuMap) {
                mLastPidCpuMap = currentPidMap;
                if (mTopType == Cpu) {
                    // cpu是增量指标，第一次只能做为基础值，此时无法进行排序
                    LogInfo("CopyAndSortByCpu with the first time");
                    return;
                }
            }
            LogDebug("{}({} processes), top{}, collect cost: {},", __FUNCTION__,
                     pids.size(), currentPidMap->size(), tp.cost<fraction_millis>());

            sortPidInfos.reserve(currentPidMap->size());
            for (auto const &curIt: *currentPidMap) {
                const pid_t pid = curIt.first;

                auto const prevIt = mLastPidCpuMap->find(pid);
                if (prevIt != mLastPidCpuMap->end() && curIt.second >= prevIt->second) {
                    // tagPidTotal pidSortInfo;
                    // pidSortInfo.pid = pid;
                    // pidSortInfo.total = curIt.second - prevIt->second;
                    sortPidInfos.emplace_back(pid, fnTopValue(curIt.second, prevIt->second));
                }
            }
            LogDebug("{}({} processes), copy cost: {},", __FUNCTION__, pids.size(), tp.cost<fraction_millis>());
            mLastPidCpuMap = currentPidMap; // currentPidCpuMap使用完毕
            LogDebug("{}({} processes), cache cost: {},", __FUNCTION__, pids.size(), tp.cost<fraction_millis>());
        }
    }
}