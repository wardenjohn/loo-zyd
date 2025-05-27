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
#include <algorithm>
#include <thread>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
#include "host_monitor/Constants.h"
#include "host_monitor/SystemInformationTools.h"
#include "logger/Logger.h"
#include "common/TimeUtil.h"

int64_t ToMillis(const std::chrono::system_clock::time_point &t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

#define Diff(a, b)  a-b>0 ? a-b : 0;

//topN进行的缓存为55s
const std::chrono::seconds ProcessSortInterval{55};

// TIndex为索引的Vector
template<typename TIndex>
class TVector {
    const std::vector<std::string> &data;
    const TIndex offset;
public:
    const std::string empty{};

    TVector(const std::vector<std::string> &d, TIndex of = (TIndex) 0)
            : data(d), offset(of) {
    }

    const std::string &operator[](TIndex key) const {
        int index = (int) key - (int) offset;
        return 0 <= index && index < static_cast<int>(data.size()) ? data[index] : empty;
    }
};

namespace logtail {

const std::string ProcessCollector::sName = "process";
const std::string kMetricLabelProcess = "valueTag";
const std::string kMetricLabelMode = "mode";


ProcessCollector::ProcessCollector(){
    Init();
}

int ProcessCollector::Init() {
    // default CPU
    fnGetPidsMetric = std::bind(&ProcessCollector::GetPidsCpu, this, std::placeholders::_1, std::placeholders::_2);
    fnTopValue = [](uint64_t cur, uint64_t prev) { return cur - prev; };
    mProcessSortCollectTime = steady_clock::time_point{}; // 清零
    return 0;
}

bool ProcessCollector::Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) {
    if (group == nullptr) {
        return false;
    }
    if (!GetPids(pids)) {
        return false;
    }

    const time_t now = time(nullptr);

    // 排除自身干扰
    GetSelfPid(mSelfPid, mParentPid);
    RemovePid(pids, mSelfPid, mParentPid);

    collectTopN(pids);

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

    for (const auto& def : metrics) {
        auto* metricEvent = group->AddMetricEvent(true);
        if (!metricEvent) {
            continue;
        }
        metricEvent->SetName(def.name);
        metricEvent->SetTimestamp(now, 0);
        metricEvent->SetValue<UntypedSingleValue>(def.value);
        metricEvent->SetTag(kMetricLabelProcess, def.mode);
    }
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

void ProcessCollector::collectTopN(const std::vector<pid_t> &pids) {
    // 排序
    std::vector<pid_t> sortPids;
    CopyAndSortByCpu(pids, sortPids);

}

// 获取每个Pid的CPU信息
int ProcessCollector::GetPidsCpu(const std::vector<pid_t> &pids, std::map<pid_t, uint64_t> &pidMap) {
    int readCount = 0;
    for (pid_t pid: pids) {
        if (++readCount > mProcessSilentCount) { // 每读一段时间就要停下，防止进程过多占用太多时间
            readCount = 0;
            std::this_thread::sleep_for(milliseconds{100});
        }
        // 获取每个Pid的CPU信息
        ProcessCpuInformation procCpu;
        if (0 == GetProcessCpuInformation(pid, procCpu, false)) {
            pidMap[pid] = procCpu.total;
        }
    }
    return 0;
}

int ProcessCollector::GetProcessCpuInformation(pid_t pid, ProcessCpuInformation &information,bool includeCTime) {
    const auto now = std::chrono::steady_clock::now();

    auto &prev = GetProcessCpuInCache(pid, includeCTime);

    information.lastTime = now;
    ProcessTime processTime{};
    int res = GetProcessTime(pid, processTime, includeCTime);

    if (res != EXECUTE_SUCCESS) {
        return res;
    }

    using namespace std::chrono;
    information.startTime = ToMillis(processTime.startTime);
    information.user = processTime.user.count();
    information.sys = processTime.sys.count();
    information.total = processTime.total.count();

    if (information.total < prev.total || IsZero(prev.lastTime)) {
        // first time called
        information.percent = 0.0;
    } else {
        auto totalDiff = static_cast<double>(information.total - prev.total);
        information.percent = totalDiff / static_cast<double>(timeDiff);
    }
    prev = information;

    return EXECUTE_SUCCESS;
}

int ProcessCollector::GetProcessTime(pid_t pid, ProcessTime &output, bool includeCTime) {
    LinuxProcessInfo processInfo{};
    int stat = ReadProcessStat(pid, processInfo);
    if (stat != EXECUTE_SUCCESS) {
        return stat;
    }

    output.startTime = processInfo.startTime;

    output.curtime = (includeCTime ? processInfo.cutime : 0_ms);
    output.cstime = (includeCTime ? processInfo.cstime : 0_ms);

    output.user = processInfo.utime + output.cutime;
    output.sys = processInfo.stime + output.cstime;

    output.total = output.user + output.sys;

    return EXECUTE_SUCCESS;
}

// 数据样例: /proc/1/stat
// 1 (cat) R 0 1 1 34816 1 4194560 1110 0 0 0 1 1 0 0 20 0 1 0 18938584 4505600 171 18446744073709551615 4194304 4238788 140727020025920 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 6336016 6337300 21442560 140727020027760 140727020027777 140727020027777 140727020027887 0
int ProcessCollector::ReadProcessStat(pid_t pid, LinuxProcessInfo &processInfo) {
    processInfo.pid = pid;

    std::string loadLines;
    std::string errorMessage;
    std::filesystem::path statPath = PROCESS_DIR / std::to_string(pid) / PROCESS_STAT;

    if (!GetHostSystemStatWithPath(loadLines, errorMessage, statPath)) {
        if (mValidState) {
            LOG_WARNING(sLogger, ("failed to get system load", "invalid System collector")("error msg", errorMessage));
            mValidState = false;
        }
        return EXECUTE_FAIL;
    }

    auto invalidStatError = [&processStat](const char *detail) {
        return (sout{} << "<" << processStat.string() << "> not a valid process stat file: " << detail).str();
    };

    auto nameStartPos = line.find_first_of('(');
    auto nameEndPos = line.find_last_of(')');

    if (nameStartPos == std::string::npos || nameEndPos == std::string::npos) {
        return EXECUTE_FAIL;
    }

    nameStartPos++; // 跳过左括号
    processInfo.name = line.substr(nameStartPos, nameEndPos - nameStartPos);
    line = line.substr(nameEndPos + 2); // 跳过右括号及空格

    std::vector<std::string> words = split(line, ' ', false);

    constexpr const EnumProcessStat offset = EnumProcessStat::state;  // 跳过pid, comm
    constexpr const int minCount = EnumProcessStat::processor - offset + 1;  // 37

    if (words.size() < minCount) {
        return EXECUTE_FAIL;
    }

    TVector<EnumProcessStat> v{words, offset};

    processInfo.state = v[EnumProcessStat::state].front();
    processInfo.parentPid = convert<pid_t>(v[EnumProcessStat::ppid]);
    processInfo.tty = convert<int>(v[EnumProcessStat::tty_nr]);
    processInfo.minorFaults = convert<uint64_t>(v[EnumProcessStat::minflt]);
    processInfo.majorFaults = convert<uint64_t>(v[EnumProcessStat::majflt]);

    MillisVector<milliseconds, EnumProcessStat> mv{v};
    processInfo.utime = mv[EnumProcessStat::utime];
    processInfo.stime = mv[EnumProcessStat::stime];
    processInfo.cutime = mv[EnumProcessStat::cutime];
    processInfo.cstime = mv[EnumProcessStat::cstime];

    processInfo.priority = convert<int>(v[EnumProcessStat::priority]);
    processInfo.nice = convert<int>(v[EnumProcessStat::nice]);
    processInfo.numThreads = convert<int>(v[EnumProcessStat::num_threads]);

    processInfo.startTime = std::chrono::system_clock::time_point{
            mv[EnumProcessStat::starttime]}; // TODO : Double check
    processInfo.vSize = convert<uint64_t>(v[EnumProcessStat::vsize]);
    processInfo.rss = convert<uint64_t>(v[EnumProcessStat::rss]); // pagesize??
    processInfo.processor = convert<int>(v[EnumProcessStat::processor]);

    return EXECUTE_SUCCESS;
}

void ProcessCollector::CopyAndSortByCpu(const std::vector<pid_t> &pids, std::vector<pid_t> &sortPids) {
    steady_clock::time_point now = steady_clock::now();
    if (mProcessSortCollectTime + ProcessSortInterval > now) {
        sortPids = mSortPids;
        return;
    }

    std::vector<tagPidTotal> sortPidInfos;
    {
        auto currentPidMap = std::make_shared<map<pid_t, uint64_t>>();
        fnGetPidsMetric(pids, *currentPidMap);

        if (!mLastPidCpuMap) {
            mLastPidCpuMap = currentPidMap;
            if (mTopType == Cpu) {
                // cpu是增量指标，第一次只能做为基础值，此时无法进行排序
                return;
            }
        }

        sortPidInfos.reserve(currentPidMap->size());
        for (auto const &curIt: *currentPidMap) {
            const pid_t pid = curIt.first;

            auto const prevIt = mLastPidCpuMap->find(pid);
            if (prevIt != mLastPidCpuMap->end() && curIt.second >= prevIt->second) {
                sortPidInfos.emplace_back(pid, fnTopValue(curIt.second, prevIt->second));
            }
        }
        mLastPidCpuMap = currentPidMap; // currentPidCpuMap使用完毕
    }
    const size_t pidCount = sortPidInfos.size();
    std::vector<tagPidTotal *> sortPidInfo2;
    sortPidInfo2.resize(sortPidInfos.size());
    for (size_t i = 0; i < pidCount; i++) {
        sortPidInfo2[i] = &sortPidInfos[i];
    }
    sort(sortPidInfo2.begin(), sortPidInfo2.end(), comparePointer);

    mSortPids.clear();
    mSortPids.reserve(sortPidInfo2.size());
    for (const auto &sortPidInfo: sortPidInfo2) {
        mSortPids.push_back(sortPidInfo->pid);
    }
    sortPids = mSortPids;
    mProcessSortCollectTime = steady_clock::now();
}

} // namespace logtail
