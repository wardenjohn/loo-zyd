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
#include <boost/program_options.hpp>

#include "boost/algorithm/string.hpp"
#include "boost/algorithm/string/split.hpp"

#include "MetricValue.h"
#include "common/StringTools.h"
#include "host_monitor/Constants.h"
#include "host_monitor/SystemInformationTools.h"
#include "logger/Logger.h"
#include "common/TimeUtil.h"

int64_t ToMillis(std::chrono::system_clock::time_point &t) {
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

extern const int ClkTck = sysconf(_SC_CLK_TCK); // 一般为100

static uint64_t Tick2Millisecond(uint64_t tick) {
    constexpr const uint64_t MILLISECOND = 1000;
    return tick * MILLISECOND / ClkTck;
}

static uint64_t Tick2Millisecond(const std::string &tick) {
    return Tick2Millisecond(static_cast<uint64_t>(std::stoll(tick)));
}

// T: uint64_t、std::chrono::milliseconds
template<typename T>
T Tick2(const std::string &tick) {
    return T{Tick2Millisecond(tick)};
}

template<typename T, typename TIndex>
class MillisVector {
    const TVector<TIndex> &v;
public:
    static constexpr const T zero{0};

    explicit MillisVector(const TVector<TIndex> &r) : v(r) {
    }

    T operator[](TIndex key) const {
        return Tick2<T>(v[key]);
    }
};

logtail::CpuInformationCache processCpuCache{}; // 全局CPU信息cache

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

    std::cout << "inside ProcessCollector::Collect" << std::endl;

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

    // 获取topN进程的信息
    std::vector<ProcessAllStat> topN;
    topN.reserve(mTopN);

    GetTopNProcessStat(sortPids, mTopN, topN);

}

// 获取TopN的进程信息
int ProcessCollector::GetTopNProcessStat(std::vector <pid_t> &sortPids, int topN, std::vector<ProcessAllStat> &processStats) {
    processStats.clear();
    processStats.reserve(topN);

    for (pid_t pid: sortPids) {
        ProcessAllStat processAllStat;
        if (GetProcessAllStat(pid, processAllStat) == 0) {
            processStats.push_back(processAllStat);
            break;
        }
    }
    return 0;
}

// 获取某个pid的信息
int ProcessCollector::GetProcessAllStat(pid_t pid, ProcessAllStat &processStat) {
    // 获取这个pid的cpu信息
    int ret = GetProcessCpuInformation(pid, processStat.processCpu, false);
    if (ret != 0) {
        return ret;
    }

    ret = GetProcessState(pid, processStat.processState);
    if (ret != 0) {
        return ret;
    }

    ret = GetProcessMemory(pid, processStat.processMemory);
    if (ret != 0) {
        return ret;
    }
}

// 获取pid的内存信息
int ProcessCollector::GetProcessMemory(pid_t pid, ProcessMemoryInformation &processMemory) {
    std::string errorMessage;
    LinuxProcessInfo linuxProcessInfo;
    int status = ReadProcessStat(pid, linuxProcessInfo);
    if (status != 0) {
        return status;
    }
    processMemory.minorFaults = linuxProcessInfo.minorFaults;
    processMemory.majorFaults = linuxProcessInfo.majorFaults;
    processMemory.pageFaults = linuxProcessInfo.minorFaults + linuxProcessInfo.majorFaults;

    std::vector<std::string> lines = {};
    const auto procStatm = PROCESS_DIR / std::to_string(pid) / PROCESS_STATM;

    std::vector<std::string> loadLines;

    if (!GetHostSystemStatWithPath(loadLines, errorMessage, procStatm)) {
        return EXECUTE_FAIL;
    }
    std::vector<std::string> processMemoryMetric = split((loadLines.empty() ? "" : lines.front()), ' ', false);
    if (processMemoryMetric.size() < 3) {
        return EXECUTE_FAIL;
    }

    int index = 0;
    processMemory.size = static_cast<uint64_t>(StringTo(processMemoryMetric[index++], processMemory.size));
}

//获取pid的状态信息
int ProcessCollector::GetProcessState(pid_t pid, ProcessStat &processState) {
    LinuxProcessInfo linuxProcessInfo;
    int status = ReadProcessStat(pid, linuxProcessInfo);
    if (status != 0) {
        return status;
    }

    processState.state = linuxProcessInfo.state;
    processState.tty = linuxProcessInfo.tty;
    processState.parentPid = linuxProcessInfo.parentPid;
    processState.priority = linuxProcessInfo.priority;
    processState.nice = linuxProcessInfo.nice;
    processState.processor = linuxProcessInfo.processor;
    processState.numThreads = linuxProcessInfo.numThreads;

    return EXECUTE_SUCCESS;
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

void ProcessCollector::CleanProcessCpuCacheIfNecessary() const {
    auto &cache = processCpuCache;
    if (cache.cleanPeriod.count() > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= cache.nextCleanTime) {
            cache.nextCleanTime = now + cache.cleanPeriod;
            for (auto entry = cache.entries.begin(); entry != cache.entries.end();) {
                if (entry->second.expireTime < now) {
                    //  no one access this entry for too long - need clean
                    cache.entries.erase(entry++);
                } else {
                    ++entry;
                }
            }
        }
    }
}

ProcessCpuInformation &ProcessCollector::GetProcessCpuInCache(pid_t pid, bool includeCTime) {
    CleanProcessCpuCacheIfNecessary();

    logtail::CpuInformationCache::key key{pid, includeCTime};
    auto &cache = processCpuCache;
    auto &entry = cache.entries[key]; // 没有则创建
    entry.expireTime = std::chrono::steady_clock::now() + cache.entryExpirePeriod;
    return entry.processCpu;
}

static inline bool IsZero(const std::chrono::steady_clock::time_point &t) {
    return t.time_since_epoch().count() == 0;
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

    int64_t timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(now - prev.lastTime).count(); 

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

    output.cutime = (includeCTime ? processInfo.cutime : std::chrono::milliseconds{0});
    output.cstime = (includeCTime ? processInfo.cstime : std::chrono::milliseconds{0});
    output.user = processInfo.utime + output.cutime;
    output.sys = processInfo.stime + output.cstime;

    output.total = output.user + output.sys;

    return EXECUTE_SUCCESS;
}

// 数据样例: /proc/1/stat, 解析/proc/pid/stat
// 1 (cat) R 0 1 1 34816 1 4194560 1110 0 0 0 1 1 0 0 20 0 1 0 18938584 4505600 171 18446744073709551615 4194304 4238788 140727020025920 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 6336016 6337300 21442560 140727020027760 140727020027777 140727020027777 140727020027887 0
int ProcessCollector::ReadProcessStat(pid_t pid, LinuxProcessInfo &processInfo) {
    processInfo.pid = pid;

    std::vector<std::string> loadLines;
    std::string first_line;
    std::string errorMessage;
    std::filesystem::path statPath = PROCESS_DIR / std::to_string(pid) / PROCESS_STAT;

    if (!GetHostSystemStatWithPath(loadLines, errorMessage, statPath)) {
        if (mValidState) {
            LOG_WARNING(sLogger, ("failed to get system load", "invalid System collector")("error msg", errorMessage));
            mValidState = false;
        }
        return EXECUTE_FAIL;
    }

    first_line = loadLines.front();
    auto nameStartPos = first_line.find_first_of('(');
    auto nameEndPos = first_line.find_last_of(')');

    if (nameStartPos == std::string::npos || nameEndPos == std::string::npos) {
        return EXECUTE_FAIL;
    }

    nameStartPos++; // 跳过左括号
    processInfo.name = first_line.substr(nameStartPos, nameEndPos - nameStartPos);
    first_line = first_line.substr(nameEndPos + 2); // 跳过右括号及空格

    std::vector<std::string> words = split(first_line, ' ', false);

    const EnumProcessStat offset = EnumProcessStat::state;  // 跳过pid, comm
    const int minCount = EnumProcessStat::processor - offset + 1;  // 37

    if (words.size() < minCount) {
        return EXECUTE_FAIL;
    }

    TVector<EnumProcessStat> v{words, offset};

    processInfo.state = v[EnumProcessStat::state].front();
    processInfo.parentPid = static_cast<pid_t>(atoi(v[EnumProcessStat::ppid].c_str()));
    processInfo.priority = static_cast<int>(atoi(v[EnumProcessStat::priority].c_str()));
    processInfo.nice = static_cast<int>(atoi(v[EnumProcessStat::nice].c_str()));
    processInfo.numThreads = static_cast<int>(atoi(v[EnumProcessStat::num_threads].c_str()));
    processInfo.tty = static_cast<int>(atoi(v[EnumProcessStat::tty_nr].c_str()));
    processInfo.minorFaults = static_cast<uint64_t>(atoi(v[EnumProcessStat::minflt].c_str()));
    processInfo.majorFaults = static_cast<uint64_t>(atoi(v[EnumProcessStat::majflt].c_str()));

    MillisVector<milliseconds, EnumProcessStat> mv{v};
    processInfo.utime = mv[EnumProcessStat::utime];
    processInfo.stime = mv[EnumProcessStat::stime];
    processInfo.cutime = mv[EnumProcessStat::cutime];
    processInfo.cstime = mv[EnumProcessStat::cstime];

    processInfo.startTime = std::chrono::system_clock::time_point{mv[EnumProcessStat::starttime]}; // for testing
    processInfo.vSize = static_cast<uint64_t>(atoi(v[EnumProcessStat::vsize].c_str()));
    processInfo.rss = static_cast<uint64_t>(atoi(v[EnumProcessStat::rss].c_str()));
    processInfo.processor = static_cast<int>(atoi(v[EnumProcessStat::processor].c_str()));

    return EXECUTE_SUCCESS;
}

static bool compare(const tagPidTotal &p1, const tagPidTotal &p2) {
    return p1.total > p2.total || (p1.total == p2.total && p1.pid < p2.pid);
}

static bool comparePointer(const tagPidTotal *p1, const tagPidTotal *p2) {
    return compare(*p1, *p2);
}

void ProcessCollector::CopyAndSortByCpu(const std::vector<pid_t> &pids, std::vector<pid_t> &sortPids) {
    steady_clock::time_point now = steady_clock::now();
    if (mProcessSortCollectTime + ProcessSortInterval > now) {
        sortPids = mSortPids;
        return;
    }

    std::vector<tagPidTotal> sortPidInfos;
    {
        auto currentPidMap = std::make_shared<std::map<pid_t, uint64_t>>();
        fnGetPidsMetric(pids, *currentPidMap); // GetPidsCpu

        if (!mLastPidCpuMap) {
            mLastPidCpuMap = currentPidMap;
            // if (mTopType == Cpu) {
            //     // cpu是增量指标，第一次只能做为基础值，此时无法进行排序
            //     return;
            // }
            return ;
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
