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

#include "host_monitor/LinuxSystemInterface.h"

#include <chrono>

using namespace std;
using namespace std::chrono;

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <pwd.h>
#include <grp.h>
#include <filesystem>
#include <boost/program_options.hpp>
#include <iostream>

#include "common/FileSystemUtil.h"
#include "common/StringTools.h"
#include "host_monitor/Constants.h"
#include "logger/Logger.h"

namespace logtail {

bool GetHostSystemStat(vector<string>& lines, string& errorMessage) {
    errorMessage.clear();
    if (!CheckExistance(PROCESS_DIR / PROCESS_STAT)) {
        errorMessage = "file does not exist: " + (PROCESS_DIR / PROCESS_STAT).string();
        return false;
    }

    int ret = GetFileLines(PROCESS_DIR / PROCESS_STAT, lines, true, &errorMessage);
    if (ret != 0 || lines.empty()) {
        return false;
    }
    return true;
}

double ParseMetric(const std::vector<std::string>& cpuMetric, EnumCpuKey key) {
    if (cpuMetric.size() <= static_cast<size_t>(key)) {
        return 0.0;
    }
    double value = 0.0;
    if (!StringTo(cpuMetric[static_cast<size_t>(key)], value)) {
        LOG_WARNING(
            sLogger,
            ("failed to parse cpu metric", static_cast<size_t>(key))("value", cpuMetric[static_cast<size_t>(key)]));
    }
    return value;
}

bool LinuxSystemInterface::GetSystemInformationOnce(SystemInformation& systemInfo) {
    std::vector<std::string> lines;
    std::string errorMessage;
    if (!GetHostSystemStat(lines, errorMessage)) {
        LOG_ERROR(sLogger, ("failed to get system information", errorMessage));
        return false;
    }
    for (auto const& line : lines) {
        auto cpuMetric = SplitString(line);
        // example: btime 1719922762
        if (cpuMetric.size() >= 2 && cpuMetric[0] == "btime") {
            if (!StringTo(cpuMetric[1], systemInfo.bootTime)) {
                LOG_WARNING(sLogger,
                            ("failed to get system boot time", "use current time instead")("error msg", cpuMetric[1]));
                return false;
            }
            break;
        }
    }
    systemInfo.collectTime = steady_clock::now();
    return true;
}

bool LinuxSystemInterface::GetCPUInformationOnce(CPUInformation& cpuInfo) {
    std::vector<std::string> cpuLines;
    std::string errorMessage;
    if (!GetHostSystemStat(cpuLines, errorMessage)) {
        return false;
    }
    // cpu  1195061569 1728645 418424132 203670447952 14723544 0 773400 0 0 0
    // cpu0 14708487 14216 4613031 2108180843 57199 0 424744 0 0 0
    // ...
    cpuInfo.stats.clear();
    cpuInfo.stats.reserve(cpuLines.size());
    for (auto const& line : cpuLines) {
        std::vector<std::string> cpuMetric;
        boost::split(cpuMetric, line, boost::is_any_of(" "), boost::token_compress_on);
        if (cpuMetric.size() > 0 && cpuMetric[0].substr(0, 3) == "cpu") {
            CPUStat cpuStat{};
            if (cpuMetric[0] == "cpu") {
                cpuStat.index = -1;
            } else {
                if (!StringTo(cpuMetric[0].substr(3), cpuStat.index)) {
                    LOG_ERROR(sLogger, ("failed to parse cpu index", "skip")("wrong cpu index", cpuMetric[0]));
                    continue;
                }
            }
            cpuStat.user = ParseMetric(cpuMetric, EnumCpuKey::user);
            cpuStat.nice = ParseMetric(cpuMetric, EnumCpuKey::nice);
            cpuStat.system = ParseMetric(cpuMetric, EnumCpuKey::system);
            cpuStat.idle = ParseMetric(cpuMetric, EnumCpuKey::idle);
            cpuStat.iowait = ParseMetric(cpuMetric, EnumCpuKey::iowait);
            cpuStat.irq = ParseMetric(cpuMetric, EnumCpuKey::irq);
            cpuStat.softirq = ParseMetric(cpuMetric, EnumCpuKey::softirq);
            cpuStat.steal = ParseMetric(cpuMetric, EnumCpuKey::steal);
            cpuStat.guest = ParseMetric(cpuMetric, EnumCpuKey::guest);
            cpuStat.guestNice = ParseMetric(cpuMetric, EnumCpuKey::guest_nice);
            cpuInfo.stats.push_back(cpuStat);
        }
    }
    cpuInfo.collectTime = steady_clock::now();
    return true;
}

bool LinuxSystemInterface::GetProcessListInformationOnce(ProcessListInformation& processListInfo) {
    processListInfo.pids.clear();
    if (!std::filesystem::exists(PROCESS_DIR) || !std::filesystem::is_directory(PROCESS_DIR)) {
        LOG_ERROR(sLogger, ("process root path is not a directory or not exist", PROCESS_DIR));
        return false;
    }

    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(
             PROCESS_DIR, std::filesystem::directory_options::skip_permission_denied, ec);
         it != std::filesystem::directory_iterator();
         ++it) {
        if (ec) {
            LOG_ERROR(sLogger, ("failed to iterate process directory", PROCESS_DIR)("error", ec.message()));
            return false;
        }
        const auto& dirEntry = *it;
        std::string dirName = dirEntry.path().filename().string();
        if (IsInt(dirName)) {
            pid_t pid{};
            if (!StringTo(dirName, pid)) {
                LOG_ERROR(sLogger, ("failed to parse pid", dirName));
            } else {
                processListInfo.pids.push_back(pid);
            }
        }
    }
    processListInfo.collectTime = steady_clock::now();
    return true;
}

bool LinuxSystemInterface::GetProcessInformationOnce(pid_t pid, ProcessInformation& processInfo) {
    auto processStat = PROCESS_DIR / std::to_string(pid) / PROCESS_STAT;
    std::string line;
    if (FileReadResult::kOK != ReadFileContent(processStat.string(), line)) {
        LOG_ERROR(sLogger, ("read process stat", "fail")("file", processStat));
        return false;
    }
    mProcParser.ParseProcessStat(pid, line, processInfo.stat);
    processInfo.collectTime = steady_clock::now();
    return true;
}

bool LinuxSystemInterface::GetMemoryInformationStringOnce(MemoryInformationString& memInfoStr) { 
    auto memInfoStat = PROCESS_DIR / PROCESS_MEMINFO;
    memInfoStr.meminfoString.clear();

    std::ifstream file(static_cast<std::string>(memInfoStat));

    if (!file.is_open()) {
        LOG_ERROR(sLogger, ("open meminfo file", "fail")("file", memInfoStat));
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        memInfoStr.meminfoString.push_back(line);
    }

    file.close();

    return true;
}

bool LinuxSystemInterface::GetMTRRInformationStringOnce(MTRRInformationString& mtrrInfoStr) {
    auto mtrrInfoStat = PROCESS_DIR / PROCESS_MTRR;
    mtrrInfoStr.mtrrString.clear();

    std::ifstream file(static_cast<std::string>(mtrrInfoStat));

    if (!file.is_open()) {
        LOG_ERROR(sLogger, ("open mtrr file", "fail")("file", mtrrInfoStat));
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        mtrrInfoStr.mtrrString.push_back(line);
    }

    file.close();

    return true;
}


bool LinuxSystemInterface::GetProcessCmdlineStringOnce(pid_t pid, ProcessCmdlineString& cmdline) {
    auto processCMDline = PROCESS_DIR / std::to_string(pid) / PROCESS_CMDLINE;
    cmdline.cmdline.clear();

    std::ifstream file(static_cast<std::string>(processCMDline));

    if (!file.is_open()) {
        LOG_ERROR(sLogger, ("open process cmdline file", "fail")("file", processCMDline));
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        cmdline.cmdline.push_back(line);
    }

    file.close();

    return true;
}

bool LinuxSystemInterface::GetProcessStatmOnce(pid_t pid, ProcessMemoryInformation& processMemory) { 
    auto processStatm = PROCESS_DIR / std::to_string(pid) / PROCESS_STATM;
    std::vector<std::string> processStatmString;
    char* endptr;

    std::ifstream file(static_cast<std::string>(processStatm));

    if (!file.is_open()) {
        LOG_ERROR(sLogger, ("open process statm file", "fail")("file", processStatm));
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        processStatmString.push_back(line);
    }
    file.close();

    std::vector<std::string> processMemoryMetric;
    if (!processStatmString.empty()) {
        const std::string& input = processStatmString.front();
        boost::algorithm::split(
            processMemoryMetric,
            input,
            boost::is_any_of(" "),
            boost::algorithm::token_compress_on
        );
    }

    if (processMemoryMetric.size() < 3) {
        return false;
    }

    long pagesize = sysconf(_SC_PAGESIZE); // 获取系统页大小
    int index = 0;
    processMemory.size = static_cast<uint64_t>(std::strtoull(processMemoryMetric[index++].c_str(), &endptr, 10));
    processMemory.size = processMemory.size * pagesize;
    processMemory.resident = static_cast<uint64_t>(std::strtoull(processMemoryMetric[index++].c_str(), &endptr, 10)); 
    processMemory.resident = processMemory.resident * pagesize;
    processMemory.share = static_cast<uint64_t>(std::strtoull(processMemoryMetric[index++].c_str(), &endptr, 10));
    processMemory.share = processMemory.share * pagesize;

    return true;
}

bool LinuxSystemInterface::GetProcessCredNameOnce(pid_t pid, ProcessCredName& processCredName) {
    auto processStatus = PROCESS_DIR / std::to_string(pid) / PROCESS_STATUS;
    std::vector<std::string> processStatusString;
    std::vector<std::string> metric;

    std::ifstream file(static_cast<std::string>(processStatus));

    if (!file.is_open()) {
        LOG_ERROR(sLogger, ("open process status file", "fail")("file", processStatus));
    }

    std::string line;
    while (std::getline(file, line))
    {
        processStatusString.push_back(line);
    }
    file.close();

    ProcessCred cred{};

    for (size_t i = 0; i < processStatusString.size(); ++i) {
        boost::algorithm::split(
            metric,
            processStatusString[i],
            boost::algorithm::is_any_of("\t"),
            boost::algorithm::token_compress_on
        );
        if (metric.front() == "Name:") {
            processCredName.name = metric[1];
        }
        if (metric.size() >= 3 && metric.front() == "Uid:") {
            int index = 1;
            cred.uid = static_cast<uint64_t>(std::stoull(metric[index++]));
            cred.euid = static_cast<uint64_t>(std::stoull(metric[index]));
        } else if (metric.size() >= 3 && metric.front() == "Gid:") {
            int index = 1;
            cred.gid = static_cast<uint64_t>(std::stoull(metric[index++]));
            cred.egid = static_cast<uint64_t>(std::stoull(metric[index]));
        }
    }

    passwd *pw = nullptr;
    passwd pwbuffer;
    char buffer[2048];
    if (getpwuid_r(cred.uid, &pwbuffer, buffer, sizeof(buffer), &pw) != 0) {
        return EXECUTE_FAIL;
    }
    if (pw == nullptr) {
        return EXECUTE_FAIL;
    }
    processCredName.user = pw->pw_name;

    group *grp = nullptr;
    group grpbuffer{};
    char groupBuffer[2048];
    if (getgrgid_r(cred.gid, &grpbuffer, groupBuffer, sizeof(groupBuffer), &grp)) {
        return EXECUTE_FAIL;
    }

    if (grp != nullptr && grp->gr_name != nullptr) {
        processCredName.group = grp->gr_name;
    }

    return true;
}

bool LinuxSystemInterface::GetExecutablePathOnce(pid_t pid, ProcessExecutePath &executePath) {
    std::filesystem::path procExePath = PROCESS_DIR / std::to_string(pid) / PROCESS_EXE;
    char buffer[4096];
    ssize_t len = readlink(procExePath.c_str(), buffer, sizeof(buffer));
    if (len < 0) {
        executePath.path = "";
        return true;
    }
    executePath.path.assign(buffer, len);
    return true;
}

bool LinuxSystemInterface::GetProcessOpenFilesOnce(pid_t pid, ProcessFd &processFd) {
    std::filesystem::path procFdPath = PROCESS_DIR / std::to_string(pid) / PROCESS_FD;

    int count = 0;
    for (const auto& dirEntry :
         std::filesystem::directory_iterator{procFdPath, std::filesystem::directory_options::skip_permission_denied}) {
        std::string filename = dirEntry.path().filename().string();
        count++;
    }

    processFd.total = count;
    processFd.exact = true;

    return true;
}
} // namespace logtail
