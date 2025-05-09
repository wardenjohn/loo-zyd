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
#pragma once

#include <vector>

#include "host_monitor/collector/BaseCollector.h"
#include "host_monitor/collector/MetricCalculate.h"

namespace logtail {

struct SystemStat {
    double load1;
    double load5;
    double load15;
    double load1_per_core;
    double load5_per_core;
    double load15_per_core;
};

class SystemCollector : public BaseCollector {
public:
    SystemCollector();

    int Init(int totalCount = 3);
    ~SystemCollector() override = default;

    bool Collect(const HostMonitorTimerEvent::CollectConfig& collectConfig, PipelineEventGroup* group) override;

    static const std::string sName;
    const std::string& Name() const override { return sName; }

private:
    bool GetHostSystemLoadStat(SystemStat& systemload);

private:
    int mTotalCount = 0;
    int mCount = 0;
    MetricCalculate<SystemStat> mCalculate;
};

} // namespace logtail
