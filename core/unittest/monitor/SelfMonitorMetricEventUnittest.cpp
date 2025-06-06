// Copyright 2024 iLogtail Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "MetricConstants.h"
#include "MetricRecord.h"
#include "Monitor.h"
#include "monitor/MetricManager.h"
#include "monitor/metric_models/SelfMonitorMetricEvent.h"
#include "unittest/Unittest.h"

namespace logtail {

class SelfMonitorMetricEventUnittest : public ::testing::Test {
public:
    void SetUp() {}
    void TearDown() {}

    void TestCreateFromMetricEvent();
    void TestCreateFromGoMetricMap();
    void TestMerge();
    void TestSendInterval();
    void TestGlobalMetrics();

private:
    std::shared_ptr<SourceBuffer> mSourceBuffer;
    std::unique_ptr<PipelineEventGroup> mEventGroup;
    std::unique_ptr<MetricEvent> mMetricEvent;
};

APSARA_UNIT_TEST_CASE(SelfMonitorMetricEventUnittest, TestCreateFromMetricEvent, 0);
APSARA_UNIT_TEST_CASE(SelfMonitorMetricEventUnittest, TestCreateFromGoMetricMap, 1);
APSARA_UNIT_TEST_CASE(SelfMonitorMetricEventUnittest, TestMerge, 2);
APSARA_UNIT_TEST_CASE(SelfMonitorMetricEventUnittest, TestSendInterval, 3);
APSARA_UNIT_TEST_CASE(SelfMonitorMetricEventUnittest, TestGlobalMetrics, 4);

void SelfMonitorMetricEventUnittest::TestCreateFromMetricEvent() {
    std::vector<std::pair<std::string, std::string>> labels;
    labels.emplace_back(std::make_pair<std::string, std::string>("plugin_type", "input_file"));
    labels.emplace_back(std::make_pair<std::string, std::string>("plugin_id", "1"));
    labels.emplace_back(std::make_pair<std::string, std::string>("pipeline_name", "pipeline_test"));
    labels.emplace_back(std::make_pair<std::string, std::string>("project", "project_a"));

    MetricsRecord* pluginMetric = new MetricsRecord(MetricCategory::METRIC_CATEGORY_PLUGIN,
                                                    std::make_shared<MetricLabels>(labels),
                                                    std::make_shared<DynamicMetricLabels>());

    CounterPtr outSizeBytes = pluginMetric->CreateCounter("out_size_bytes");
    ADD_COUNTER(outSizeBytes, 100);
    CounterPtr outEventTotal = pluginMetric->CreateCounter("out_event_total");
    ADD_COUNTER(outEventTotal, 1024);
    IntGaugePtr monitorFileTotal = pluginMetric->CreateIntGauge("monitor_file_total");
    SET_GAUGE(monitorFileTotal, 10);

    SelfMonitorMetricEvent event(pluginMetric);

    APSARA_TEST_EQUAL(MetricCategory::METRIC_CATEGORY_PLUGIN, event.mCategory);
    APSARA_TEST_EQUAL(4U, event.mLabels.size());
    APSARA_TEST_EQUAL("input_file", event.mLabels["plugin_type"]);
    APSARA_TEST_EQUAL("1", event.mLabels["plugin_id"]);
    APSARA_TEST_EQUAL("pipeline_test", event.mLabels["pipeline_name"]);
    APSARA_TEST_EQUAL("project_a", event.mLabels["project"]);
    APSARA_TEST_EQUAL(2U, event.mCounters.size());
    APSARA_TEST_EQUAL(100U, event.mCounters["out_size_bytes"]);
    APSARA_TEST_EQUAL(1024U, event.mCounters["out_event_total"]);
    APSARA_TEST_EQUAL(1U, event.mGauges.size());
    APSARA_TEST_EQUAL(10, event.mGauges["monitor_file_total"]);

    delete pluginMetric;
}

void SelfMonitorMetricEventUnittest::TestCreateFromGoMetricMap() {
    std::map<std::string, std::string> pluginMetric;
    pluginMetric["labels"] = R"(
        {
            "metric_category":"plugin",
            "plugin_type":"input_file",
            "plugin_id":"1",
            "pipeline_name":"pipeline_test",
            "project":"project_a"
        }
    )";
    pluginMetric["counters"] = R"(
        {
            "out_size_bytes": "100",
            "out_event_total": "1024"
        }
    )";
    pluginMetric["gauges"] = R"(
        {
            "monitor_file_total": "10"
        }
    )";
    SelfMonitorMetricEvent event(pluginMetric);

    APSARA_TEST_EQUAL(MetricCategory::METRIC_CATEGORY_PLUGIN, event.mCategory);
    APSARA_TEST_EQUAL(4U, event.mLabels.size());
    APSARA_TEST_EQUAL("input_file", event.mLabels["plugin_type"]);
    APSARA_TEST_EQUAL("1", event.mLabels["plugin_id"]);
    APSARA_TEST_EQUAL("pipeline_test", event.mLabels["pipeline_name"]);
    APSARA_TEST_EQUAL("project_a", event.mLabels["project"]);
    APSARA_TEST_EQUAL(2U, event.mCounters.size());
    APSARA_TEST_EQUAL(100U, event.mCounters["out_size_bytes"]);
    APSARA_TEST_EQUAL(1024U, event.mCounters["out_event_total"]);
    APSARA_TEST_EQUAL(1U, event.mGauges.size());
    APSARA_TEST_EQUAL(10, event.mGauges["monitor_file_total"]);
}

void SelfMonitorMetricEventUnittest::TestMerge() {
    {
        SelfMonitorMetricEvent event1;
        SelfMonitorMetricEvent event2;

        // 初始化 event1 和 event2
        event1.mCounters["counter1"] = 100;
        event1.mGauges["gauge1"] = 1.5;
        event2.mCounters["counter1"] = 200;
        event2.mGauges["gauge1"] = 2.5;

        event1.mUpdatedFlag = false;
        event2.mUpdatedFlag = true;

        event1.Merge(event2);

        // 检验是否正确合并
        APSARA_TEST_EQUAL(300, event1.mCounters["counter1"]);
        APSARA_TEST_EQUAL(2.5, event1.mGauges["gauge1"]);
        APSARA_TEST_TRUE(event1.mUpdatedFlag);
    }
    // 含有不重叠键值的情况
    {
        SelfMonitorMetricEvent event1;
        SelfMonitorMetricEvent event2;

        // 初始化 event1 和 event2
        event1.mCounters["counter1"] = 100;
        event2.mCounters["counter2"] = 200;
        event1.mGauges["gauge1"] = 1.5;
        event2.mGauges["gauge2"] = 2.5;

        event1.Merge(event2);

        // 检验是否正确合并
        APSARA_TEST_EQUAL(100, event1.mCounters["counter1"]);
        APSARA_TEST_EQUAL(200, event1.mCounters["counter2"]);
        APSARA_TEST_EQUAL(1.5, event1.mGauges["gauge1"]);
        APSARA_TEST_EQUAL(2.5, event1.mGauges["gauge2"]);
    }
    // 不同发送间隔
    {
        SelfMonitorMetricEvent event1;
        SelfMonitorMetricEvent event2;

        event1.SetInterval(5);
        event2.SetInterval(10);

        event1.mCounters["counter1"] = 100;
        event2.mCounters["counter1"] = 200;

        event1.Merge(event2);

        // 检验间隔是否被设置为 event2 的间隔
        APSARA_TEST_EQUAL(0, event1.mIntervalsSinceLastSend);
        APSARA_TEST_EQUAL(10, event1.mSendInterval);
        // 检验计数器是否正确合并
        APSARA_TEST_EQUAL(300, event1.mCounters["counter1"]);
    }
}

void SelfMonitorMetricEventUnittest::TestSendInterval() {
    SelfMonitorMetricEvent event;
    mSourceBuffer.reset(new SourceBuffer);
    mEventGroup.reset(new PipelineEventGroup(mSourceBuffer));
    mMetricEvent = mEventGroup->CreateMetricEvent();

    event.mUpdatedFlag = true;
    event.SetInterval(3);
    APSARA_TEST_FALSE(event.ShouldSend());
    APSARA_TEST_FALSE(event.ShouldDelete());
    APSARA_TEST_FALSE(event.ShouldSend()); // 模拟两次调用，间隔计数为2
    APSARA_TEST_FALSE(event.ShouldDelete());
    APSARA_TEST_TRUE(event.ShouldSend()); // 第三次调用，间隔计数达到3，应返回true
    APSARA_TEST_FALSE(event.ShouldDelete());
    event.ReadAsMetricEvent(mMetricEvent.get());
    APSARA_TEST_FALSE(event.ShouldDelete());

    event.mUpdatedFlag = false;
    APSARA_TEST_FALSE(event.ShouldSend());
    APSARA_TEST_FALSE(event.ShouldDelete());
    APSARA_TEST_FALSE(event.ShouldSend());
    APSARA_TEST_FALSE(event.ShouldDelete());
    APSARA_TEST_FALSE(event.ShouldSend());
    APSARA_TEST_TRUE(event.ShouldDelete()); // 第三次调用，间隔计数达到3，应返回true
}

void SelfMonitorMetricEventUnittest::TestGlobalMetrics() {
    { // test set/get agent metric
        SelfMonitorMetricEvent originAgentEvent;
        SelfMonitorMetricEvent wantAgentEvent;

        // set
        originAgentEvent.mCategory = MetricCategory::METRIC_CATEGORY_AGENT;
        originAgentEvent.mLabels = {{METRIC_LABEL_KEY_PROJECT, "test_project"}, {METRIC_LABEL_KEY_OS, "Linux"}};
        originAgentEvent.mCounters = {{"test_counter", 1}};
        originAgentEvent.mGauges = {{METRIC_AGENT_CPU, 0.3}, {METRIC_AGENT_MEMORY, 99}};
        LoongCollectorMonitor::GetInstance()->SetAgentMetric(originAgentEvent);

        // get
        APSARA_TEST_TRUE(LoongCollectorMonitor::GetInstance()->GetAgentMetric(wantAgentEvent));
        APSARA_TEST_EQUAL(MetricCategory::METRIC_CATEGORY_AGENT, wantAgentEvent.mCategory);
        APSARA_TEST_EQUAL("test_project", wantAgentEvent.GetLabel(METRIC_LABEL_KEY_PROJECT));
        APSARA_TEST_EQUAL("Linux", wantAgentEvent.GetLabel(METRIC_LABEL_KEY_OS));
        APSARA_TEST_EQUAL("", wantAgentEvent.GetLabel(""));
        APSARA_TEST_EQUAL(1, wantAgentEvent.GetCounter("test_counter"));
        APSARA_TEST_EQUAL(0, wantAgentEvent.GetCounter(""));
        APSARA_TEST_EQUAL(0.3, wantAgentEvent.GetGauge(METRIC_AGENT_CPU));
        APSARA_TEST_EQUAL(99, wantAgentEvent.GetGauge(METRIC_AGENT_MEMORY));
        APSARA_TEST_EQUAL(0, wantAgentEvent.GetGauge(""));
    }
    { // test set/get runner metric
        SelfMonitorMetricEvent originRunnerEvent;
        SelfMonitorMetricEvent wantRunnerEvent;
        APSARA_TEST_FALSE(LoongCollectorMonitor::GetInstance()->GetRunnerMetric("", wantRunnerEvent));

        // set
        std::string runnerName = METRIC_LABEL_VALUE_RUNNER_NAME_HTTP_SINK;
        originRunnerEvent.mCategory = MetricCategory::METRIC_CATEGORY_RUNNER;
        originRunnerEvent.mLabels
            = {{METRIC_LABEL_KEY_RUNNER_NAME, runnerName}, {METRIC_LABEL_KEY_PROJECT, "test_project"}};
        originRunnerEvent.mCounters = {{METRIC_RUNNER_IN_EVENTS_TOTAL, 1}, {METRIC_RUNNER_TOTAL_DELAY_MS, 99}};
        originRunnerEvent.mGauges = {{METRIC_RUNNER_LAST_RUN_TIME, 1111111}};
        LoongCollectorMonitor::GetInstance()->SetRunnerMetric(runnerName, originRunnerEvent);

        // get
        APSARA_TEST_FALSE(LoongCollectorMonitor::GetInstance()->GetRunnerMetric("", wantRunnerEvent));
        APSARA_TEST_TRUE(LoongCollectorMonitor::GetInstance()->GetRunnerMetric(runnerName, wantRunnerEvent));
        APSARA_TEST_EQUAL(MetricCategory::METRIC_CATEGORY_RUNNER, wantRunnerEvent.mCategory);
        APSARA_TEST_EQUAL("test_project", wantRunnerEvent.GetLabel(METRIC_LABEL_KEY_PROJECT));
        APSARA_TEST_EQUAL(runnerName, wantRunnerEvent.GetLabel(METRIC_LABEL_KEY_RUNNER_NAME));
        APSARA_TEST_EQUAL("", wantRunnerEvent.GetLabel(""));
        APSARA_TEST_EQUAL(1, wantRunnerEvent.GetCounter(METRIC_RUNNER_IN_EVENTS_TOTAL));
        APSARA_TEST_EQUAL(99, wantRunnerEvent.GetCounter(METRIC_RUNNER_TOTAL_DELAY_MS));
        APSARA_TEST_EQUAL(0, wantRunnerEvent.GetCounter(""));
        APSARA_TEST_EQUAL(1111111, wantRunnerEvent.GetGauge(METRIC_RUNNER_LAST_RUN_TIME));
        APSARA_TEST_EQUAL(0, wantRunnerEvent.GetGauge(""));
    }
}

} // namespace logtail

int main(int argc, char** argv) {
    logtail::Logger::Instance().InitGlobalLoggers();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
