@input
Feature: performance file to file fluentbit
  Performance file to file fluentbit

  @e2e-performance @docker-compose @fluentbit-file
  Scenario: PerformanceFileToFileFluentbit
    Given {docker-compose} environment
    Given docker-compose boot type {benchmark}
    When start docker-compose {performance_file_to_file_fluentbit}
    When start monitor {fluent-bit}, with timeout {6} min
    When generate random nginx logs to file, speed {10}MB/s, total {5}min, to file {./test_cases/performance_file_to_file_fluentbit/a.log}
    When wait monitor until log processing finished
