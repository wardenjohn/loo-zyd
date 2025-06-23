/*
 * Copyright 2024 iLogtail Authors
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

#include <filesystem>

#include "common/StringView.h"

namespace logtail {

extern std::filesystem::path PROCESS_DIR;
const extern std::filesystem::path PROCESS_STAT;
const extern std::filesystem::path PROCESS_LOADAVG;
extern std::filesystem::path PROCESS_MEMINFO;
extern std::filesystem::path PROCESS_MTRR;
const extern int64_t SYSTEM_HERTZ;

#ifdef __ENTERPRISE__
inline constexpr StringView DEFAULT_INSTANCE_ID_LABEL = "instance_id";
inline constexpr StringView DEFAULT_USER_ID_LABEL = "user_id";
#else
inline constexpr StringView DEFAULT_HOST_IP_LABEL = "host_ip";
#endif

} // namespace logtail
