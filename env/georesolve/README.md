# georesolve

按来访者区域/租户返回不同结果的名字解析服务。规则按 **全局 → 区域 → 租户** 三层覆盖，
同一层可配置多个带权目标；正/负答案分别按各自 TTL 缓存；配置版本单调递增，新版本
应用后新请求立即使用不低于生效版本的规则；目标健康变化在同一版本内按确定顺序切换。

## 核心语义

### 分层覆盖与隔离
- 对 `(name, region, tenant)` 的解析，取最具体的已生效规则：`tenant > region > global`。
- 缓存键就是 `(name, region, tenant)` 三元组，一个区域/租户的答案在物理上是另一条
  缓存项，不可能被泄露给其他区域或租户；无租户规则的租户只会回落到区域/全局规则，
  绝不会命中别的租户的规则。

### 版本与缓存
- 配置以 `version` 单调递增的 bundle 全量下发；`version <= 当前版本` 被拒绝（HTTP 409）。
- 每条规则带 `rule_version`（最后变更它的配置版本）与 `effective_from`（生效时间，
  可未来定时）。定时规则与当前生效规则并存，到点自动激活。
- 缓存项记录产生它的规则指纹与目标健康签名。以下情况缓存项立即失效并记入审计：
  - 配置应用后该名字的有效规则发生变化（`config_applied` / `rule_version_changed`）；
  - 规则目标的健岩集合发生变化（`health_changed`）；
  - 手工 `POST /v1/cache/flush`（`manual_flush`）。
- 未受影响的名字的缓存项继续服务直到 TTL 过期——“已发出的旧答案可以用到过期”。
- 正答案按规则 `ttl` 缓存；不存在的名字按 `negative_ttl`（规则级优先，否则全局默认）
  缓存。缓存过期时间会被钳制到下一次定时规则切换点，保证定时激活立即被新请求看到。

### 确定性切换与多节点收敛
- 目标排序使用加权 rendezvous 哈希（HRW，指数竞争形式）：排序是
  `(客户端键, 目标集合, 权重)` 的纯函数，权重决定首选概率。
- 目标失去健康时，沿该确定顺序取下一个健康目标——同一配置版本内完成切换，无需改配置。
- 所有节点对相同目标跑相同的健康检查（间隔/阈值一致），健康视图在有界时间内收敛；
  选择是纯函数，因此恢复后各节点必然回到同一个确定性答案，不会长期分叉。
- 全部目标不健康时按 fail-open 返回确定性的降级答案（`degraded: true`）。

### 解析限流档位（rate limit tiers）
- 管理员可在 bundle 的 `rate_limit_tiers` 中定义多个限流档位。每个档位包含作用域
  （全局/区域/租户）、匹配标签 `match_labels`（请求标签必须包含全部相等的键值）、
  每秒令牌补充额度 `rate_per_second`、突发容量 `burst` 和优先级 `priority`
  （同一层级数值小者优先）。
- 每次解析只选择 **一个** 档位：先查租户层，再查区域层，最后全局层；在第一个存在
  匹配档位的层级中选择最高优先级匹配项。没有匹配档位时不限流。
- 令牌桶按 `(tier_id, client_key, tenant, 规范化标签签名)` 隔离；同一客户端在不同
  租户或携带不同标签时使用不同桶。区域不单独进入签名，因为选中的 `tier_id` 已唯一
  标识其作用域。
- 令牌在进入规则/灰度/缓存计算前扣减，因此**缓存命中也消耗额度**。超出额度时请求返回
  `429 Too Many Requests`，响应头带非零整数 `Retry-After`，响应体包含 `retry_after`、
  命中档位、剩余令牌与拒绝原因；被拒绝请求不会读取解析缓存作为答案，也不会写入新缓存。
- 应用任何新配置版本都会立即清空并替换旧桶；限流档位增删改同时记录策略变更与桶重置。
  审计类型包括 `rate_limit_change`、`rate_limit_rejected`、`rate_limit_bucket_reset`。
- 配置校验明确拒绝：非正数或负的每秒额度、非正数突发容量、`burst < rate_per_second`、
  非有限值、重复档位 ID、作用域字段不匹配、同一作用域层内相同优先级且标签条件相容
  （包括完全重复标签；互斥标签不冲突）。
- `GET /v1/explain` 不消耗令牌，其 `rate_limit` 段显示是否启用、命中档位、额度/突发、
  当前剩余令牌、桶签名以及拒绝原因和按当前令牌数计算出的 `retry_after`。

### 灰度发布组（release groups）
- 管理员可为某个名字在全局/区域/租户层配置多个带条件的发布组，每组包含：
  匹配标签 `match_labels`（全部相等才匹配，子集匹配）、流量百分比 `percent`（0–100）、
  时间窗口 `[window_start, window_end)`、优先级 `priority`（数值小者优先）与目标集合。
- 解析请求可携带标签（`labels=env=canary,team=pay`）。对请求可见（作用域匹配）、
  窗口激活且标签匹配的组中，**只命中优先级最高的一个**；随后按百分比决定是否落到
  该组的目标集合，未命中、窗口未开始或标签不匹配时回退到原规则。
- 百分比分桶是 `(配置版本, 组指纹, 客户端键)` 的纯函数，组指纹覆盖窗口、标签条件、
  百分比与目标集合——因此配置版本、时间窗口、标签匹配和百分比全部参与确定性选择：
  同一 client 在窗口内重复请求保持同一发布组；窗口切换或规则变更后新请求立即使用
  新组，旧缓存不会串用（缓存键含标签签名，条目记录灰度令牌并在窗口边界截断 TTL，
  配置应用时按条目保存的标签重算并失效）。
- 配置校验明确拒绝：百分比越界（0–100 之外）、非法窗口（`window_end <= window_start`
  或非有限值）、同名组 id 重复、同名且同作用域层（全局/同一区域/同一租户）的重叠窗口
  （无论标签条件是否相同、优先级是否相同）、同优先级且标签条件相容
  （可能匹配同一客户端）的重叠窗口、空目标集合、`rule_version` 超过 bundle 版本。
- `GET /v1/explain` 的 `release` 段显示命中/未命中原因
  （`hit` / `percentage_miss` / `labels_mismatch` / `window_inactive` /
  `no_visible_groups` / `no_groups`）、命中组详情、分桶值与候选组评估过程。
- 审计新增：`release_group_change`（组增删改，含新旧内容）、`release_group_hit`
  （命中，含分桶、百分比、窗口、标签）、缓存失效记录携带 `group_id`，
  灰度决策变化导致的失效原因为 `release_group_changed`。

## 解析用量计量与预算告警

每次解析（缓存命中也不例外）在通过限流与预算闸门后产生**一条可重放的用量事件**，
全部落 SQLite，重启后明细、聚合、预算状态与未确认告警都保持。

### 事件、幂等与事件时间归档
- 事件字段：`event_id`、`event_time`（事件时间）、`recorded_at`（录入时间）、
  租户、客户端、名字、区域、标签签名、**生效规则作用域**（实际产出答案的规则所在层，
  可能比请求的租户层更宽）、`rule_version`/`group_id`/`config_version`、结果
  （`served`/`budget_degraded`/`budget_rejected`）、计费量与来源（`live`/`backfill`）。
- 事件写入按 `event_id` 幂等：数据面可用 `X-Request-Id` 头携带客户端事件键，
  不带时服务端生成；同键重试重放原事件、**绝不重复计费**。
- 明细按 **event_time** 归档（不是入库时间），并在同一笔立即事务里增量折叠进
  日/月聚合行（UTC 对齐边界，按 租户×客户端×规则作用域 细分）。乱序、迟到事件
  落入其事件时间所属的周期；`POST /v1/metering/recompute` 以不可变明细为唯一事实源
  重建受影响聚合，重算后明细与所有聚合严格一致。
- 在线事件的 `event_time` 不允许显著超前于服务端时钟（默认 60s，防未来时间污染）；
  补录事件只受有限值校验。

### 预算、阈值与超预算策略
- 管理员用 `PUT /v1/budgets/{tenant}` 为租户设置：周期 `day`/`month`（UTC 边界，
  跨周期自动重置）、预算量 `amount`、阈值列表 `alert_thresholds`（预算的比例，如
  `0.8`/`1.0`）、超预算策略 `over_policy`：
  - `allow`：照常服务，仅计量（响应预算段 `reason=over_budget_allow`）；
  - `degrade`：照常计算但答案带 `degraded: true` 与 `degrade_reasons:[budget_exceeded]`，
    仍按一单位计量，结果记为 `budget_degraded`；
  - `reject`：在读取/写入解析缓存**之前**拒绝，HTTP **402**，响应体含可解释的预算段
    （周期、已用、余量、策略、未确认告警）；拒绝本身归档一条 **0 计费量**的
    `budget_rejected` 事件，使拒绝也可重放、可解释，且不消耗预算。
- 闸门投影"当前用量 + 本次一单位"，因此恰好在用尽的那次请求被拒。`GET /v1/explain`
  返回同样的投影但**不计量、不产生任何事件**。
- 每越过一个阈值，在 `(租户, 周期, 阈值)` 上恰好生成一条 `open` 审计告警（唯一约束
  加进程锁保证 exactly-once）；迟到/补录事件把历史周期推过阈值时补记 **retroactive**
  告警，重算也只补缺、从不删除已有告警。告警用 `POST .../acknowledge` 确认，
  未确认告警跨重启保持。

### 租户组继承与临时覆盖
- **预算组**（budget group）用 `POST /v1/budget-groups?group_id=` 创建，可携带默认
  预算四元组（周期、预算量、阈值、超预算策略）；`parent_id` 指向父组时本组可不定义
  策略而沿父链继承。组链必须无环，自环/成环的创建与修改返回 **409** 并写
  `budget_policy_denied`。组的每次变更自增 `version` 并把全量状态归档进
  `budget_group_revisions`，供历史周期回溯。
- 租户用 `POST /v1/budget-groups/{id}/members?tenant=` 加入或迁入某组
  （`DELETE /v1/budget-groups/members/{tenant}` 移出）。成员行带独立 `version`，
  迁移支持 `expected_version`：并发迁移同一租户时只有一方成功，另一方得到 **409**
  （`concurrent_migration`，并审计）。成员关系的每次变迁都追加一条
  `budget_group_membership_history` 区间，记录该租户在任意历史时刻属于哪个组。
- **策略解析链**（高优先级在前）：生效中的临时覆盖 → 租户专属预算 → 所属组默认策略
  （含沿父链继承）。解析结果（`GET /v1/budgets/{tenant}/resolved`、闸门响应的
  `budget.policy_origin`、预算查询）都给出 `source`（`override`/`tenant`/`group`）、
  `source_id`、`source_version`，组继承时还区分 `group_id`（实际定义策略的组）与
  `member_group_id`（租户直接所属组）。
- 组策略变更、成员迁移、覆盖批准或撤销都在进程锁下实时计算，**下一个解析请求立即**
  按新策略执行（无缓存）。
- **临时覆盖**：租户管理员用 `POST /v1/budgets/{tenant}/overrides` 申请一段带
  `[window_start, window_end)` 时间窗的覆盖；覆盖在另一名持有该租户 `budget:write`
  的管理员 `.../approve` 之前完全无效（申请人不能审批自己的请求，违反返回 409 并写
  `self_approval` 审计）。窗口已结束的申请/批准被拒绝；两个未终结覆盖的窗口不得重叠
  （409，`window_overlap`）。批准后可由申请人或授权管理员 `.../revoke` 立即撤销；
  窗口到期由惰性过期处理（状态翻为 `expired` 并审计），到期/终结后不再参与解析。
- **历史周期快照**：每个 `(租户, 周期)` 首次观测时在 `budget_policy_snapshots`
  记录实际采用的策略来源与版本。仍在开放的周期跟随当前链（每次事件刷新来源/版本）；
  周期关闭后的第一次观测按**周期关闭边界**回溯当时有效的成员关系、组修订与覆盖并
  **冻结**，此后组变更、成员迁移或覆盖撤销都不会改写历史周期的告警/重算。
  `GET /v1/budgets/{tenant}?at=<epoch>` 返回该历史时刻的解析（优先使用冻结快照）。
- 跨作用域修改（租户管理员建组/迁成员/改其它租户的覆盖）在授权层直接 **403**；
  所有语义拒绝（成环、覆盖到期、跨作用域状态写、并发迁移、自审批）都写
  `budget_policy_denied` 审计。

### 计费争议单与预算调整（budget disputes）

管理员可针对**某租户的指定周期**创建一笔计费争议单，引用一条或多条不可变用量
事件，填写争议原因与需要调整的**带符号计费量**（负为核减、正为补收）。状态机：
`draft → pending_review → approved → applied`，另可 `→ rejected`；
`draft/pending_review/approved` 以及开放周期内**已应用**的争议单可 `revoked`，
`rejected` 为终态，关闭周期的 retroactive 调整不可撤销。

- **提交即冻结**（`draft → pending_review`，或创建时 `submit:true`）：在同一事务
  内冻结引用事件的**完整清单**（按提交顺序）、该周期的**原始聚合**（按
  租户×客户端×规则作用域的明细单元与总量）以及**当前预算策略来源与版本**
  （override/tenant/group、source_id、source_version）。冻结后迟到事件、组变更、
  成员迁移或覆盖撤销都不会改写该单的冻结内容；**原始用量事件永不被修改**。
- **职责分离**：争议单必须由**另一名**持有该租户 `budget:write` 的管理员批准/驳回，
  创建人不能审批自己的单（409，`self_approval` 审计）。批准、驳回、应用、撤销均支持
  `expected_version` 乐观并发与 `Idempotency-Key`：并发操作由进程锁与 SQLite
  事务串行化、条件更新兜底，**只有一方成功**；幂等键重复提交只重放原结果
  （`idempotent_replay:true`，不重复写版本/审计/调整记录），同键不同载荷 409。
- **应用是一个事务**：写入不可变的 `budget_adjustments` 调整记录（带符号量、
  原始/调整后用量、策略来源），更新该周期的预算投影
  `budget_usage_projections`，并按调整后投影重新判断阈值告警——已有告警
  **只补缺、从不删除或改写**。应用后开放周期的**下一个解析请求立即**按新投影执行；
  闸门响应与 `explain` 同时给出 `raw_used`、`normal_adjustment` 与投影后 `used`。
- **关闭周期只能做 retroactive 调整**：提交/应用时若周期已关闭而未声明
  `retroactive`，或开放周期却声明 `retroactive`，都明确拒绝（409，
  `frozen_period` / `period_open`）。retroactive 调整只向不可变账本与审计追加
  一笔**可追溯**记录，**不改变**该周期的预算投影、原告警事实或冻结策略快照；
  视图以 `retroactive_adjustment` 与 `adjusted_including_retroactive` 单独呈现。
  开放周期应用的普通调整在周期关闭后也不能再撤销（会改写冻结事实）。
- **明确拒绝并保留拒绝审计**（`budget_policy_denied`，动作
  `dispute_submit/decide/apply/revoke`）：引用不存在（`unknown_event`）、
  跨租户引用（`cross_tenant_event`）、同单重复引用（`duplicate_event`）、
  事件不属于争议周期（`event_wrong_period`）、调整后用量为负
  （`negative_usage`）、操作已冻结的历史快照（`frozen_period`）、
  状态机不符（`status_conflict_*`）。版本不符返回 409
  （`expected_version`）。
- **持久化与历史**：争议单、审批关系（`created_by`/`submitted_by`/`decided_by`/
  `applied_by`/`revoked_by` 与时间戳）、不可变调整账本、版本冲突结果与追加式
  生命周期事件流 `budget_dispute_events` 全部落 SQLite，重启后状态、版本、审计
  顺序保持一致；列表与历史接口支持按 `since/until`（创建/事件时间）时间窗查询。
- 审计类型 `budget_dispute`（created/submitted/approved/rejected/applied/revoked）；
  拒绝写入既有 `budget_policy_denied`。重算（recompute）以明细重建聚合后会以
  账本为准确保投影重新收敛。

### 并发、权限与审计
- 预算行、预算组、成员关系、临时覆盖、预算争议单与告警行均带单调 `version`，写接口支持
  `expected_version` 乐观并发（冲突 409）；
- 所有写接口支持 `Idempotency-Key`：首个响应持久化，重复提交重放（不重复写事件/审计/
  版本），同键不同载荷 409；同内容预算 PUT 是无变化 no-op，重复确认返回 `changed:false`。
- 权限动作：`metering:read`（明细/聚合查看）、`metering:backfill`（补录，须覆盖全部
  涉及租户）、`metering:recompute`（重算，全量仅全局作用域）、`budget:read`、
  `budget:write`。作用域与规则同构（global ⊇ region ⊇ tenant）：区域管理员可管理
  任意租户预算、审批/撤销该租户的临时覆盖；预算组与成员迁移属于跨租户资源，仅
  **全局** `budget:write` 可操作（且迁成员还须覆盖该租户）；租户管理员不能越权到
  其它租户/区域/全局；列表类接口按授权作用域过滤。
- 审计类型：`usage_event`（每条事件，含结果/计费量/事件时间/来源/触发告警/解析所用
  策略来源与版本）、`usage_backfill`、`usage_recompute`、`budget_change`（新旧值与
  版本）、`budget_alert`（fired/acknowledged，含阈值、用量、周期、是否 retroactive、
  触发时的 `policy_origin`、操作人）、`budget_group`、`budget_membership`、
  `budget_override`（requested/approved/rejected/revoked/expired）、
  `budget_dispute`（created/submitted/approved/rejected/applied/revoked）、
  `budget_resolution`（每次真实解析所采用的来源/版本与闸门裁决）以及
  `budget_policy_denied`（成环继承、窗口到期/重叠、自审批、并发迁移、争议单
  冻结/跨租户/负用量等语义拒绝）。

## 配置变更管理：预演、历史与回滚

### 预演（dry-run）
- `POST /v1/config/preview`（回滚对应 `POST /v1/config/rollback/preview`）按与正式应用
  **完全相同**的流程计算：bundle 校验、未来定时规则合并、规则/发布组/限流档位差异、
  灰度选择影响、将被失效的缓存条目（按规则指纹与灰度令牌逐条判定）、限流策略指纹变化与
  将重置的桶数量。
- 预演**不写任何正式状态**：生效配置、解析缓存、限流桶、SQLite 版本表和审计日志都保持
  不变。预演令牌仅保存在内存中，默认 300 秒过期（`GEORESOLVE_PREVIEW_TTL`）。
- 响应包含：`base_version`、`proposed_version`、内容指纹、差异计数、影响（`impact`）、
  完整版本摘要（`summary`：受影响名字、每条规则/发布组/限流档位的新旧值）和一次性
  `preview_token`。请求体省略 `version` 时默认取“当前版本 + 1”。
- `POST /v1/config` / `POST /v1/config/rollback` 可携带 `preview_token`；服务端校验：
  - 令牌过期 → **410 Gone**（预演结果过期，请重新预演）；
  - 令牌已被使用或未知 → **409**；
  - 预演基线版本与当前版本不一致（期间有别的提交）→ **409**（预演已过时）；
  - 提交内容指纹/目标版本/预演种类（apply vs rollback）不匹配 → **409**。
- 不带 `preview_token` 的提交行为与以前一致（仍然做全部校验和版本单调性检查）。

### 版本历史
- 每次正式应用都会在 `config_versions` 中持久化版本载荷与可查询摘要。摘要至少包含：
  - `affected_names`：受影响的名字（规则增删改、发布组增删改涉及的名字并集）；
  - `rule_diffs`：每条规则的动作（added/updated/removed）、作用域、新旧 `rule_version`
    与目标 ID；
  - `release_group_diffs`：发布组的动作、优先级、百分比、标签、目标集合新旧值；
  - `rate_limit_tier_diffs`：限流档位的动作、作用域、`rate_per_second`/`burst` 新旧值；
  - `impact`：实际失效缓存条目数（规则变化/灰度变化分项）、限流桶重置数与策略是否变化；
  - `base_version`、内容指纹与（回滚产生时）`rollback_of`。
- `GET /v1/config/versions` 返回摘要列表（不含完整载荷），
  `GET /v1/config/versions/{v}` 返回单个版本的摘要、差异与完整 bundle（`?payload=false`
  可省略载荷）。升级前创建的数据库自动迁移出 `summary` 列，旧版本的差异为空。

### 安全回滚
- `POST /v1/config/rollback`（体 `{"version": N}`）取回已保存版本 N 的**全量**载荷，
  将其头部版本重写为**全新的、严格更高的版本号**（默认当前 + 1，也可显式给
  `new_version`，仍必须高于当前版本），然后复用普通应用的同一条提交管线：
  Pydantic 校验 → 差异计算 → 持久化（版本表，带 `rollback_of=N` 摘要）→ 内存生效 →
  缓存选择性失效 → 限流桶重置 → 审计（`rule_change`/`release_group_change`/
  `rate_limit_change`/`config_applied` 外加一条 `config_rollback`）。
- 明确拒绝：
  - 版本 N 不存在 → **404**；
  - N 就是当前版本 → **409**（回滚目标与当前版本相同）；
  - N 的内容指纹与当前生效配置完全相同 → **409**（回滚不会带来任何变化）；
  - `new_version <= 当前版本`、预演令牌过期/过时/不匹配 → 相应 4xx。
- 回滚后历史中出现的是一个**新版本**（可继续回滚、可再次回滚到任意历史版本）；
  因为内容指纹相同而无变化的重复回滚会被拒绝。

### 并发提交
- 进程内由配置管理器的锁串行化；跨节点/进程由 SQLite 版本主键兜底：相同版本号的第二个
  提交者得到 **409**，且因为先持久化后生效，失败方的内存配置与缓存不会被半应用状态污染。
- 客户端可带 `expected_version` 做乐观并发控制：仅当当前版本等于该值时才提交，否则
  **409**，从而保证并发提交不会覆盖较新的版本。

## 多租户管理员委托与作用域授权

控制面支持多套管理员身份：每个身份（identity）持有自己的 Bearer 令牌并挂载若干角色
（role），角色是 `(action, scope)` 权限的集合。身份、角色、令牌哈希、幂等键与授权版本
全部落 SQLite 持久化，重启后继续有效。

### 作用域链与继承

授权作用域与规则作用域同构，形成委托链 **global ⊇ region(r) ⊇ tenant(t)**：

- **global** 授权覆盖一切资源；
- **region(r)** 授权覆盖本区域资源，并**继承**全部租户级资源（租户规则本身与区域无关，
  因此租户管理经区域管理员委托下放）；
- **tenant(t)** 授权只覆盖本租户，是链的叶子——**禁止把租户权限扩大到区域或全局**。

委托约束：`admin:manage` 调用者只能创建/修改/指派**自己授权作用域完全覆盖**的角色与身份
（新旧权限集合都受检），因此租户管理员不可能为自己或他人铸造区域/全局权限，越权委托
返回 **403**。

### 动作与控制面授权

动作集合：`config:read`、`config:write`、`versions:read`、`cache:read`、`cache:flush`、
`health:read`、`health:write`、`audit:read`、`admin:manage`、
`metering:read`、`metering:backfill`、`metering:recompute`、
`budget:read`、`budget:write`、`drill:read`、`drill:write`。每个控制面请求先认证
（失败 **401**），再按动作与资源作用域授权（越权 **403**，且授权在任何变更之前完成，
**被拒绝的请求不会产生配置或缓存副作用**）。允许与拒绝都写入审计
（`authz_decision` / `authz_denied`）。

- `POST /v1/config`（含 preview）：全局调用者照旧全量应用；作用域调用者提交的 bundle 里
  **每一项都必须被其作用域覆盖**（否则 403），随后按**作用域合并**应用——只替换自己
  作用域内的规则/发布组/限流档位，域外项（含定时规则）原样保留，`defaults` 仅全局
  调用者可改。版本号仍在全局单调递增，`expected_version`/`preview_token` 语义不变。
- `GET /v1/config`、`GET /v1/cache`、`GET /v1/health/targets`：按调用者作用域过滤输出。
- `POST /v1/cache/flush`：只清调用者作用域内的缓存项（区域授权清本区域答案，租户授权
  清本租户答案，全局清全部），审计记录清理作用域。
- `POST /v1/health/targets/{id}`（`{"healthy": bool}`）：手工健康覆盖。仅当**所有**引用
  该目标的规则/发布组都在调用者作用域内时允许（否则 403，无副作用），写 `health_change`
  审计（含操作身份）。
- `GET /v1/config/versions*`：版本摘要的差异与 payload 按 `versions:read` 作用域过滤。
- 回滚会重写全局状态，因此仅 **global** 作用域的 `config:write` 可用。
- `GET /v1/audit`：全局调用者看全部；作用域调用者看到与自身相关的记录及其作用域覆盖的
  记录。

### 身份生命周期、版本与幂等

- 创建身份时返回一次明文令牌（只存 SHA-256 哈希，之后任何接口不再回显）；
  `PUT /v1/admin/identities/{id}` 可整体替换角色或 `rotate_token` 轮换令牌——
  **旧令牌立即失效**（下一次请求即 401）；`POST .../deactivate` 停用**立即生效**，
  `.../reactivate` 恢复。
- 每次角色/身份变更使全局 `authz_version` 单调递增并提升实体的
  `role_version`/`identity_version`；更新可带 `expected_version` 做乐观并发（冲突 409），
  并发提交由锁串行化、唯一约束兜底。
- 所有管理写接口接受 `Idempotency-Key` 头：首个响应被持久化，相同键的重复提交**重放**
  原响应（`idempotent_replay: true`，不重复递增版本、不重复写审计）；同键不同载荷
  返回 **409**。停用/启用本身也是天然幂等的（重复调用返回 `changed: false`，不产生
  额外版本或审计）。
- 角色仍被身份引用时不可删除（409）；所有身份/角色变更写 `identity_change` /
  `role_change` 审计（含操作者与 `authz_version`）。

### 临时应急授权（emergency grants）

应急授权是一个身份的**临时权限提升**，走"申请 → 审批 → 生效 → 到期/撤销"流程：

- **申请**：任何已认证身份都可以为自己或另一个身份提交
  `POST /v1/admin/emergency-grants`，携带原因 `reason`、权限集合 `permissions`
  （与角色相同的 `(action, scope)` 形式）、有效时长 `duration_seconds`。
  申请本身不授予任何权限，`pending` 状态的授权不参与权限计算。
- **审批**：另一名持有 `admin:manage` 的管理员调用 `.../approve` 或 `.../reject`。
  **审批人不能审批自己的申请**（403）；被批准的权限必须完全落在审批人
  `admin:manage` 的**可委托范围**内（否则 403）——租户管理员无法批准区域/全局的
  提权。有效期从**批准时刻**起算（`expires_at = approved_at + duration_seconds`）。
- **生效**：授权在`approved` 且未到期时，于**每一次控制面请求**并入该身份的权限
  计算——配置读写、缓存清理、健康操作、版本查询等全部按授权的作用域执行，
  与角色权限完全同构；授权决定审计（`authz_decision`）会带上生效中的授权 ID。
- **失效**：到期与撤销都**立即生效**——权限按请求实时计算、从不烘进令牌，因此
  过期或被撤销后，同一令牌的下一次请求即失去该权限（403）。过期采用惰性判定：
  任何请求或查询首次发现过期时完成状态迁移、持久化并写审计。
- **状态机**：`pending → approved / rejected`，`approved → revoked / expired`。
  终态不可再写：重复审批、审批已拒绝的授权、撤销未生效或**已过期**的授权都返回
  **409**；并发审批/撤销由锁串行化，只有一个成功，其余 409。`approve`/`reject`/
  `revoke` 支持 `expected_version` 乐观并发。
- **持久化与审计**：`requested` / `approved` / `rejected` / `revoked` / `expired`
  全部落 SQLite（重启后状态继续有效）并写 `emergency_grant` 审计（含申请人、
  审批人、原因、权限、作用域、到期时间与 `authz_version`）；四个写接口都支持
  `Idempotency-Key` 幂等重放。
- **可见性**：申请人、受权身份本人、以及 `admin:manage` 覆盖该授权作用域的管理员
  可以在 `GET /v1/admin/emergency-grants*` 看到授权；撤销可以由受权身份、申请人
  或覆盖作用域的管理员发起。

### 认证模式与兼容

- 设置了 `GEORESOLVE_ADMIN_TOKEN`：该令牌作为内置全局 **bootstrap** 调用者，既有部署
  行为不变；身份令牌与 bootstrap 令牌可同时使用。
- 未设置令牌且没有任何身份：控制面保持开放（开发模式）；**一旦创建第一个身份即强制
  认证**，匿名请求得到 401。

## 隔离故障演练与解析回放（fault drills）

管理员可针对**某个已保存配置版本**创建故障演练，冻结创建时刻的目标清单、规则摘要
与客户端请求序列，然后一步步在**私有空间**里重放真实解析逻辑。

### 创建即冻结
- `POST /v1/drills`（体含 `config_version`、`steps[]`、可选 `initial_health`、
  `drill_id`、`description`）。创建时从 `config_versions` 取回该版本的**全量 bundle**
  并冻结：配置版本与完整载荷、**目标清单**（该版本所有规则/发布组引用的目标 id，去重）、
  **规则摘要**（按 `(name, scope, region, tenant)` 的规则/发布组/限流档位摘要）、
  有序编号的**客户端请求序列**、初始模拟健康集合（线上健康视图叠加调用方覆盖）与固定的
  模拟时钟锚点。
- 明确拒绝（均写**演练审计** `drill_audit`，不创建可用演练）：配置版本不存在
  （**404** `config_version_not_found`）、步骤健康变化或初始健康引用的目标不在冻结清单
  （409 `target_not_in_frozen_manifest`）、健康值非法（409 `illegal_health_change`）、
  空步骤序列（422）。

### 严格隔离（绝不触碰线上）
- 每一步用**生产 `Resolver`** 跑，但协作者全部私有：由冻结 bundle 重建的
  `Snapshot`（绝不读线上 ConfigManager）、演练私有模拟健康注册表、模拟时钟上的演练私有
  `ResolutionCache`；**不挂限流、不挂计量**（不扣令牌、不产生用量事件、不跑预算闸门）。
- 重放内部审计（`release_group_hit`/缓存失效）进 **null 审计**丢弃；演练生命周期与拒绝
  事件进独立的 `drill_audit` 表（**绝不写真实 `audit`**）。
- 因此演练可以任意改健康、老化缓存、重复回放，线上健康视图、解析缓存、限流桶与真实审计
  都不受影响；不同演练之间状态也互不串用。

### 步骤推进与生命周期
- 状态机：`ready → running ⇄ paused → completed`。创建为 `ready`；`resume` 启动
  （`ready → running`，也是暂停后的继续），`pause` 挂起，推进到最后一步转 `completed`。
- `POST /v1/drills/{id}/advance`（体可选 `seq`、`expected_version`）按序推进下一步；
  步骤在创建时冻结，每步可指定 `health_changes`（推进前施加的目标健康变化）、请求参数
  （name/region/tenant/client/labels）与 `expected`（预期 `chosen`/`status`/`order`/
  `degraded`）以及模拟时间（绝对 `at` 或相对上一步的 `advance_seconds`，缺省用创建锚点，
  保证回放确定）。
- 每步记录：`started_at`（墙钟开始时间）、`input`（请求、推进前健康、缓存键等输入快照）、
  `health_after`（模拟后的完整健康集合）、`answer`（解析结果）、`order`（目标排序）、
  `cache_hit`（是否命中**模拟**缓存）、`expected`、`matched_expected`、`diffs` 与
  `diff_reasons`（与预期的逐字段差异原因）。
- 明确拒绝并写演练审计：步骤序号跳跃（409 `step_sequence_gap`）、暂停/完成态推进
  （409 `status_conflict`）、`expected_version` 不符（409 `expected_version`）。
  失败的推进**不占用**步骤号，修正后可按同一序号重试。
- `POST .../pause`、`.../resume`、`.../reset`：重置清空已记录步骤、模拟缓存与报告，
  以**新的 run epoch** 回到 `ready`，上一 epoch 的幂等键不再能重放旧结果。
- 步骤推进/暂停/恢复/重置均支持 `expected_version` 乐观并发与 `Idempotency-Key`：
  幂等键按 `(演练, run_epoch)` 隔离，重复提交只重放同一结果（`idempotent_replay:true`，
  不重复写步骤/版本/审计），同键不同载荷 409；并发推进同一步骤在锁与状态机下只有一方成功。

### 只读报告
- `POST /v1/drills/{id}/report`（读权限即可）：报告内容在每个 run 内**只生成一次**，
  此后重复生成只返回同一份内容与同一 `checksum`（blake2b，`idempotent_replay:true`）。
- 报告固定**创建时的演练快照**（目标清单、规则/发布组/限流摘要），逐步给出预期与实际
  选择、命中缓存与否、模拟健康，并以 `first_diff` 指出**首个**差异步骤；reset 后重新
  生成全新 run 的报告。

### 持久化
- 演练、步骤结果、独立演练审计、演练级幂等与报告全部落 SQLite；服务重启后演练状态、
  步骤结果、版本冲突判定、报告校验值与审计追加顺序保持一致。

### 接口
- 演练冻结的是**全量配置快照**，因此 `drill:read`/`drill:write` 仅 **global** 作用域可用
  （region/tenant 授权 403）。

| 方法/路径 | 说明 |
|---|---|
| `POST /v1/drills` | 创建演练（冻结版本/清单/规则摘要/请求序列），201 |
| `GET /v1/drills?status=&config_version=&limit=` | 演练列表 |
| `GET /v1/drills/{id}` | 演练详情（冻结内容、当前健康、本 run 步骤与模拟缓存） |
| `POST /v1/drills/{id}/advance` | 推进下一步（`seq`/`expected_version`，支持幂等键） |
| `POST /v1/drills/{id}/pause` / `.../resume` / `.../reset` | 暂停 / 恢复 / 重新开始（支持幂等键） |
| `GET /v1/drills/{id}/steps/{seq}` | 按步骤号查询单步结果 |
| `POST /v1/drills/{id}/report` | 只读报告（每个 run 固定一份，带 checksum） |
| `GET /v1/drills-audit?drill_id=&action=&since=&limit=` | 独立演练审计（与真实 `audit` 分离） |

## 可复用演练计划、独立运行与分支（drill plans / runs / branches）

管理员可把一个**已完成**的演练（或直接用已保存配置版本加步骤序列）保存为**命名计划**，
之后从同一计划创建多次**完全独立**的运行，并可从运行中已完成的某一步**创建分支**。

### 计划即冻结
- `POST /v1/drill-plans`（体含 `name`、`source_drill_id`，或 `config_version`+`steps[]`，
  可选 `plan_id`、`description`、`initial_health`、`expected_version`，支持幂等键）。
  源演练未完成时 409 `drill_not_completed`。
- 计划冻结：配置版本与完整 bundle、目标清单、规则/发布组/限流摘要、**逐步的请求输入与
  预期结果**，以及所有运行共享的固定模拟时钟锚点（保证同计划不同运行可确定性对比）。
- 计划不可变；唯一后续生命周期是归档（`POST /v1/drill-plans/{id}/archive`，支持
  `expected_version` 与幂等键）。**已归档计划不能再创建运行**（409 `plan_archived`），
  已存在的运行仍可推进。
- 计划版本为乐观并发令牌：归档与每次创建运行都会 bump；并发修改只有一方成功。

### 多次独立运行
- `POST /v1/drill-plans/{id}/runs`（体可选 `run_id`、`owner_id`（缺省为调用身份）、
  `note`、计划级 `expected_version`，支持幂等键）为每次运行分配**独立的**生命周期状态、
  模拟健康注册表、模拟时钟缓存、逐步结果、运行版本与 reset epoch。
- 运行之间**不共享**健康状态、缓存、步骤结果或生命周期：推进/暂停/重置/报告一个运行
  绝不改变另一个运行、计划或任何分支。
- 运行支持与演练一致的 `advance`/`pause`/`resume`/`reset`（运行级 `expected_version`
  与按 `(运行, run_epoch)` 隔离的幂等键）、单步查询和每运行一份的只读报告。
- **负责人隔离**：非全局管理员身份只能读取或操作 `owner_id` 为自己的运行（越权 403
  `owner_mismatch`，审计留痕），列表自动按负责人过滤；可显式 `?owner_id=` 筛选。

### 分支
- `POST /v1/drill-runs/{id}/branches`（体含 `branch_point_seq` 与**替换尾部**步骤，
  可选新 `run_id`、`owner_id`、`note`、父运行级 `expected_version`，支持幂等键）。
- 分支只能从**已经完成（已记录）的某一步**创建（越界 409 `branch_point_invalid`，
  从最后一步分支 409 `branch_tail_length`；替换步骤数必须恰好等于分支点之后的步数，
  替换步骤按分支点后 1..n 编号）。
- 分支**只读继承**分支点及之前所有步骤的输入与结果（答案、排序、缓存命中、健康集合、
  以及该点完整的私有模拟缓存），之后的步骤可替换请求、健康变化与预期；分支是独立运行。
- 父运行之后的推进、暂停、重置或报告都**不能改变分支**（reset 分支只回退到分支点，
  继承前缀在新 epoch 中保持可见；reset 父运行也不触碰已独立的分支）。

### 只读比较报告
- `POST /v1/drill-runs/{id}/compare`（体含 `other_run_id`）生成**只读**比较报告。
- 报告固定**首次比较时两个运行的版本**，并按固定顺序指出**第一处**差异：
  `step_progress`（一方尚未记录该步）→ `step_input`（请求/标签/模拟时间）→
  `health_set`（健康集合）→ `resolution_order`（解析排序）→ `cache_hit`（缓存命中）→
  `expected_result`（预期结果）。
- **同一对运行只生成一份报告**：以无序运行对为键，重复生成（无论请求方向、之后运行
  是否继续推进）都重放同一内容与同一 `checksum`（`idempotent_replay:true`）。
- 仅同一计划下的运行可比较（409 `compare_plan_mismatch`）；双方运行都必须归当前负责人
  所有。

### 持久化与接口
- 计划、运行、步骤（含 `recorded`/`inherited` 两类）、运行关系、负责人、幂等记录、每运行
  报告与比较报告全部落 SQLite；重启后计划快照、运行关系、负责人权限、分支结果、版本冲突
  判定与报告校验值保持一致。
- 与演练相同，仅 **global** `drill:read`/`drill:write` 授权可用。

| 方法/路径 | 说明 |
|---|---|
| `POST /v1/drill-plans` | 从已完成演练或版本+序列创建命名冻结计划，201（支持幂等键） |
| `GET /v1/drill-plans?status=&config_version=&limit=` | 计划列表（含每计划 `run_count`） |
| `GET /v1/drill-plans/{id}` | 计划详情（冻结内容、步骤规格、初始健康） |
| `POST /v1/drill-plans/{id}/archive` | 归档计划（支持 `expected_version` 与幂等键） |
| `POST /v1/drill-plans/{id}/runs` | 创建独立运行（`owner_id`/`note`/计划级 `expected_version`，支持幂等键），201 |
| `GET /v1/drill-plans/{id}/runs?owner_id=&status=` | 该计划的运行列表（按负责人过滤） |
| `GET /v1/drill-runs?plan_id=&owner_id=&status=` | 跨计划运行列表/按负责人筛选 |
| `GET /v1/drill-runs/{id}` | 运行详情（仅负责人；含步骤、健康、模拟缓存） |
| `GET /v1/drill-runs/{id}/steps/{seq}` | 单步结果（含只读 `inherited` 标记） |
| `POST /v1/drill-runs/{id}/advance` | 推进下一步（支持 `expected_version` 与幂等键） |
| `POST /v1/drill-runs/{id}/pause` / `.../resume` / `.../reset` | 暂停 / 恢复 / 重置（分支重置回退到分支点） |
| `POST /v1/drill-runs/{id}/report` | 每运行只读报告（固定一份，带 checksum） |
| `POST /v1/drill-runs/{id}/branches` | 从已记录步骤创建分支（支持幂等键与 expected_version），201 |
| `POST /v1/drill-runs/{id}/compare` | 固定两运行版本的只读比较报告（每对唯一，带 checksum） |
| `GET /v1/drill-plans-audit?plan_id=&run_id=&action=&since=&limit=` | 计划/运行独立审计 |

## API

数据面（无需认证）：

| 接口 | 说明 |
|---|---|
| `GET /v1/resolve?name=&region=&tenant=&client=&labels=` | 解析名字，返回答案（含 `rule_version`、`release_group`、`chosen`、有序目标列表、TTL、`rate_limit`、`budget`、`event_id`）；限流返回 429/`Retry-After`，预算超支按策略返回 402 或带 `budget_exceeded` 降级标记；可带 `X-Request-Id` 作为用量事件幂等键；`labels` 形如 `env=canary,team=pay` |
| `GET /v1/explain?name=&region=&tenant=&client=&labels=` | 查询当前采用的规则版本、目标、生效时间、灰度命中与原因、限流档位/剩余额度/拒绝原因、**预算投影（只预测不计量）**、缓存状态、下次切换时间；不消耗限流令牌也不写用量事件 |
| `GET /healthz` | 存活探针 |

控制面（需认证：`Authorization: Bearer <token>`，令牌为身份令牌或
`GEORESOLVE_ADMIN_TOKEN`；所有请求按调用者身份与作用域授权，越权返回 403 且无副作用）：

| 接口 | 说明 |
|---|---|
| `GET /v1/config` | 当前配置快照，按 `config:read` 作用域过滤（版本、默认值、规则含定时版本、发布组、限流档位） |
| `POST /v1/config` | 应用新配置 bundle（版本必须递增）；作用域调用者按作用域合并应用；可带 `expected_version` 做乐观并发校验，可带 `preview_token` 只提交预演过的内容 |
| `POST /v1/config/preview` | 配置预演：跑完整校验/合并/差异/影响计算（规则、灰度组、缓存失效、限流桶），**不改变生效配置、缓存、限流桶或审计**，返回一次性、有时效的 `preview_token` |
| `GET /v1/config/versions?limit=` | 已保存版本列表与摘要，差异按 `versions:read` 作用域过滤 |
| `GET /v1/config/versions/{v}?payload=true` | 单个已保存版本：摘要、差异与（按作用域过滤的）bundle |
| `POST /v1/config/rollback` | 回滚到已保存版本：以其内容生成**更高的新版本**，走与普通应用相同的校验、缓存失效、桶重置与审计流程；可带 `expected_version`/`preview_token`；仅全局作用域 |
| `POST /v1/config/rollback/preview` | 回滚预演（不落任何变更）；仅全局作用域 |
| `GET /v1/audit?type=&limit=&since=` | 审计记录：`rule_change`、`release_group_change`、`release_group_hit`、`rate_limit_change`、`rate_limit_rejected`、`rate_limit_bucket_reset`、`cache_invalidation`、`health_change`、`config_applied`、`config_rollback`、`authz_decision`、`authz_denied`、`identity_change`、`role_change`、`emergency_grant`、`usage_event`、`usage_backfill`、`usage_recompute`、`budget_change`、`budget_alert`、`budget_dispute`（含拒绝时的 `budget_policy_denied`）；按 `audit:read` 作用域过滤（记录带 `tenant`/`scope`） |
| `GET /v1/health/targets` | 目标健康视图，按 `health:read` 作用域过滤 |
| `POST /v1/health/targets/{id}` | 手工健康覆盖（`{"healthy": bool}`）；要求目标的所有引用都在调用者 `health:write` 作用域内；写审计 |
| `GET /v1/cache` / `POST /v1/cache/flush` | 缓存查看（按 `cache:read` 过滤）/ 按 `cache:flush` 作用域清空（清空会记审计） |
| `GET /v1/metering/events?tenant=&client=&rule_scope=&start=&end=` | 按**事件时间**窗口查询可重放用量明细（每条含租户、客户端、名字、区域、生效规则作用域、结果、计费量、事件/录入时间）；按 `metering:read` 作用域授权与过滤 |
| `GET /v1/metering/aggregates?period=day\|month&tenant=&start=&end=&group_by_client=&group_by_scope=` | 日/月窗口聚合统计（事件数、计费量、served/degraded/rejected 分项），周期按 UTC 对齐事件时间 |
| `POST /v1/metering/backfill` | 事件补录：按各自 `event_time` 归档并折叠进聚合/告警，重复 `event_id` 跳过不重复计费；需 `metering:backfill` 覆盖全部涉及租户；支持 `Idempotency-Key` |
| `POST /v1/metering/recompute` | 以明细日志为唯一事实源重建窗口内聚合并对账阈值告警（迟到/乱序/漂移自愈，已有告警不删除，缺失穿越补记为 retroactive）；带租户时需覆盖该租户，全量重算仅全局作用域；支持 `Idempotency-Key` |
| `GET /v1/budgets` / `GET /v1/budgets/{tenant}` | 预算列表（按 `budget:read` 过滤）/ 单租户当前周期用量、余量、使用率、周期边界与未确认告警；后者可带 `at=<epoch>` 查询历史时刻解析（优先用冻结快照，返回 `policy_origin` 与 `frozen`） |
| `GET /v1/budgets/{tenant}/resolved` | 只解析生效策略：来源 `override/tenant/group`、`source_id`/`source_version`、所属组与覆盖窗口；可带 `at` 做历史回溯 |
| `PUT /v1/budgets/{tenant}` | 设置/替换租户预算（`period_type=day/month`、`amount`、`alert_thresholds`、`over_policy=allow/degrade/reject`、`expected_version`）；同内容 PUT 为无变化 no-op；需 `budget:write` 覆盖该租户；支持 `Idempotency-Key` |
| `DELETE /v1/budgets/{tenant}` | 删除租户预算（明细与历史告警保留） |
| `POST /v1/budget-groups?group_id=` / `GET /v1/budget-groups` / `GET /v1/budget-groups/{id}` | 创建预算组（默认策略四元组或 `parent_id` 继承；成环 409）/ 列表（含成员数，按授权过滤）/ 详情（含成员）；组写操作仅全局 `budget:write`，均支持 `expected_version` 与 `Idempotency-Key` |
| `PUT /v1/budget-groups/{id}` / `DELETE /v1/budget-groups/{id}` | 更新组策略/父组（自增版本并归档修订；同内容 no-op）/ 删除空组（有成员或子组时 409） |
| `POST /v1/budget-groups/{id}/members?tenant=` | 把租户加入或迁入该组（`expected_version` 乐观锁，并发迁移一方 409；需全局 `budget:write` 且覆盖该租户；支持幂等键） |
| `DELETE /v1/budget-groups/members/{tenant}?expected_version=` | 把租户移出组（关闭成员关系区间；同上授权） |
| `GET /v1/budget-groups/members/{tenant}/history` | 租户的组成员关系时间区间（迁移审计/历史回溯依据） |
| `POST /v1/budgets/{tenant}/overrides` | 申请临时覆盖（策略四元组 + `window_start/window_end` + `reason`）；需该租户 `budget:write`；窗口重叠或已结束返回 409；支持幂等键 |
| `GET /v1/budget-overrides?tenant=&status=` / `GET /v1/budget-overrides/{id}` | 覆盖列表（按授权过滤）/ 详情 |
| `POST /v1/budget-overrides/{id}/approve` / `.../reject` / `.../revoke` | 另一名覆盖该租户的 `budget:write` 管理员批准/拒绝（申请人不能自审批；支持 `comment`、`expected_version` 与幂等键）；批准后可撤销，立即恢复下层策略 |
| `GET /v1/budget-alerts?tenant=&status=open\|acknowledged&period=day\|month` | 预算告警列表（按 `budget:read` 过滤） |
| `POST /v1/budget-alerts/{id}/acknowledge` | 确认告警（`comment`、`expected_version`）；重复确认返回 `changed:false`；需 `budget:write` 覆盖该租户；支持 `Idempotency-Key` |
| `POST /v1/budget-disputes` | 创建计费争议单（`tenant`、`period_type=day\|month`、`period` 标签（缺省当前周期）、`event_ids`、`reason`、带符号 `adjustment_quantity`、`retroactive`、`submit`）；`submit:false` 存为草稿，`true` 立即冻结事件清单/原始聚合/策略来源版本并进待复核；需该租户 `budget:write`；支持幂等键 |
| `GET /v1/budget-disputes?tenant=&period_type=&period=&status=&since=&until=` | 争议单列表（按授权作用域过滤，时间窗按创建时间） |
| `GET /v1/budget-disputes/{id}` / `GET .../history?since=&until=` | 争议单详情（含冻结载荷）与追加式生命周期事件流（创建→提交→批准/驳回→应用→撤销） |
| `POST /v1/budget-disputes/{id}/submit` | 提交草稿（冻结引用/聚合/策略；关闭周期须 `retroactive:true`）；支持幂等键 |
| `POST /v1/budget-disputes/{id}/approve` / `.../reject` | 另一名持该租户 `budget:write` 的管理员批准/驳回（创建人自审批 409；`comment`、`expected_version`）；支持幂等键 |
| `POST /v1/budget-disputes/{id}/apply` | 应用已批准争议单：单事务写不可变调整记录、更新周期预算投影并重判阈值告警（开放周期立即生效；关闭周期仅当 `retroactive` 时只追加可追溯记录）；`expected_version` 与幂等键 |
| `POST /v1/budget-disputes/{id}/revoke` | 撤销草稿/待复核/已批准单，或冲回开放周期内已应用的调整（追加反向不可变记录并刷新投影；关闭周期 retroactive 调整不可撤销）；`reason`、`expected_version`、幂等键 |
| `GET /v1/budgets/{tenant}/adjustments?period_type=&period=&kind=normal\|retroactive` | 该租户周期的不可变调整账本 |
| `GET /v1/budgets/{tenant}/adjusted?period_type=&period=` | 按租户周期查看调整后预算：原始用量、正常/retroactive 调整净额、调整后用量、账本行与未终结争议 |

管理委托（需 `admin:manage`，写接口支持 `Idempotency-Key` 幂等重试）：

| 接口 | 说明 |
|---|---|
| `POST /v1/admin/roles` | 创建角色（权限作用域必须被调用者覆盖，否则 403） |
| `GET /v1/admin/roles` / `GET /v1/admin/roles/{id}` | 列出/查看角色（按委托可见性过滤） |
| `PUT /v1/admin/roles/{id}` | 更新角色权限/描述（`role_version` 递增，可带 `expected_version`） |
| `DELETE /v1/admin/roles/{id}` | 删除角色（仍被引用时 409） |
| `POST /v1/admin/identities` | 创建身份，明文令牌仅此一次返回 |
| `GET /v1/admin/identities` / `GET /v1/admin/identities/{id}` | 列出/查看身份（不含令牌哈希） |
| `PUT /v1/admin/identities/{id}` | 替换角色 / `rotate_token` 轮换令牌（旧令牌立即失效） |
| `POST /v1/admin/identities/{id}/deactivate` / `.../reactivate` | 停用（立即生效）/ 恢复；天然幂等 |

临时应急授权（申请 → 审批 → 生效 → 到期/撤销；写接口支持 `Idempotency-Key`）：

| 接口 | 说明 |
|---|---|
| `POST /v1/admin/emergency-grants` | 申请应急授权（`identity_id`、`reason`、`permissions`、`duration_seconds`）；任何已认证身份可申请，201 返回 `pending` 授权 |
| `GET /v1/admin/emergency-grants?status=&identity_id=` | 列出可见的授权（申请人/受权人/可委托管理员可见） |
| `GET /v1/admin/emergency-grants/{id}` | 查看单个授权（含 `active`、`remaining_seconds`） |
| `POST /v1/admin/emergency-grants/{id}/approve` / `.../reject` | 审批/拒绝：需 `admin:manage` 且授权权限不超出审批人可委托范围；不能审批自己的申请（403）；非 `pending` 状态返回 409；可带 `expected_version` |
| `POST /v1/admin/emergency-grants/{id}/revoke` | 撤销生效中的授权（受权人/申请人/可委托管理员）；立即失效；未生效或已过期返回 409 |

### 配置示例

```json
{
  "version": 2,
  "defaults": {"negative_ttl": 30},
  "rules": [
    {"name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
     "targets": [{"id": "b1", "address": "http://10.0.0.1:80", "weight": 3},
                 {"id": "b2", "address": "http://10.0.0.2:80", "weight": 1}]},
    {"name": "api", "scope": "region", "region": "eu", "rule_version": 2, "ttl": 60,
     "targets": [{"id": "eu1", "address": "http://10.1.0.1:80", "weight": 1}]},
    {"name": "api", "scope": "tenant", "tenant": "vip", "rule_version": 2, "ttl": 30,
     "targets": [{"id": "v1", "address": "http://10.2.0.1:80", "weight": 1}]}
  ],
  "release_groups": [
    {"id": "canary-eu", "name": "api", "scope": "region", "region": "eu",
     "priority": 5, "match_labels": {"env": "canary"}, "percent": 25, "ttl": 30,
     "window_start": 1757600000, "window_end": 1758200000, "rule_version": 2,
     "targets": [{"id": "eu1-c", "address": "http://10.1.0.11:80", "weight": 1}]}
  ],
  "rate_limit_tiers": [
    {"id": "global-default", "scope": "global", "rate_per_second": 100,
     "burst": 200, "priority": 100, "match_labels": {}},
    {"id": "global-canary", "scope": "global", "rate_per_second": 20,
     "burst": 40, "priority": 10, "match_labels": {"env": "canary"}},
    {"id": "eu-baseline", "scope": "region", "region": "eu",
     "rate_per_second": 80, "burst": 120, "priority": 100},
    {"id": "vip-guaranteed", "scope": "tenant", "tenant": "vip",
     "rate_per_second": 500, "burst": 1000, "priority": 0}
  ]
}
```

目标地址：`tcp://host:port`（TCP 连通性检查）或 `http(s)://host:port/path`
（GET 期望 2xx/3xx）。`effective_from` 为未来时间戳时规则定时激活；发布组由
自身的 `window_start`/`window_end` 控制激活与结束。

## 运行

本地：

```bash
pip install -r requirements.txt
uvicorn --factory app.main:build_from_env --port 8080
```

Docker：

```bash
docker build -t georesolve .
docker run -p 8080:8080 -v georesolve-data:/data \
  -e GEORESOLVE_ADMIN_TOKEN=secret georesolve
```

Docker Compose（双节点 + 两个演示后端，共享配置文件热加载）：

```bash
docker compose up --build
curl "http://localhost:8081/v1/resolve?name=api&region=eu&tenant=vip&client=1.2.3.4"
# 修改 config/config.json 并递增 version，两个节点约 1 秒内同时应用
```

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `GEORESOLVE_DB_PATH` | `/data/georesolve.db` | SQLite 路径（配置版本与审计持久化） |
| `GEORESOLVE_CONFIG_FILE` | 无 | 监视的配置文件，版本更高时自动应用 |
| `GEORESOLVE_CONFIG_POLL` | `1.0` | 配置文件轮询间隔（秒） |
| `GEORESOLVE_ADMIN_TOKEN` | 无 | 控制面 Bearer 令牌（不设置则不鉴权，勿暴露公网） |
| `GEORESOLVE_HEALTH_INTERVAL` / `GEORESOLVE_HEALTH_TIMEOUT` | `2.0` / `1.0` | 健康检查间隔/超时（秒） |
| `GEORESOLVE_BACKGROUND` | `1` | 置 `0` 关闭后台健康检查与文件监视 |
| `GEORESOLVE_PREVIEW_TTL` | `300` | 预演令牌有效期（秒），过期后提交该预演结果会被拒绝（410） |

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest
```

150+ 个用例覆盖：三层覆盖与跨租户/区域隔离、加权选择的确定性与分布、正/负缓存与
TTL、版本单调性与选择性失效、定时规则激活、健康切换的确定顺序与恢复收敛、
健康检查阈值、灰度发布组（标签匹配、时间窗口、百分比确定性、优先级、缓存隔离
与失效、explain 与审计、非法配置拒绝）、租户/标签限流（层级选择、优先级、
client/tenant/标签桶隔离、缓存命中扣费、429/Retry-After、拒绝不写缓存、
explain 余量、桶替换重置与审计、非法配置拒绝）、配置变更管理（预演不改任何正式
状态、预演影响与实际失效一致、预演令牌的过期/单次/过时基线/内容篡改/种类不匹配
拒绝、版本历史与差异查询、回滚生成更高新版本并走完整校验/缓存/审计管线、回滚到
不存在/当前/同内容版本被拒、乐观并发与同版本号并发提交不覆盖）、
多租户管理员委托与作用域授权（身份生命周期与立即停用/令牌轮换、
global→region→tenant 作用域继承、作用域合并应用与定时规则保留、越权 403 且
无配置/缓存副作用、缓存清理与健康覆盖的作用域限制、版本历史与审计的作用域过滤、
禁止租户权限扩大到区域/全局、乐观并发与并发修改、幂等键重放与冲突、
授权决定/拒绝/身份变更审计、重启后持久化）、
临时应急授权（申请-审批-生效-到期/撤销全流程、审批前不生效、审批人不能批自己的
申请、授权范围不超出审批人可委托范围、生效授权逐请求参与配置/缓存/健康/版本
计算、到期与撤销立即失效且旧令牌不可继续用、终态与过期状态写入 409、并发审批
唯一成功、幂等重放、全事件持久化与审计、重启后状态与到期语义保持）、
解析用量计量与预算告警（事件按 `event_id` 幂等、`X-Request-Id` 重试不重复计费、
迟到/乱序事件按事件时间归档、日/月聚合按租户/客户端/规则作用域分项且重算后与明细
一致、阈值告警 exactly-once 与历史周期 retroactive 告警、allow/degrade/reject 三种
超预算策略与 402 可解释拒绝、拒绝 0 计费但留痕、缓存命中仍计量、explain 只投影不计量、
预算/告警乐观并发、同内容 no-op、补录与重算的租户授权和幂等键、区域/租户管理员作用域
隔离、重启后明细/聚合/预算/未确认告警保持、并发下事件不重复计费与预算版本仅一胜）、
API 全流程（含 400/401/402/403/404/409/410/422/429）。

## 设计说明与边界

- 缓存为节点内存态（与 DNS 缓存语义一致），重启后重新计算；配置与审计落 SQLite 持久化。
- 多节点一致性论证：答案是 `(配置版本, 健康视图, 客户端键, 标签)` 的纯函数。配置版本由
  单调版本号与全量 bundle 保证；健康视图由各节点对相同目标的相同检查在有界时间内
  收敛；因此节点间只可能短暂分叉，不会长期不一致。
- 客户端键（`client` 参数，缺省取来源 IP）决定加权选择的落点；同一键在任何节点、
  任何时刻（相同健康视图下）得到相同答案。
