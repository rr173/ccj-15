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
  或非有限值）、同名组 id 重复、同层相同标签条件的重叠窗口、同优先级且标签条件相容
  （可能匹配同一客户端）的重叠窗口、空目标集合、`rule_version` 超过 bundle 版本。
- `GET /v1/explain` 的 `release` 段显示命中/未命中原因
  （`hit` / `percentage_miss` / `labels_mismatch` / `window_inactive` /
  `no_visible_groups` / `no_groups`）、命中组详情、分桶值与候选组评估过程。
- 审计新增：`release_group_change`（组增删改，含新旧内容）、`release_group_hit`
  （命中，含分桶、百分比、窗口、标签）、缓存失效记录携带 `group_id`，
  灰度决策变化导致的失效原因为 `release_group_changed`。

## API

数据面（无需认证）：

| 接口 | 说明 |
|---|---|
| `GET /v1/resolve?name=&region=&tenant=&client=&labels=` | 解析名字，返回答案（含 `rule_version`、`release_group`、`chosen`、有序目标列表、TTL）；`labels` 形如 `env=canary,team=pay` |
| `GET /v1/explain?name=&region=&tenant=&client=&labels=` | 查询当前采用的规则版本、目标、生效时间、灰度命中与原因、缓存状态、下次切换时间 |
| `GET /healthz` | 存活探针 |

控制面（设置 `GEORESOLVE_ADMIN_TOKEN` 后需 `Authorization: Bearer <token>`）：

| 接口 | 说明 |
|---|---|
| `GET /v1/config` | 当前配置快照（版本、默认值、全部规则含定时版本、全部发布组） |
| `POST /v1/config` | 应用新配置 bundle（版本必须递增） |
| `GET /v1/audit?type=&limit=&since=` | 审计记录：`rule_change`、`release_group_change`、`release_group_hit`、`cache_invalidation`、`health_change`、`config_applied` |
| `GET /v1/health/targets` | 目标健康视图 |
| `GET /v1/cache` / `POST /v1/cache/flush` | 缓存查看 / 清空（清空会记审计） |

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

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest
```

65 个用例覆盖：三层覆盖与跨租户/区域隔离、加权选择的确定性与分布、正/负缓存与
TTL、版本单调性与选择性失效、定时规则激活、健康切换的确定顺序与恢复收敛、
健康检查阈值、灰度发布组（标签匹配、时间窗口、百分比确定性、优先级、缓存隔离
与失效、explain 与审计、非法配置拒绝）、API 全流程（含 400/401/409/422）。

## 设计说明与边界

- 缓存为节点内存态（与 DNS 缓存语义一致），重启后重新计算；配置与审计落 SQLite 持久化。
- 多节点一致性论证：答案是 `(配置版本, 健康视图, 客户端键, 标签)` 的纯函数。配置版本由
  单调版本号与全量 bundle 保证；健康视图由各节点对相同目标的相同检查在有界时间内
  收敛；因此节点间只可能短暂分叉，不会长期不一致。
- 客户端键（`client` 参数，缺省取来源 IP）决定加权选择的落点；同一键在任何节点、
  任何时刻（相同健康视图下）得到相同答案。
