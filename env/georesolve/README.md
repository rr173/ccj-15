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

## API

数据面（无需认证）：

| 接口 | 说明 |
|---|---|
| `GET /v1/resolve?name=&region=&tenant=&client=` | 解析名字，返回答案（含 `rule_version`、`chosen`、有序目标列表、TTL） |
| `GET /v1/explain?name=&region=&tenant=&client=` | 查询当前采用的规则版本、目标、生效时间、缓存状态、下次切换时间 |
| `GET /healthz` | 存活探针 |

控制面（设置 `GEORESOLVE_ADMIN_TOKEN` 后需 `Authorization: Bearer <token>`）：

| 接口 | 说明 |
|---|---|
| `GET /v1/config` | 当前配置快照（版本、默认值、全部规则含定时版本） |
| `POST /v1/config` | 应用新配置 bundle（版本必须递增） |
| `GET /v1/audit?type=&limit=&since=` | 审计记录：`rule_change`、`cache_invalidation`、`health_change`、`config_applied` |
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
  ]
}
```

目标地址：`tcp://host:port`（TCP 连通性检查）或 `http(s)://host:port/path`
（GET 期望 2xx/3xx）。`effective_from` 为未来时间戳时规则定时激活。

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

32 个用例覆盖：三层覆盖与跨租户/区域隔离、加权选择的确定性与分布、正/负缓存与
TTL、版本单调性与选择性失效、定时规则激活、健康切换的确定顺序与恢复收敛、
健康检查阈值、API 全流程（含 401/409/422）。

## 设计说明与边界

- 缓存为节点内存态（与 DNS 缓存语义一致），重启后重新计算；配置与审计落 SQLite 持久化。
- 多节点一致性论证：答案是 `(配置版本, 健康视图, 客户端键)` 的纯函数。配置版本由
  单调版本号与全量 bundle 保证；健康视图由各节点对相同目标的相同检查在有界时间内
  收敛；因此节点间只可能短暂分叉，不会长期不一致。
- 客户端键（`client` 参数，缺省取来源 IP）决定加权选择的落点；同一键在任何节点、
  任何时刻（相同健康视图下）得到相同答案。
