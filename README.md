# RAG Document Authorization Lab · RAG 文档权限实验室

[![Tests](https://github.com/carb6661/rag-document-authz-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/carb6661/rag-document-authz-lab/actions/workflows/tests.yml)
[![MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

一个面向应用安全、API 安全测试与 RAG 数据治理岗位的**本地多租户文档 API 实验**。实现服务端身份上下文、租户隔离、对象所有权、角色权限、列表过滤、并发版本检查和结构化审计，并用同一组请求比较故意缺陷版与修复版。

保护对象是未来可能被 RAG 检索的文档正文及来源元数据。没有接入大模型、嵌入模型或向量数据库，不把它包装成完整 RAG 系统。所有用户、租户和文档均为原创合成数据。

## 0. 0.2版：从权限演示深入到授权检索

本轮修复五项已复现的输入/资源/审计问题，并增加 **先授权后评分** 的本地精确关键词检索。技术问题、根因、旧版/新版证据和生产方案见[技术深挖报告](docs/TECHNICAL_DEEP_DIVE.md)。

- 重复JSON字段422、关键头歧义400，不静默选择最后值或某个身份。
- 请求读取同时限制64KiB、1024帧和5秒总期限。
- 常规未处理异常500也有审计、关联ID和no-store；审计增加时间、序号及覆盖计数。
- 会话签发前清理过期项，限制容量，支持本进程按租户成员批量撤销。
- 新增 POST /v1/retrieve，返回授权文档片段和版本引用；尚非语义RAG。

本地164项测试、16组对照；历史0.1版基线仍保留。已知限制包括处理中撤销的身份快照窗口、内存存储与非持久审计，不称为生产就绪。

## 1. 与已有项目的区别

Compliance RAG Assistant 负责结构化入库；本项目负责“谁可以读取、修改或列出哪些文档”。Prompt Injection Firewall 处理内容风险，RAGShield 提供安全评测；这里交付的是可运行的对象 API 和明确的授权策略，未与这些仓库自动集成。

即使登录成功，也不能直接按调用者提供的文档 ID 读取内容。OWASP API1:2023 将缺失对象级授权列为 API 风险，要求访问对象的功能检查相应权限。[OWASP 官方说明](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/)

本实验用于合法本地教学和工程展示，不是扫描器，不访问外部目标，不尝试真实凭据，也不包含删除或破坏功能。

## 2. 五分钟复现

Python 3.11—3.13：

```bash
git clone https://github.com/carb6661/rag-document-authz-lab.git
cd rag-document-authz-lab
python -m venv .venv
```

Windows PowerShell：

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.lock
```

macOS/Linux：

```bash
source .venv/bin/activate
python -m pip install -r requirements.lock
```

依赖安装需要网络，固定实验不连接外部服务：

```bash
python -X utf8 -m doclab experiment
python -X utf8 -m pytest -q
python -X utf8 -m doclab.live_smoke
```

experiment 使用 FastAPI TestClient 在进程内执行16组固定合成请求，每组同时跑缺陷版与修复版，返回状态、是否符合预期、是否修改内存数据及审计证据。完整输出见[可重现报告](examples/report.json)，测试会精确对比报告。

live_smoke 则启动真正的回环 HTTP 服务，验证自身读取、同租户他人拒绝、跨租户拒绝、匿名拒绝和列表过滤，结束后关闭服务；不打印会话令牌。

## 3. 修复前后对照

| 情境 | 缺陷版 | 修复版 | 证据意义 |
| --- | --- | --- | --- |
| 所有者读自己的文档 | 200 | 200 | 合法使用没有被一律拒绝 |
| 同租户编辑者读他人的个人文档 | 200 | 404 | 修复缺失的对象所有权判断 |
| 不同租户的同名用户读文档 | 200 | 404 | 仅比较用户名不足以隔离租户 |
| A租户管理员读取B租户 | 200 | 404 | 管理员不能跨租户 |
| 编辑者修改他人或其他租户文档 | 200，内存数据改变 | 404，数据不变 | 验证实际状态，而非只看返回码 |
| reader 修改自己的文档 | 403 | 403 | 只读角色没有写权限 |
| 合法所有者或本租户管理员修改 | 200 | 200 | 保留合法编辑能力 |
| 修改 owner_id 等受保护字段 | 422 | 422 | 请求模型拒绝批量赋值 |
| 匿名访问 | 401 | 401 | 缺陷版仍有认证，问题在对象授权 |
| Alice列出文档 | 4个 | 1个 | 列表和单对象采用一致策略 |

缺陷版只故意省略租户/所有权范围，其他控制仍保留，不是对所有漏洞的模拟。每个情境使用新的数据副本，避免前一个请求影响下一个案例。不是对真实目标进行攻击，也不是企业实战经历。

## 4. 授权规则与API

身份来自服务端保存的短期随机会话，**不信任 X-Tenant-ID、X-Role 或请求正文指定的所有者**。角色语义由本实验定义，不是所有组织通用的权限规则：

| 角色 | 读取/列表 | 编辑 |
| --- | --- | --- |
| reader | 仅本租户本人所有文档 | 不允许 |
| editor | 仅本租户本人所有文档 | 仅本人文档 |
| tenant_admin | 本租户所有文档 | 本租户所有文档 |

所有角色都先满足租户边界。未授权对象和不存在对象均返回404及相同公开错误正文；这减少存在性暴露，但**没有承诺时间侧信道不可区分**。对已获对象访问的只读角色，写入返回403。

| 路由 | 功能与约束 |
| --- | --- |
| GET /health | 查看默认是否为 hardened |
| GET /v1/documents | 按实际身份过滤列表，不接受调用者指定租户作为授权依据 |
| GET /v1/documents/{id} | 检查租户、所有权及角色后返回合成文档 |
| PATCH /v1/documents/{id} | 仅允许 title/text，必须提供 expected_version |
| POST /v1/retrieve | 仅query/top_k；先过滤对象权限，再字面评分及返回版本引用 |

PATCH 的授权、版本比较和更新在同一进程锁内完成。旧版本返回409，保护并发更新不互相覆盖。id、tenant_id、owner_id、version 不接受客户端直接赋值。没有创建、删除、公开令牌签发或任意文件读取接口。

### 精确关键词检索

使用本次启动的会话，POST /v1/retrieve 的请求体示例：

```json
{"query":"原创演示","top_k":5}
```

Alice只获得自己的1项结果；query为“同租户”时，虽然其他人的文档包含该词，Alice仍得到0项。query最多128字符、8个空白分隔词，top_k为1—10。score是词频，不是可信度；不支持语义理解，snippet为前240字符，citation仅定位合成文档ID/版本。

## 5. 手工使用本地API

```bash
python -X utf8 -m doclab serve --port 8000
```

只绑定127.0.0.1，启动时为五个合成身份生成会话并显示一次，15分钟过期、重启失效。CLI不提供 --unsafe 或外部监听参数。缺陷版仅用于进程内对照；不要自行将 unsafe=True 应用挂到网络。

另开终端，复制本次启动输出中 alice-editor 的会话。以下仅为占位示例，不是有效凭据：

```bash
curl --noproxy "*" http://127.0.0.1:8000/v1/documents/doc-a-alice -H "Authorization: Bearer <本次启动的会话>"
curl --noproxy "*" http://127.0.0.1:8000/v1/documents/doc-a-bob -H "Authorization: Bearer <同一个会话>"
```

预期分别为200、404。Windows PowerShell可使用 curl.exe；不要公开终端会话输出或把实际运行令牌写入Git。使用 Python HTTP 客户端时采用 trust_env=False，避免环境代理转发本地请求。原型不使用Cookie，也不提供登录页面。

会话由标准库生成32字节随机值，服务端仅以其SHA-256索引保存身份及到期时间；支持内部撤销。它不是JWT、不是OAuth/OIDC，不处理真实密码，也不是生产身份服务。生产应使用经过审核的身份提供方，并正确映射可信租户与用户。

## 6. 证据与安全措施

- 认证失败401、认证上下文由服务端确定；不同会话库签发的令牌不能互用。
- 身份和资源都包含租户；同名用户的跨租户请求有专门测试。
- 列表与单对象复用策略，未知动作默认拒绝。
- 写入要求版本；拒绝时测试确认内存数据未改变。
- 请求体最大64 KiB、最多1024个ASGI帧、总读取期限5秒；非法/重复JSON不回显正文，关键头重复拒绝。
- 所有响应使用 Cache-Control: no-store，避免依赖缓存保存受限内容。
- 审计包含服务端 request_id、行为者、租户、角色、动作、资源、理由和状态；不记录 Authorization 或文档内容。
- 审计只保留最近256条，增加UTC时间、序号和覆盖计数；常规未处理异常也记录。无公开审计接口，不是持久取证日志。

[报告](examples/report.json)去掉每次变化的 request_id 和 timestamp，保留可重现的授权理由；真实响应头与内存事件仍有相同ID，便于关联。内部原因区分 tenant_mismatch、owner_mismatch、read_only_role、version_conflict 等，公开404不暴露这些细节。

## 7. 误拒、漏控与适用范围

这不是分类模型，因此不报告“检测准确率”。对照中的“合法被拒”及“越权被放行”分别可理解为策略误拒和漏控：

- 当前策略故意不支持共享文档。若业务允许团队共享，editor读同事文档会被拒绝；不能直接称为通用正确策略，需要增加显式共享授权和测试。
- 没有组织层级、委托、字段级脱敏、外部共享、紧急授权或属性动态变化；不能推断这些场景已安全。
- 令牌失窃后，攻击者可在其有效期内冒用该会话。没有MFA、设备绑定、速率限制或集中撤销。
- 数据、会话和审计都在单进程内存，不能用于多进程一致性或持久化；重启重置四份样本。
- 已有授权后精确关键词检索及合成文档版本引用，但没有语义/向量检索、标准原文引用、LLM答案授权或模型提示词安全；不证明下游无泄漏。
- 本进程主体撤销拒绝新请求；已经持有身份快照的处理中请求仍可能完成，有专门测试说明此限制。
- 未做生产压测、真实客户部署、跨服务完整性证明或独立安全审计；通过测试不代表全部授权漏洞已排除。

详细[威胁模型](docs/THREAT_MODEL.md)、[修复与集成建议](docs/REMEDIATION.md)与[验证记录](docs/VALIDATION.md)。

## 8. 测试、结构与岗位能力

测试包括完整角色×对象×动作矩阵、API正反例、到期/撤销/篡改令牌、假身份请求头、批量赋值、并发版本冲突、错误输入、审计脱敏及16场景报告重放。GitHub Actions跑Windows/Linux × Python 3.11/3.12/3.13，依赖锁定，Actions固定提交SHA。

```text
doclab/
  security.py       短期会话和默认拒绝策略
  models.py         身份、文档及更新字段约束
  api.py            对象API、列表/检索过滤、更新锁与审计
  ingress.py        严格JSON、关键头与有界请求
  retrieval.py      授权快照的精确关键词评分
  diagnostics.py    五项修复探针
  experiment.py     进程内修复前后对照
  live_smoke.py     真实回环HTTP验证与清理
fixtures/           五个合成身份、四份文档、16场景
examples/report.json
tests/test_lab.py
docs/
```

面试演示主线：认证不等于授权 → 同租户不等于有对象权限 → 同名用户不能跨租户 → 管理员仍受租户约束 → 拒绝请求还要验证数据未修改 → 列表、正文与未来检索都要遵守同一边界。

可展示应用安全分析、FastAPI工程、对象级授权、数据隔离、回归测试及证据解释；仅陈述已理解和复现的部分，不把实验写成生产经历。

MIT仅覆盖本项目原创代码、文档与合成样本。[安全使用说明](SECURITY.md)
