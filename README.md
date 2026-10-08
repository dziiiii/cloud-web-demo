# NW6 最小静态页主动拉取发布草案

状态：仅本地可审查草案；未推送、未运行Actions、未连接/安装服务器、未修改线上。
本方案替代SWAS/OIDC发布与SSH部署路线；旧SSH诊断封存，不需运行。

## 固定边界
- 源仓库：dziiiii/cloud-web-demo；手动dispatch主分支main，无需输入SHA，直接使用github.sha并记录在manifest/active中。
- 产物分支：nw6-release；正常fast-forward推送，不force，不支持可选仓库/分支/下载URL。
- 产物仅 release.json 和 site.tar.gz；压缩包只包含无秘密的最小index.html，当前固定入口为仓库根目录index.html，初版仍为无敏感测试页。
- 服务端仅写 /var/www/haoduoo/sites/nw6/index.html，使用同目录临时文件+os.replace原子替换。
- 父任务已核实：/nw6/302到/nw6，/nw6使用现有root和try_files；本方案不修改Nginx。
- 独立nw6-pull用户，无sudo，无SSH/登录密码配置。不执行、导入或安装发布分支的代码。
- 此处是最小静态页验证；四款业务源码不在产物中，腾讯后台同步、图片访问均未解决。

## 流程
1. GitHub Actions只允许workflow_dispatch，无push/PR/定时触发。
2. 源代码checkout固定workflow完整SHA；运行离线测试，构建确定性最小tar.gz。
3. publish job经nw6-static-release Environment和批准变量门禁，重建相同SHA并比对build job摘要。
4. 使用GitHub自动生成的短期GITHUB_TOKEN发布固定分支。没有新增repository Secrets、API key、OIDC或SSH私钥。
   实际contents:write是仓库级权限，不能宣称token仅限nw6-release分支。需要父任务审查分支保护与Environment设置。
5. 服务器timer约每5分钟匿名HTTPS检查固定release ref。先得到完整release commit，commit/root tree核验后，manifest与archive由同一commit的Contents JSON/base64读取。
6. 下载无重定向、无认证头，无任意URL或脚本执行。服务端不绑定页面模板，仅验证唯一普通index.html及manifest/压缩包的SHA256与长度；更新仓库index.html文字无需重装服务端程序。
7. 在任何修改前检验当前页与本机TLS健康；备份原文件、持久化journal、单文件原子替换。
8. 本机127.0.0.1:443连接，TLS验证haoduoo.com，GET /nw6，要求200和完整响应SHA256正确；失败原子恢复旧文件并复验。
9. 进程被中断后，下次优先用journal恢复旧页；遇到无关页面变化或备份漂移则停止，不盲目覆盖。

## 限制与结果含义
- 需要父任务授权的管理员引导安装。现在原目录root:root755，未安装用户无权原子替换；不声称当前已有写权限。
- 只给nw6子目录所需权限，sites父目录保持root:root755。程序仅写index.html，但OS目录写权限不等于内核只允许一个文件名。
- 服务单元ProtectSystem=strict，ReadWritePaths只开放nw6目录及专用state/backups；私有/tmp和/var/tmp只读。
- 发布分支成功不等于站点已上线；需等待timer并核对服务结果和公网页面。
- 无认证GitHub API通常有速率限制。HTTP200到github.com不证明api.github.com/Contents API也可访问；三者需后续验证。404/限流/下载失败保留现页。
- 20个备份容量上限，满后停止并请求管理员审查清理；不自动删除备份或递归清理未知文件。
- 同一服务使用文件锁；管理员仍应避免与timer并发修改同一页。不会声称能阻挡所有root级竞态操作。
- 回滚恢复文件内容及0644。替换inode由独立用户创建，不能恢复原root UID；此所有权差异必须纳入安装授权。
- 父路径、其他网站、Nginx配置、四款开发文件均不触碰。
- 不增加入站接口、VPN、付费runner或数据库。工作流使用标准ubuntu-24.04 runner；不承诺账号费用为零。

## 离线验证
```bash
python3 -m unittest discover -s tests -v
```
46项测试通过；所有下载与健康响应均为模拟，未探测服务器。
Python3.6语法检查通过；实际本地执行为3.12.14，尚未在目标3.6实跑。
actionlint1.7.7通过。systemd-analyze本地257校验通过，目标239需要授权后安装前验证。

## 修复轮1协议和事务边界
HTML单文件最大65536字节（64KiB），构建、解包、当前页读取、备份与本机健康响应均采用此上限；压缩包另限65536字节，展开tar限262144字节，JSON限8192字节。即使HTML未超限，压缩包超限仍拒绝。
服务器只将HTML视为字节数据，不执行；浏览器会正常解释HTML/JS，发布内容仍须人工审查且不得含秘密。
服务端安装只需root-owned __init__.py/protocol.py/puller.py，不安装源HTML；render/build是构建侧入口，不被拉取器调用。
pending保存旧/新active及摘要。journal存在意味着未完成提交，恢复旧页面和旧active，二者持久化后再删除journal。
正常提交先持久化页面，通过健康检查，再持久化active；unlink journal为逻辑提交边界，随后fsync state为持久化完成边界。
删除后fsync失败时页面与active均保留新版本，报告commit cleanup durability unconfirmed，不虚称已回滚；管理员需确认持久化，下次无journal时验证active与页面一致。
真实断电落盘顺序需目标验收；离线故障注入不代表硬件断电验证。
RestrictSUIDSGID为上游242新增，不适用于239，已明确移除；其他保护项保持原样。安装前必须检测未知指令并验证实际隔离，禁止用本地257结果替代。


第6轮当前下载通路、退避、测试数及真实证据边界以review/STATUS.md为准。原下载段落为历史草案；现有程序不访问raw域名或响应下载URL。本轮69项发布器/协议测试通过，新目标3.6与产物实下载待验证。
