# 本地控制面与发行包

此文件只说明这次安全补丁的边界。发行源仍是 `package.json` 里的 `kingcharleslzy-ai/dsh-purge`，没有改成当前 fork。

审计过的源码提交与以后下载的发行包不是同一件事。自动安装在解开真实归档后，如果本机 `package.json` 的 `purgeSecurity.localApiAuth` 高于发行包，会停止该次自动安装。手动更新不受这条拦截。归档不存在时（测试桩）不拦截，也不把“没读到包”当成已经包含补丁。

本地 `/dsh-purge/*` 与 `POST /redteam/api` 不再因为对端是环回地址就跳过来源检查。不提供任何未认证即可取回的令牌。Linux 上能读到 `/proc/net/tcp` 时，还会核对接字 uid 是否为本进程用户。这不是 DSH 会话 cookie 的校验；本仓库没有宿主的校验函数。Windows 与 macOS 上没有同等的对端 uid，环回上的其他本地账户仍可能伪造 Origin。桌面端 `app://` 与 `file://` 在 Host 仍是环回时保留。

`redteam_preflight` 和 `platformSummary` 不再带出 FOFA、其它密钥字段或代理 URL 中的用户名和口令。空的密钥字段表示保留已保存的值。红队凭据库仍按原功能把操作者记录的口令交给本机会话。
