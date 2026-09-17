# 格式与边界

## 验证范围

2026-09-14 在 Apple Silicon、macOS 27、微信4.1.13/build269602 上真实验证过临时副本取钥、原版微信在线只读查询和WAL新消息读取。版本号是验证范围，不是永久兼容承诺；其他系统/版本需要当前原始资料和本机验证，不能把Windows方法直接套到Mac。

## 本地状态

- 配置：`~/Library/Application Support/CodexWeChatRead/config.json`，字段 `db_root`、`keys_file`，可选时区 `timezone`。个人账号和路径留在该文件，不写进Skill。
- 默认密钥文件：同目录 `validated-keys.json`，格式为相对db_storage路径映射到 `{enc_key, salt, algorithm}`。enc_key为32字节hex，salt为16字节hex；内容绝不能展示。
- 当前已验证的算法为 `hmac-sha512-reserve80`，页4096字节，SQLCipher4 raw-key加显式salt。采集器的其他算法候选不能直接算运行兼容；读取器会拒绝尚未支持的算法标签。
- 默认数据发现：`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/*/db_storage`。以明确配置或正在使用的账号为准，多账号不盲选。

## 表与身份

| 来源 | 作用 |
|---|---|
| `message/message_N.db` | 常规聊天分片；所有实际Msg表都要覆盖 |
| `message/biz_message_N.db` | 业务/公众号消息分片 |
| `Msg_<md5(username)>` | 会话消息；跨分片可能重复出现同一表名 |
| 每分片 `Name2Id` | `rowid → user_name`，发送者ID只在本分片解释 |
| `contact/contact.db` 的 `contact` | username、nick_name、remark、alias等 |
| `session/session.db` 的 `SessionTable` | 会话列表及最新摘要；不是全量历史 |
| `message/message_resource.db` / `media_0.db` | 消息资源关联/媒体记录，不等于已解析全部媒体文件 |

常见消息列：`local_id, server_id, local_type, sort_seq, real_sender_id, create_time, message_content, source, WCDB_CT_message_content, WCDB_CT_source`。`server_id`输出为字符串以免64位精度损失。按实际schema消费，不从旧模板补造字段。

WCDB_CT=4为本机观察到的zstd压缩；0为未压缩。TEXT存储类中可能放二进制，读取时保留bytes。不要把压缩数据转换成“乱码”或用占位符冒充正文。

## 实际边界

- 三个FTS库使用私有 `MMFtsTokenizer`。通用SQLCipher直接跑其虚拟表完整性检查可报SQL logic error；本机已对全部加密页HMAC及物理底表分别验证通过。不要用假的分词器替代并声称微信全文索引语义正确；日常搜索直接扫描解压后的消息。
- 原始辅助库 `migrate/unspportmsg.db` 在本次未取得key。没有证据证明它为空或内容全部冗余；保留为未验证，不阻断已经证实的常规对话读取。
- `brandsessionholder`、`brandservicesessionholder`为聚合入口。`@opencustomerservicemsg`的摘要可通过last_msg_sender映射到实际子会话；本机曾核对到同local_id/同时间的原始记录。每次出现新差异仍须核实，不能把所有无Msg表的Session一律忽略。
- Session时间领先Msg一两秒不自动证明漏读；检查last_msg_locald_id是否实际存在，并考虑跨库非同时点。
- 本 Skill 的默认消息输出不暴露原始媒体凭据或整段协议XML。未知内容保留记录和失败标记。需要附件本体或精细卡片解析时再按当前数据补充，不宣称已经具备全媒体解析。

## 原始参考

- [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/)：raw key、显式salt、cipher_integrity_check。
- [WCDB](https://github.com/Tencent/wcdb)：底层数据库能力，不能替代微信私有格式的本机验证。
- [macOS 4.1.13 CommonCrypto取钥方法](https://github.com/TimFang4162/wechat4-macos-frida-export)：拦截方法参考；其原始全库导出脚本存在本任务已发现的遗漏，不能直接当完整性证明。
- [wxkey](https://github.com/r266-tech/wxkey)：保留SIP的临时副本思路。查到网页摘要不等于原仓/发行物仍可用，更新时核对原始来源。
