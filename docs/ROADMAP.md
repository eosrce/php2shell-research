# PHP2Shell Research Map

> **Maintenance rule**: update this map at every research milestone (new proof,
> new blocker, new research question, new tool). Output the full map, not only a
> diff. This is the canonical research map for this repository.
>
> Snapshot 2026-10-26 (night): 8M FPM HTTP-only chain closed — debug 3/3,
> official stripped 1-worker 3/3, 4-worker 3/3; chunk/PIE leaked over HTTP with
> `chunk+0x56c60` as the stable PIE source. 128M FPM stays deterministic.
>
> Previous: v4 (8M reclaim 3/3). This version adds the HTTP-only leak/endgame
> results, the proof-directory pitfall and the 31-case lab matrix.
>
> Snapshot 2026-10-29: the repository moved to a single curated commit that
> also ships the clean-room `src/p2s/` chain (MIT). See "What changed since the
> 2026-10-26 snapshot" below; the FPM map body stays at its 2026-10-26 state.
>
> Snapshot 2026-10-31 (v11): two pure-HTTP gdb-free FPM chains are added —
> PHP 8.5.11/128M (R1→R2a→R1(K2)→R2a(K2)→R3, ROUNDS=3 3/3 `uid=33`,
> `gdb_hits=0`) and the same chunk-relative carrier ported to the real-CVE
> PHP 8.2.34-FPM branch (`PROFILE=8234`, BG `+0x350/+0x358`, d=0xFE000,
> F=0x7A000, S=0x84000). Lab matrix 57/57 (49 proof + 2 refuse + 6 gap;
> http-only 21/57); A/B 87.55/85.05. See the 2026-10-31 "What changed" section.

```text
==========================================================================================
 PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 全域路径
 版本  研究快照 2026-10-31 v11（FPM 详细图保留 2026-10-26 snapshot；2026-10-31 增补见 What changed 段）
 图例  [OK] 已验证   [~~] 有条件/部分   [XX] 未打通   [--] 未开始
       (!) 本轮新结论/新证据
 基线  lab matrix 57/57 按预期（49 proof + 2 refuse + 6 gap；http-only 21/57）
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
  [OK] lab matrix                          50/50 按预期（42 proof + 2 refuse
                                         + 6 gap；http-only 14/50）
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

## What changed since the 2026-10-26 snapshot (2026-10-29)

The FPM map above is kept as the 2026-10-26 snapshot (still accurate for the FPM
8M/128M chains).  The 2026-10-29 research state adds the following; this
repository ships the curated `src/`, `labs/`, `docs/`, `tests/` content only
(proofs, logs and the live working map stay in the main workspace):

- Self-implemented `src/p2s/` (MIT): the mod_php warning + pure128 chain.
  Warning chain: 8M 1-worker / 4-worker, 16M/32M/64M/128M/256M
  (16M and 32M 3/3 including after a container restart); pure128: 1/5/150
  workers.
- mod_php 8.4.26 8M-256M and 8.3.35/8.5.11; patched builds (8.4.27/8.5.12)
  are refused with exit 3; `p2s.cli` mirrors `exploit.py`'s version gate.
- FPM 8.3.35: consumer closed 3/3 + full HTTP-only chain 1-worker/4-worker;
  official stripped 8.4.26 8M HTTP-only 1-worker/4-worker.
- 128M application chains: Laravel 13.17 native file session 3/3 and the T18b
  pure-HTTP `ps_files` writer chain 3/3; Symfony native file session 3/3;
  **Symfony pure-HTTP chain R1->R2a->R2b->R3 3/3 `uid=33`** (matrix
  `symfony-http-1w`, `oracle=http`; no gdb in the proof path);
  WordPress+FPM reclaim 3/3 (1-worker/4-worker).  WordPress *pure-HTTP* is
  still open: the 128M post-OOM free area starts above the `E`/`DT` objects
  (anchor 0x6A018), so chunk-relative carriers cannot reach them (docs/99 §7,
  F113/R16) -- a structural blocker, not a dead route.
- Clean-room `p2s` on a CMS: **MediaWiki 1.43.9 / PHP 8.3.35 / 128M /
  post_max_size=8M 3/3 `uid=33`** (matrix `cms-mediawiki-p2s`,
  `oracle=http`; chunked 132MiB OOM field + pin 149/150 + neutral
  `/_p2s_ip.php` page; 8.3.35@128M keeps the 8M stage-3 geometry).
- Lab regression matrix: **54 cases = 46 proof + 2 refuse + 6 gap; 18 of them
  are `oracle=http` (no gdb)**; the two WP 8.4.15 de=On cases use a lab
  `html_errors=On` ini and either the `/_p2s_pk.php` helper page or the
  helper-free `stage1-A + forged zend_string len=0x2000000` SIGSEGV recycle.
- Licensing unchanged: all code in this tree is self-implemented p2s work
  (MIT); related research is credited in NOTICE and `docs/licensing.md`.

## What changed since the 2026-10-29 snapshot (2026-10-31)

This is the release-candidate state for the 2026-10-31 snapshot (v9). The
curated map body above stays at its earlier state; proofs/logs stay in the
main research workspace.

- **8.5.11 FPM / 128M pure-HTTP gdb-free chain closes**
  (`fpm-8511-http-1w`, `oracle=http`): in-run `ROUNDS=3` PASS=3/3, matrix
  3 independent runs PASS 86.4 / 88.5 / 87.5 s, `/srv/www/x.php` 392 B and
  `uid=33`, measured sampler `gdb_hits=0`; prime/grow are now all-HTTP.
  Details: `docs/research/fpm-8511-http.md`.
- **8.2.34 FPM / 128M real-CVE quadrant port** (`fpm-8234-http-1w`,
  `oracle=http`): the same runner via `PROFILE=8234`; in-run `ROUNDS=3`
  PASS=3/3 and matrix 3 independent runs PASS 101.4 / 92.4 / 104.9 s.
  Details: `docs/research/fpm-8234-port.md`.
- **Lab matrix: 57 cases = 49 proof + 2 refuse + 6 gap; 21/57
  `oracle=http`**; scoring A/B **87.55 / 85.05** (docs/87 v42; A = no-gdb
  only, B = research completeness including gdb calibration).
- **zendkit M24** method card (`rfc1867 --shape-floor`): the carrier floor
  `F` is per body shape (independent of the prime plane, E1 cold==primed);
  unknown shapes must be calibrated or the tool errors out instead of reusing
  historical `F0` readings (docs/107 §1).
- **CVE-2026-115560 is out of scope**: a serialize-handler mismatch
  (php.net informational advisory, 2026-10-23), not the
  CVE-2026-109618/109619 OOM/dangling-global primitive; it does not change
  the 109619 boundary and is not covered by this matrix (docs/107 §4.6).
- **8.5.12 patch gate**: a plain `refuse` exit is a false-positive PASS; the
  main research tree now has a fail-closed `PATCH GATE: closed` token and its
  own classifier (design notes live in the main tree, not in this snapshot).
  The snapshot matrix below stays at the 57 proof/refuse/gap cases.
- Limitations (apply to both new proofs): lab prime page + `cleanup=Off` +
  per-round `docker restart` + one-off gdb calibration; carrier floor per
  shape/plane.

## What changed since the 2026-10-31 v9 snapshot (2026-10-31, v10)

Release-candidate state for the multi-worker milestone. The engine chains from
v9 are unchanged; the new evidence is that they also run under `pm=static` 4
workers with lab pinning, and the runner now asserts each round strictly.

- **4w pure-HTTP chains, dual quadrant** (`fpm-8234-http-4w`,
  `fpm-8511-http-4w`; both `proof`, `oracle=http`): three concurrent
  `_sleep.php` requests pin 3/4 children so grow/prime/R2a/R3 land on the same
  free child; in-run `ROUNDS=3` PASS=3/3 (8.2.34 248.3 s; 8.5.11 301 s) and
  matrix runs PASS (8.2.34 strict 103.4/168.2/138.7 s under VM load; 8.5.11
  98.9/121.8 s plus a third PASS block). Details:
  `docs/research/fpm-8234-4w.md`, `docs/research/fpm-8511-4w.md`.
- **Runner strict assertions**: `WORKERS=1|4`, `SLEEP_T`, `P4W_GDB`,
  `ASSERT4` (grow/prime/fatal/markers/primed pid/free pid/SR/x.php/negctrl/
  health) and stage-code assertions (R2a 502, R3 200).
- **BG offset dual parse**: `BG(unserialize).level` is `+0x358` on 8.2.34 and
  `+0x370` on 8.5.11; the one-shot gdb check now parses both offsets and
  requires `level1_count==1` (a legitimate 0 at the other offset must not mask
  the match).
- **8.2.35 branch gate** (`fpm-8235-gate`, `kind=gate`, not proof): image
  `p2s-phpfpm-lab:8.2.35-gate` (`sha256:ac855a04...`), container
  `p2s-fpm8235-128`/19140, 1 worker with a mounted `cleanup=Off` ini copy.
  **3/3 `PATCH GATE: closed` (exit 0, 268.9 s)**; 8.2.34 positive control
  3/3 `OPEN (expected on vulnerable)` (exit 3); unknown `PROFILE` exit 2.
  8.2.35 still OOMs on prime (500/0 B + `7000064` fatal) but leaves
  `BG level=0`; R2a 200/SR=361 B, R2a(K2) 200/SR=698 B, R3 200 with no
  `x.php`/`uid=33`. Details: `docs/research/fpm-8235-gate.md`.
- **Lab matrix: 61 cases = 51 proof + 2 refuse + 6 gap + 2 gate; 23/61
  `oracle=http`**; A/B **87.55 / 85.05 unchanged** (lab scheduling layer and
  gates never raise the score).
- Limitations: lab pinning precondition (`_sleep.php` + exclusive container +
  `cleanup=Off` ini/`zz-r40-lab.ini` + `request_terminate_timeout`); per-round
  restart; `P4W_GDB=1` calibration only; `log_errors=Off` gives
  `fatal=inferred`.

## What changed since the 2026-10-31 v10 snapshot (2026-10-31, v11)

Release-candidate state for the multi-worker patched gate and 8.5.13
readiness. The engine chains are unchanged; the new evidence is that the
8.5.12 gate also holds in `WORKERS=4` pin mode, and the 8.5.13 gate is staged
for release day.

- **8.5.12 4w patch gate** (`fpm-8512-gate-4w`, `kind=gate`): container
  `p2s-gate8512-4w`/19143, image `sha256:d06afa5c...`; `PATCH GATE: closed`
  3/3 (exit 0, ~94.9 s/run); signature = 1w (SR 469 -> 374 -> 724, BG all 0,
  no `x.php`); 8.5.11 4w control `OPEN (expected on vulnerable)` exit 3
  (SR 47/70 + `x.php` 392 B + `uid=33`); `NO_PIN=1` on the same container
  gives the same closed signature. Details:
  `docs/research/fpm-8512-gate-4w.md`.
- **First-run false positive recorded**: the draft shared one stage body and
  hardcoded 1w SR values, printing `OPEN (REGRESSION)` for a closed target -
  an instrument bug (SR arithmetic 819/1264), fixed by per-stage bodies and
  exploit-signal-only OPEN; unknown signatures become `ERROR/rebaseline`.
- **8.5.13 readiness** (not released): tag 404 / latest 8.5.12; estimate
  ~2026-11-19 +/- `[UNVERIFIED]`; apiki `php-8.5.13` is a trap; gate
  `r41_patch_gate8513.sh` prepared (DIAG, `BG_VERIFIED`/
  `ALLOW_BG_UNVERIFIED`, exact-version strictness, digest pins, port 19145);
  details `docs/research/fpm-8513-readiness.md`.
- **Lab matrix: 62 cases = 51 proof + 2 refuse + 6 gap + 3 gate; 23/62
  `oracle=http`**; A/B **87.55 / 85.05 unchanged**.
- Limitations: 4w pinning is a lab scheduling precondition (exclusive
  container); BG one-shot gdb or `[UNVERIFIED]`; `log_errors=Off` ->
  `fatal=inferred`; per-round restart; 8.5.13 unreleased; gate closed !=
  build safe (CVE-2026-115560 separate).

## What changed since the 2026-10-31 v11 snapshot (2026-10-31, v12)

Release-candidate state for the 8.2.35 4-worker gate, the upstream fix-commit
evidence and the CVE-2026-115560 release-level scope.

- **8.2.35 4w patch gate** (`fpm-8235-gate-4w`, `kind=gate`): container
  `p2s-gate8235-4w`/19148, image `sha256:ac855a04...`; `PATCH GATE: closed`
  3/3 (exit 0, ~98 s/run); signature = 8.2.35 1w (grow 7,048,390, SR
  456 -> 361 -> 698, BG all 0, no `x.php`); 8.2.34 4w control `OPEN
  (expected on vulnerable)` exit 3 (SR 47/70 + `x.php` 392 B + `uid=33`);
  `NO_PIN=1` gives the same closed signature. The shared runner now selects
  the branch by `PROFILE` (8512/8511 and 8235/8234) with image/version/ini
  preflight. Details: `docs/research/fpm-8235-gate-4w.md`.
- **Upstream fix commits**: one patch per branch - 8.5.12 `31c0ea7d7f` and
  8.2.35 `01a40e89fb` (+ NEWS/version commits), public replay
  `3584a98bda` with an identical diff and merge chain; delayed OOM,
  `php_basic_early_rinit()` reset, incomplete-only decode + fail-fast,
  rfc1867 early stop, `$_SESSION` delete; `php_session_cancel_decode`
  unchanged (GH-24493 open). Details:
  `docs/research/fix-commits-2026-10-31.md`.
- **CVE-2026-115560 release-level scope**: A 3/3 RCE on both 8.5.11 and
  8.5.12-gate digests; A2 NO_RCE; C2 (`php_admin_value` handler lock)
  NO_RCE; C3 (+ `enabled=Off`) NO_RCE; still out of scope / not
  matrix-registered.
- **Lab matrix: 63 cases = 51 proof + 2 refuse + 6 gap + 4 gate; 23/63
  `oracle=http`**; A/B **87.55 / 85.05 unchanged**.
- Limitations: 4w pinning lab precondition (exclusive container); image/
  version/ini preflight pins; BG one-shot gdb or `[UNVERIFIED]`;
  `log_errors=Off` -> `fatal=inferred`; per-round restart; 115560 requires
  app conditions and stays out of scope.

## What changed since the 2026-10-31 v12 snapshot (2026-10-31, v13)

Release-candidate state for the 8.3.36 4-worker gate, the E7 runtime
mechanism verification and the 8.3.36 release/EOL facts.

- **8.3.36 4w patch gate** (`fpm-8336-gate-4w`, `kind=gate`): container
  `p2s-gate8336-4w`/19152, image
  `sha256:b229bcfd...f732b24965`; `PATCH GATE: closed` 3/3 (exit 0,
  78.4 s single round / three 78 s matrix runs); signature = 8.2-style
  (grow 7,048,390, SR 456 -> 361 -> 698, BG all 0 at the **8.3 level field
  `+0x360`**, no `x.php`/`uid`); 8.3.35 4w control `OPEN (expected on
  vulnerable)` exit 3 (SR 47/70 + `x.php` 392 B + `uid=33`, `+0x360=1` at the
  free child); `NO_PIN=1` same closed signature. The runner now selects
  `PROFILE=8336|8335` and parses three BG offsets (8.2 `+0x358`, 8.3
  `+0x360`, 8.5 `+0x370`). Details: `docs/research/fpm-8336-gate-4w.md`.
- **E7 mechanism verification** (`docs/118`): dynsym exports only on the
  patched image; natural-run differential (patched same-request BG destroy +
  two delayed-OOM calls, next request 0; vulnerable stale `HASH=1` until
  module RINIT); controlled write proves `php_basic_early_rinit` clears BG
  (capability [CONFIRMED]; natural-path attribution [REFINED]; delayed-OOM
  causality [INFERRED]); incomplete-only call confirmed. Details:
  `docs/research/e7-mechanism-verification.md`.
- **8.3.36 release/EOL**: pure security release (fix `3c832b523e` + NEWS
  `d59a20c8f9` + version `5ba6ad5192`; tag object `7ed5ca1a...`); EOL
  corrections - 8.3 security to 2027-12-31 (active ended 2025-12-31),
  8.2 EOL 2026-12-31, 8.4 to 2028-12-31, 8.5 to 2029-12-31.
- **Lab matrix: 64 cases = 51 proof + 2 refuse + 6 gap + 5 gate; 23/64
  `oracle=http`**; A/B **87.55 / 85.05 unchanged**.
- Limitations: 4w pinning lab precondition (exclusive container); image/
  version/ini preflight; BG one-shot; `fatal=inferred`; per-round restart;
  **AGENTS #31 correction** (no `exit 70` in this 4w shape).

## What changed since the 2026-10-31 v13 snapshot (2026-10-31, v14)

Release-candidate state for the E7 static/timing CONFIRMED evidence, the
8.4.27 gate PoC (blocked control) and the 8.5.13 release-day tooling.

- **8.4.27 4w gate PoC** (`fpm-8427-gate-4w` **not registered**): container
  `p2s-gate8427-4w`/19154, image
  `sha256:26ba8279...7597a99d`; `PATCH GATE: closed` exit 0 (grow 7,050,470,
  SR 469 -> 374 -> 724, BG all 0 at `+0x370`, no `x.php`/`uid`; `NO_PIN=1`
  same signature). But the 8.4.26 4w positive control returns
  `ERROR`/rebaseline (R2a 502, SR 469 -> 469 -> 914): the instrument uses
  8.5-family constants and the 8.4.26 vulnerable geometry/aim differs.
  **[BLOCKED] positive control => gate not registered**; matrix stays 64.
  Image has two valid index digests (release-day original vs current rebuild) -
  quote both. Details: `docs/research/fpm-8427-gate-4w-poc.md`.
- **E7 static-function recovery & rfc1867 order**: static targets recovered
  via dynsym anchor -> objdump call targets -> runtime callback pointer
  (`initialize` 0x5c0140/0x5bb690, `rfc1867_update` 0x5c1830/0x5bcd50,
  `rfc1867_callback` 0x5c1a70/0x5bcfa0 for 8.5.12/8.5.11); gdb shows the
  consumer order callback -> update -> initialize (incomplete-only) -> flush
  **before module RINIT**, and the fail-fast is the update's
  `PS(session_status)!=active` check (**[REFINED]**). rfc1867 internal order
  is now **[CONFIRMED]**; 374/361 B alignment stays **[INFERRED]**.
- **8.5.13 release-day tooling**: `labs/fpm/r41_patch_gate8513.sh`,
  `labs/fpm/r46_build8513.sh` and the one-command
  `labs/fpm/r49_release_day_8513.sh` pipeline ship in the snapshot (build ->
  DIAG -> closed 3/3 -> 8.5.11 4w control -> unknown `PROFILE` -> 115560
  reminder; exact-version gate; `BG_VERIFIED`/`ALLOW_BG_UNVERIFIED`; port
  19145).
- **8.4.27 release facts**: fix `506e87fa7d` + NEWS `2f966f79f6` + version
  `500438163a`; not a pure security release; EOL active 2026-12-31 / security
  2028-12-31.
- **Lab matrix: 64 cases = 51 proof + 2 refuse + 6 gap + 5 gate (unchanged);
  23/64 `oracle=http`**; A/B **87.55 / 85.05 unchanged**.
- Limitations: the 8.4 gate is a PoC with a blocked control; static/gdb work
  ran on clone containers (mechanism evidence only); the 8.5.13 pipeline needs
  the released official image and exact-version gate before any verdict.

## What changed since the 2026-10-31 v14 snapshot (2026-10-31, v15)

Release-candidate state for the 8.4 gate registration, the E7
`cancel_decode` closure and the reverse-review corrections.

- **8.4.27 4w gate registered** (`fpm-8427-gate-4w`): 8.4.26 positive control
  3/3 `OPEN (expected on vulnerable)` (83/83/83 s, SR 47/70, `x.php` 392 B,
  `uid=33`) and 8.4.27 3/3 `PATCH GATE: closed` (86/85/83 s, grow 7,050,470,
  SR 469 -> 374 -> 724, BG 0, no `x.php`/`uid`, sleepers 3/3); `NO_PIN=1`
  same. The 8.4 prime plane is its own: `d=chunk+0xFD000`, `E=d+0x1C000`,
  `DT=d+0x3000` => progress=chunk+0x61000, aim=-93688, AIM_W=-99777,
  S=0x84000, SP=7,050,470, BG `+0x370`. Matrix 3x PASS 101/100/100 s =>
  **65 = 51 proof + 2 refuse + 6 gap + 6 gate**, 23/65 `oracle=http`.
  Failed candidates (8.5 constants ERROR, 8.2 constants closed-like) are kept
  as evidence that a positive control is not optional. Details:
  `docs/research/fpm-8427-gate-4w-poc.md`.
- **E7 `php_session_cancel_decode` [CONFIRMED]**: static addresses
  0x21d673/0x21d68e; fail-fast stack and `_SESSION` cleanup were observed, and
  the vulnerable image calls it too (the fix point is the update's status
  early-exit, **[REFINED]**); rfc1867 timing is now [CONFIRMED], only the
  374/361 B alignment stays [INFERRED].
- **web-r50 / reverse-r51 corrections**: 8.4.27 ChangeLog breadth (Session 2
  entries are `create_sid`, not the CVEs); digest sequence 10-21 -> 10-23 ->
  10-28 current `f3397667...`; CISA KEV no 10-31 update (catalog 2026.10.30;
  115560 not listed); MANIFEST hashes are committed Git blobs (LF) - fresh
  clone is clean, a CRLF worktree must be restored before hashing.
- **Lab matrix: 65 cases = 51 proof + 2 refuse + 6 gap + 6 gate; 23/65
  `oracle=http`**; A/B **87.55 / 85.05 unchanged**.

## What changed since the 2026-10-31 v15 snapshot (2026-10-31, v16)

Release-candidate state for the cross-branch gate smoke, hardening, E7
numeric alignment and web-r51 corrections.

- **Cross-branch gate family smoke** (1 run/case, **not** a 3/3 re-validation):
  6/6 registered gates PASS (`fpm-8512-gate`, `fpm-8512-gate-4w`,
  `fpm-8235-gate`, `fpm-8235-gate-4w`, `fpm-8336-gate-4w`,
  `fpm-8427-gate-4w`; runner 69.8-112.2 s) and 4/4 controls
  `OPEN (expected on vulnerable)` (47/70, `x.php` 392 B, `uid=33`). Family
  signatures: 8.5/8.4 grow 7,050,470 / SR 469 -> 374 -> 724 (BG `+0x370`);
  8.2/8.3 grow 7,048,390 / SR 456 -> 361 -> 698 (BG `+0x358`/`+0x360`).
  Details: `docs/research/gate-family-crossbranch-2026-10-31.md`.
- **gate4w fail-closed hardening** (script sha256 `4a94d199...3ec66bf`): PASS
  requires BG verified (`GDB_BG=0` -> exit 2 unless `ALLOW_BG_UNVERIFIED=1`),
  `sleepers_alive=3/3` (NO_PIN comparison-only) and pinned page sha
  (`EXPECT_PAGE_SHA256`); after hardening the four registered 4w cases re-ran
  4/4 PASS (96.1/94.9/94.5/94.4 s).
- **E7 numeric alignment** (`docs/121`): 374 B = prefix 43 + `a:5` fields
  (5+31+31+32+15+216) + `}` 1; 361 B = 374 - 13 (`tmp_name` 27 -> 14); 47 B =
  prefix 43 + `i:0;` 4. gdb normal R2a has no CANCEL/DESTROY => the bytes are
  a normal progress record; old fail-fast attribution **[REFINED]** (malformed
  only); only the `i:0;` mechanism stays `[INFERRED]`.
- **web-r51 corrections**: #24493/#24677 are **not** the 115560 tracker (8.5.12
  session-data-loss regression); 115560 promised for the next regular release,
  no public fix/tracker, not in KEV; `3584a98bda` is an ancestor of all four
  public branches (`behind_by=0`); 8.2 security ends 2026-12-31.
- **Generic pipeline** `labs/fpm/r50_release_day_any.sh` v2: FAMILY signature
  table, exact version, `RUNS>=3`, control via `CONTROL_EXPECT_IMAGE`,
  unknown PROFILE exit 2; fail-closed negatives verified.
- **Lab matrix: 65 cases = 51 proof + 2 refuse + 6 gap + 6 gate (unchanged);
  23/65 `oracle=http`**; A/B **87.55 / 85.05 unchanged**.

## What changed since the 2026-10-31 v16 snapshot (2026-10-31, v17)

- **Cross-branch full 3x re-validation**: 6 gate cases x3 = **18/18 PASS**
  (attempts=1) and 4 controls x3 = **12/12 `OPEN (expected on vulnerable)`**
  (47/70, `x.php` 392 B, `uid=33`, sleepers 3/3, BG `level=1` per family).
  The v16 1-run smoke is retained as history and marked superseded.
  Details: `docs/research/gate-family-crossbranch-2026-10-31.md`.
- **Selector trap and fix**: `verify_matrix.py --only` is now **exact**
  (prefix no longer matches `-4w` siblings); `--only-substr` is the legacy
  substring mode; unknown names exit **2** with substring hints. CLI tests
  **4/4**, project pytest **70 passed**. The matrix wrapper defaults to
  `--gdb-bg 1` (no inheritance of `GDB_BG=0`).
- **zendkit / public data (note)**: zendkit M25-M29, **100 tests**; latest
  releases still 8.5.12/8.4.27/8.3.36/8.2.35; 8.5.13/8.4.28 unpublished;
  109618/619 in CISA KEV since 2026-10-26; 115560 no patch (next regular
  release), so the 8.5.13 release-day gate cannot run yet.
- **Lab matrix: 65 cases = 51 proof + 2 refuse + 6 gap + 6 gate (unchanged);
  23/65 `oracle=http`**; A/B **87.55 / 85.05 unchanged**.

## Change log

| Date | Version | Change |
|---|---|---|
| 2026-10-24 | v1 | first version: mod_php / FPM / T2 / T3 / T15 quadrants |
| 2026-10-25 | v2 | FPM 128M determinism; CMS matrix |
| 2026-10-26 | v3 | 8M FPM prime; empty chunk; R3 writer located |
| 2026-10-26 | v4 | **8M FPM reclaim 3/3**; `no-oracle` 1/1; HTTP leak/official/4w open |
| 2026-10-26 | research | independent research tree (MIT; self-implemented p2s code) |
| 2026-10-26 night | v5 | **8M FPM HTTP-only chain closed**: debug 3/3, official 1w 3/3, 4w 3/3; PIE source `chunk+0x56c60`; proof-dir pitfall; 31-case lab matrix (`fpm-8m-reclaim`) |
| 2026-10-29 | v6 | clean-room `src/p2s/` (warning + pure128, MIT) shipped; 49-case matrix (41 proof / 2 refuse / 6 gap; 13/49 http-only); app chains closed (Laravel T18b pure-HTTP, Symfony file session, WP+FPM reclaim); single-commit release sync |
| 2026-10-29 | v7 | p2s 16M restored to the matrix (3/3 incl. restart); **50-case matrix = 42 proof + 2 refuse + 6 gap; 14/50 http-only**; F82 closed for 16M/32M |
| 2026-10-29 | **v8** | **Symfony pure-HTTP chain 3/3** (`symfony-http-1w`, `oracle=http`; same-key R2a insight) and **clean-room p2s on MediaWiki 3/3** (`cms-mediawiki-p2s`; chunked OOM + neutral page + 8.3.35@128M geometry); **52-case matrix = 44 proof + 2 refuse + 6 gap; 16/52 http-only**; WP pure-HTTP structural blocker recorded (anchor 0x6A018, F113/R16) |
| 2026-10-29 | **v9** | **WP 8.4.15 de=On pure-HTTP full chain 3/3 `uid=33`** (`cms-wordpress-on2-p2s`; `html_errors=On` lab ini + HTTP child-recycle helper page; stage2 cookie form-decode bug fixed); matrix **53 = 45 proof + 2 refuse + 6 gap, 17/53 http-only**; zendkit M14-M16 |
| 2026-10-29 | **v10** | **Helper-free WP 8.4.15 de=On chain**: stage1-A(OOM) + forged zend_string len=0x2000000 (Set-Cookie read past the 2MiB chunk) SIGSEGVs the serving child; full chain **12/12 rounds `uid=33`** with the `/_p2s_pk.php` page moved out of the docroot; matrix adds `cms-wordpress-on2-p2s-noh` -> **54 = 46 proof + 2 refuse + 6 gap, 18/54 http-only**; downward-writer path refuted (psv is a live bin-32 reference, carrier bin-40 run sits +0x880 above) |
| 2026-10-31 | **release candidate v9** | 8.5.11 FPM 128M pure-HTTP gdb-free chain (`fpm-8511-http-1w`) and 8.2.34 real-CVE quadrant port (`fpm-8234-http-1w`) registered; **57-case matrix = 49 proof + 2 refuse + 6 gap; 21/57 http-only**; A/B 87.55/85.05; zendkit M24 (shape-dependent floor F); CVE-2026-115560 out of scope; 8.5.12 patch gate WIP |
| 2026-10-31 | **release candidate v10** | 4w pure-HTTP chains (`fpm-8234-http-4w`, `fpm-8511-http-4w`; proof/oracle=http) with lab `_sleep.php` pinning + `ASSERT4` strict assertions + BG dual-offset parse; 8.2.35 branch gate (`fpm-8235-gate`, closed 3/3 vs 8.2.34 control OPEN 3/3); **61-case matrix = 51 proof + 2 refuse + 6 gap + 2 gate; 23/61 http-only**; A/B 87.55/85.05 unchanged |
| 2026-10-31 | **release candidate v11** | 8.5.12 4w patch gate (`fpm-8512-gate-4w`, closed 3/3 vs 8.5.11 4w control OPEN 3/3; first-run false positive recorded as instrument bug and fixed) + 8.5.13 readiness (gate prepared, not released); **62-case matrix = 51 proof + 2 refuse + 6 gap + 3 gate; 23/62 http-only**; A/B 87.55/85.05 unchanged |
| 2026-10-31 | **release candidate v12** | 8.2.35 4w patch gate (`fpm-8235-gate-4w`, closed 3/3 vs 8.2.34 4w control OPEN 3/3; NO_PIN same signature) + upstream fix-commit evidence (8.5.12 `31c0ea7d7f` / 8.2.35 `01a40e89fb`; public replay `3584a98bda`) + CVE-2026-115560 release-level scope (A 3/3 RCE; A2/C2/C3 NO_RCE); **63-case matrix = 51 proof + 2 refuse + 6 gap + 4 gate; 23/63 http-only**; A/B 87.55/85.05 unchanged |
| 2026-10-31 | **release candidate v13** | 8.3.36 4w patch gate (`fpm-8336-gate-4w`, closed 3/3 vs 8.3.35 4w control OPEN 3/3; 8.3 BG level `+0x360`; NO_PIN same signature) + E7 runtime mechanism verification (dynsym/natural-run differential/controlled write/incomplete-only) + 8.3.36 pure-security-release and EOL correction (8.3 security to 2027-12-31); **64-case matrix = 51 proof + 2 refuse + 6 gap + 5 gate; 23/64 http-only**; A/B 87.55/85.05 unchanged |
| 2026-10-31 | **release candidate v14** | 8.4.27 4w gate PoC (closed exit0 but 8.4.26 positive control `ERROR`/rebaseline => **[BLOCKED]**, not registered) + E7 static-function recovery & rfc1867-before-module-RINIT order **[CONFIRMED]** (fail-fast via `PS(session_status)` check, [REFINED]) + 8.5.13 release-day pipeline (`r46_build8513.sh`, `r41_patch_gate8513.sh`, `r49_release_day_8513.sh` shipped); **matrix 64 unchanged (51/2/6+5 gate; 23/64 http-only)**; A/B 87.55/85.05 unchanged |
| 2026-10-31 | **release candidate v15** | 8.4 gate calibrated and registered (`fpm-8427-gate-4w`: 8.4.26 4w control 3/3 OPEN after re-baselining to the 8.4 prime plane `d=0xFD000/E=0x119000/DT=0x100000`; 8.4.27 3/3 closed; NO_PIN same) + E7 `php_session_cancel_decode` **[CONFIRMED]** (0x21d673/0x21d68e; fail-fast stack/`_SESSION` cleanup; vulnerable calls it too, fix point = update status early-exit [REFINED]) + web-r50/reverse-r51 corrections (8.4.27 ChangeLog/digests/KEV; MANIFEST = committed blobs, CRLF worktree artifact); **65-case matrix = 51 proof + 2 refuse + 6 gap + 6 gate; 23/65 http-only**; A/B 87.55/85.05 unchanged |
| 2026-10-31 | **release candidate v16** | Cross-branch gate family **smoke** (6/6 registered gates PASS 69.8-112.2 s + 4/4 controls OPEN; 1 run/case, not a re-validation) + gate4w **hardening** (sha `4a94d199...`: BG verified, sleepers 3/3 hard assertion, `EXPECT_PAGE_SHA256`; `GDB_BG=0`/`SLEEP_T=1` -> exit 2; four 4w gates re-ran 4/4 PASS) + E7 **numeric alignment** (374/361 B = normal `a:5` progress records; attribution [REFINED]) + web-r51 corrections (#24493/#24677 not the 115560 tracker; 115560 next regular release/not in KEV; `3584a98bda` ancestor of four branches) + generic `r50_release_day_any.sh`; **matrix 65 unchanged**; A/B 87.55/85.05 unchanged |
| 2026-10-31 | **release candidate v17** | Cross-branch **full 3x** re-validation (**18/18 gates + 12/12 controls PASS**, attempts=1; per-case times recorded) + **selector fix** (`--only` exact, `--only-substr` legacy, unknown name rc=2 + hints; CLI tests 4/4, pytest 70) + matrix wrapper `--gdb-bg 1` default + zendkit 100 tests / public-data note (8.5.13 still unreleased, 115560 next regular release); **matrix 65 unchanged**; A/B 87.55/85.05 unchanged |
