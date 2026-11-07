/**
 * Rule catalog.
 *
 * Rules are content rules, not string blacklists. Each one asks a structural
 * question about the normalized command ("is any segment a recursive delete
 * whose target is a root-ish path?") rather than grepping for a literal.
 *
 * Tier semantics:
 *   allow   — no rule fired; executes.
 *   log     — executes, but the audit trail flags it. Visibility without friction.
 *   confirm — a human must approve before it executes.
 *   deny    — never executes. No approval can override it (a human can only
 *             change the rule, which is itself an audited action).
 *
 * The deny list is intentionally SHORT and precise. A long deny list is a
 * security theatre anti-pattern: it raises false positives, users disable the
 * tool, and you end up with zero coverage instead of partial coverage.
 */

import type { Norm, Rule, Segment } from './types.ts';
import { DOWNLOADERS, INTERPRETERS } from './normalize.ts';

// ---------------------------------------------------------------------------
// accessors
// ---------------------------------------------------------------------------

const hasProg = (n: Norm, ...p: string[]): boolean => n.programs.some((x) => p.includes(x));

const segsOf = (n: Norm, ...p: string[]): Segment[] => n.segments.filter((s) => p.includes(s.program));

const argsOf = (n: Norm, ...p: string[]): string[] =>
  segsOf(n, ...p).flatMap((s) => s.argv.slice(1).map((a) => a.toLowerCase()));

const anyArg = (n: Norm, re: RegExp): boolean => n.segments.some((s) => s.argv.slice(1).some((a) => re.test(a)));

const allText = (n: Norm): string => n.segments.map((s) => s.argv.join(' ')).join(' ').toLowerCase();

// ---------------------------------------------------------------------------
// detectors
// ---------------------------------------------------------------------------

const SENSITIVE_PATH =
  /(\.ssh[\\/]|id_rsa|id_ed25519|id_ecdsa|\.aws[\\/]credentials|\.npmrc|\.netrc|\.git-credentials|\.gnupg|\.kube[\\/]config|\.docker[\\/]config\.json|\.pypirc|\.terraform[\\/]|\.azure[\\/]|\.config[\\/]gcloud|secrets?\.(?:json|ya?ml)|credentials\.json)/i;

const DOTENV = /(^|[\\/\s"'=:])\.env(?:\.[a-z0-9]+)?($|[\s"'`;|&)])/i;

/**
 * `@.env` in a curl upload is the same file as `.env`; `id_rsa.pub` is not a
 * secret at all. Both directions matter: strip the `@` (catch more), drop the
 * `.pub` (catch less).
 */
function isSensitiveArg(raw: string): boolean {
  const a = raw.replace(/^@/, '').replace(/^["']|["']$/g, '');
  if (/\.pub$/i.test(a)) return false;
  return SENSITIVE_PATH.test(a) || DOTENV.test(a);
}

const anySensitive = (n: Norm): boolean => n.segments.some((s) => s.argv.slice(1).some(isSensitiveArg));

/**
 * Two sensitivity levels, deliberately.
 *   .env          -> local dev convenience, `log` is enough
 *   keys/tokens   -> `confirm`, because reading is step one of exfiltrating
 * Collapsing them would either hide the real thing or make the gate cry wolf
 * on every project that has a .env file (i.e. all of them).
 */
function isKeyMaterial(raw: string): boolean {
  const a = raw.replace(/^@/, '').replace(/^["']|["']$/g, '');
  if (/\.pub$/i.test(a)) return false;
  return SENSITIVE_PATH.test(a);
}

const anyKeyMaterial = (n: Norm): boolean => n.segments.some((s) => s.argv.slice(1).some(isKeyMaterial));

/** SQL text inside `echo 'DROP TABLE ...' > x.sql` is data, not an instruction. */
const SQL_IS_DATA = new Set(['echo', 'printf', 'tee', 'cat', 'write-output', 'out-file', 'set-content', 'add-content']);

const sqlIsExecuted = (n: Norm): boolean => !hasProg(n, ...SQL_IS_DATA);

const CRED_READERS = new Set([
  'cat', 'type', 'less', 'more', 'head', 'tail', 'gc', 'get-content', 'strings',
  'xxd', 'base64', 'openssl', 'cp', 'copy', 'scp', 'rsync', 'tar', 'zip', 'gzip',
]);

const NETWORK_PROGS = new Set([
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'scp', 'ssh', 'rsync', 'socat',
  'iwr', 'invoke-webrequest', 'invoke-restmethod', 'telnet', 'ftp',
]);

const MUTATORS = new Set([
  'rm', 'del', 'rd', 'rmdir', 'mv', 'move', 'cp', 'copy', 'chmod', 'chown',
  'tee', 'sed', 'dd', 'echo', 'set-content', 'add-content', 'out-file',
  'remove-item', 'new-item', 'truncate', 'sponge',
]);

const SYSTEM_PKG = new Set(['apt', 'apt-get', 'dnf', 'yum', 'pacman', 'brew', 'winget', 'choco', 'snap', 'apk']);

const DB_MIGRATE =
  /(prisma\s+migrate|alembic\s+upgrade|flyway\s+migrate|knex\s+migrate|sequelize\s+db:migrate|manage\.py\s+migrate|rails\s+db:migrate|dbmate\s+up|sqitch\s+deploy|golang-migrate)/;

const ROOT_TARGETS = new Set([
  '/', '/*', '~', '~/', '$home', '${home}', 'c:\\', 'c:/', 'c:\\*', '..',
  '/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/boot', '/home', '/root',
  '/opt', '/srv', '%userprofile%', '$env:userprofile', '/system', '/library',
]);

function isRecursive(argv: string[]): boolean {
  return argv.slice(1).some((a) => {
    if (a === '--recursive' || a === '-R') return true;
    if (/^\/s$/i.test(a)) return true; // rmdir /s, rd /s
    if (/^-[a-zA-Z]+$/.test(a) && /[rR]/.test(a)) return true;
    return false;
  });
}

function isForce(argv: string[]): boolean {
  return argv.slice(1).some((a) => /^(-f|-F|--force|\/q|\/f|-rf|-fr)$/i.test(a));
}

function deleteTargets(argv: string[]): string[] {
  return argv
    .slice(1)
    .filter((a) => !a.startsWith('-') && !/^\/[sq]$/i.test(a))
    .map((a) => a.toLowerCase().replace(/["']/g, ''));
}

/**
 * Walks the pipe chain forward from a downloader. Adjacent pairs are not
 * enough: `curl … | tee /tmp/a | sh` is still download-to-shell, and it exists
 * specifically because naive scanners check neighbours.
 */
function downloadPipedToInterpreter(n: Norm): boolean {
  for (let i = 0; i < n.segments.length; i++) {
    if (!DOWNLOADERS.has(n.segments[i]!.program)) continue;
    let j = i;
    while (j < n.segments.length - 1 && n.segments[j]!.nextOp === '|') {
      j += 1;
      if (INTERPRETERS.has(n.segments[j]!.program)) return true;
    }
  }
  return false;
}

/** curl -o f ... && chmod +x f && ./f  — staged payload, no pipe needed. */
function stagedPayload(n: Norm): boolean {
  for (let i = 0; i < n.segments.length; i++) {
    const a = n.segments[i]!;
    if (!DOWNLOADERS.has(a.program)) continue;
    const writesFile = a.argv.some((x) => /^(-o|--output|-outfile|-destination)$/i.test(x));
    if (!writesFile) continue;
    const later = n.segments.slice(i + 1);
    if (later.some((t) => t.program === 'chmod' || /^\.\//.test(t.argv[0] ?? '') || INTERPRETERS.has(t.program)))
      return true;
  }
  return false;
}

/** Payload strings passed inline to an interpreter (`-c`, `-e`, `-enc`, ...). */
const INLINE_FLAG_RE = /^(-c|-e|--eval|-command|-enc|-encodedcommand|\/c|\/k)$/i;

function inlinePayloads(n: Norm): string[] {
  const out: string[] = [];
  for (const s of n.segments) {
    if (!INTERPRETERS.has(s.program)) continue;
    for (let i = 1; i < s.argv.length - 1; i++) {
      if (INLINE_FLAG_RE.test(s.argv[i]!)) out.push(s.argv[i + 1]!);
    }
  }
  return out;
}

/** Is a secret file being read in segment i and piped forward into the network? */
function pipesSecretToNetwork(n: Norm): boolean {
  for (let i = 0; i < n.segments.length - 1; i++) {
    const src = n.segments[i]!;
    if (!src.argv.slice(1).some(isSensitiveArg)) continue;
    let j = i;
    while (j < n.segments.length - 1 && n.segments[j]!.nextOp === '|') {
      j += 1;
      if (NETWORK_PROGS.has(n.segments[j]!.program)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// catalog
// ---------------------------------------------------------------------------

export const RULES: Rule[] = [
  // ======================= DENY =======================
  {
    id: 'fs.rm-root',
    tier: 'deny',
    title: '递归删除根级路径',
    why: '递归删除的目标是 /、~、$HOME、盘符根或系统目录。这不是"清理构建产物"，这是抹盘。',
    test: (n) =>
      hasProg(n, 'rm', 'del', 'rd', 'rmdir', 'remove-item') &&
      n.segments.some(
        (s) =>
          ['rm', 'del', 'rd', 'rmdir', 'remove-item'].includes(s.program) &&
          isRecursive(s.argv) &&
          deleteTargets(s.argv).some((t) => ROOT_TARGETS.has(t)),
      ),
  },
  {
    id: 'fs.disk-wipe',
    tier: 'deny',
    title: '磁盘/分区级破坏',
    why: 'mkfs、dd of=/dev/*、diskpart、format —— 影响范围超出仓库，且不可逆。',
    test: (n) =>
      hasProg(n, 'mkfs', 'mkfs.ext4', 'diskpart', 'format', 'fdisk', 'parted') ||
      (hasProg(n, 'dd') && anyArg(n, /^of=\/dev\//)) ||
      anyArg(n, /^\/dev\/(sd|nvme|disk|hd)/),
  },
  {
    id: 'net.pipe-to-shell',
    tier: 'deny',
    title: '下载内容直接管道进解释器',
    why: 'curl/wget/iwr 的输出直接交给 sh/bash/node —— 远端代码立即执行，零审查窗口。这是供应链攻击的标准形状。',
    test: (n) => downloadPipedToInterpreter(n),
  },
  {
    id: 'net.exe-and-run',
    tier: 'deny',
    title: '下载后本地执行',
    why: '先落盘、再 chmod、再执行 —— 绕过管道检测的常见变体，同样是从网络到执行的直通车。',
    test: (n) => stagedPayload(n),
  },
  {
    id: 'creds.exfil',
    tier: 'deny',
    title: '凭据外发',
    why: '网络程序与密钥/凭据路径同时出现，或使用 nc -e / /dev/tcp 反弹。读密钥可能只是好奇，发出去就是事故。',
    test: (n) =>
      (hasProg(n, ...NETWORK_PROGS) && anySensitive(n)) ||
      (hasProg(n, ...NETWORK_PROGS) && pipesSecretToNetwork(n)) ||
      (hasProg(n, 'nc', 'ncat', 'netcat') && anyArg(n, /^-e$|^--exec$/)) ||
      /\/dev\/tcp\//.test(n.lower),
  },
  {
    id: 'obf.decode-exec',
    tier: 'deny',
    title: '解码后直接执行',
    why: 'base64/hex 解码的输出直接进解释器。这是"把要跑的东西藏起来再跑"的定义，正常工程流程里没有这个形状。',
    test: (n) => {
      for (let i = 0; i < n.segments.length - 1; i++) {
        const a = n.segments[i]!;
        const b = n.segments[i + 1]!;
        if (a.nextOp !== '|' || !INTERPRETERS.has(b.program)) continue;
        const decodes =
          (a.program === 'base64' && a.argv.some((x) => /^-(d|D|-decode)$/.test(x))) ||
          (a.program === 'xxd' && a.argv.includes('-r')) ||
          (a.program === 'certutil' && a.argv.some((x) => /^-decode/i.test(x))) ||
          (a.program === 'openssl' && a.argv.includes('-d'));
        if (decodes) return true;
      }
      return false;
    },
  },
  {
    id: 'perm.777-root',
    tier: 'deny',
    title: '对根级路径放宽权限',
    why: 'chmod 777 作用在 / 或系统目录上，等于拆掉整台机器的权限模型。',
    test: (n) =>
      hasProg(n, 'chmod', 'chown') &&
      n.segments.some(
        (s) =>
          deleteTargets(s.argv).some((t) => ROOT_TARGETS.has(t)) ||
          s.argv.slice(1).some((a) => ROOT_TARGETS.has(a.toLowerCase())),
      ) &&
      anyArg(n, /^0?777$|^-R$/),
  },
  {
    id: 'infra.destroy',
    tier: 'deny',
    title: '基础设施销毁',
    why: 'terraform destroy、kubectl 删命名空间/PVC、云资源 terminate —— 影响的是别人的线上系统，且往往不可回滚。',
    test: (n) => {
      if (hasProg(n, 'terraform') && argsOf(n, 'terraform').includes('destroy')) return true;
      if (hasProg(n, 'kubectl')) {
        const a = argsOf(n, 'kubectl');
        if (a.includes('delete') && a.some((x) => ['namespace', 'ns', 'pvc', 'pv', '--all'].includes(x))) return true;
      }
      if (hasProg(n, 'helm') && argsOf(n, 'helm').includes('uninstall')) return true;
      if (hasProg(n, 'aws') && anyArg(n, /terminate-instances|delete-(db-instance|bucket|stack|cluster)/)) return true;
      if (hasProg(n, 'gcloud') && anyArg(n, /^projects\s+delete$/)) return true;
      if (hasProg(n, 'docker') && /(system\s+prune\s+.*-a|volume\s+rm)/.test(allText(n))) return true;
      return false;
    },
  },
  {
    id: 'policy.self-modify',
    tier: 'deny',
    title: '篡改网关自身的策略',
    why: '要改的是审批网关自己的策略/数据库/环境变量。不能自己拔自己的刹车——这条是"谁来看守看守者"的底线。',
    test: (n) => {
      const touchesPolicy =
        anyArg(n, /agent-gate|\.agent-gate/i) || n.redirects.some((r) => /agent-gate/i.test(r));
      if (touchesPolicy && hasProg(n, ...MUTATORS)) return true;
      if (touchesPolicy && hasProg(n, 'git', 'npm', 'node')) return false;
      if (/agent_gate_/.test(n.lower) && hasProg(n, 'export', 'setx', 'set')) return true;
      return false;
    },
  },
  {
    id: 'git.history-rewrite',
    tier: 'deny',
    title: '重写共享历史 / 强推主干',
    why: 'filter-branch、reflog expire、gc --prune=now、强推 main —— 已经广播出去的历史无法收回，团队其他人的工作会直接丢失。',
    test: (n) => {
      if (!hasProg(n, 'git')) return false;
      const a = argsOf(n, 'git');
      if (a.includes('filter-branch') || a.includes('filter-repo')) return true;
      if (a.includes('reflog') && a.some((x) => /expire/.test(x)) && a.some((x) => /--expire=now/.test(x))) return true;
      if (a.includes('gc') && a.some((x) => /--prune=now/.test(x))) return true;
      if (a.includes('push') && a.some((x) => /^--force$|^-f$/.test(x)) && a.some((x) => /(^|:)(main|master)$/.test(x)))
        return true;
      return false;
    },
  },
  {
    id: 'sql.drop-database',
    tier: 'deny',
    title: '删除数据库',
    why: 'DROP DATABASE / DROP SCHEMA 是整库级操作，通常不可恢复，且一把命令就能从测试库误伤到生产库。',
    test: (n) => sqlIsExecuted(n) && /drop\s+(database|schema)\b/i.test(allText(n)),
  },

  // ======================= CONFIRM =======================
  {
    id: 'obf.suspicious',
    tier: 'confirm',
    title: '命令存在混淆特征',
    why: 'base64/hex 编码、多层嵌套、eval、解码后执行 —— 无法静态还原真实意图。看不见内容本身就是要拦的理由。',
    test: (n) => n.obfuscation >= 0.7,
  },
  {
    id: 'fs.rm-wildcard',
    tier: 'confirm',
    title: '通配符递归删除',
    why: '在仓库里 rm -rf * 或 rm -rf . 会把 .git 和未跟踪文件一起带走，且不进回收站。',
    test: (n) =>
      hasProg(n, 'rm', 'del', 'rd', 'rmdir', 'remove-item') &&
      n.segments.some(
        (s) =>
          isRecursive(s.argv) &&
          deleteTargets(s.argv).some((t) => t === '*' || t === '.' || t === './' || t === './*'),
      ),
  },
  {
    id: 'fs.rm-recursive',
    tier: 'confirm',
    title: '递归删除',
    why: '常规的目录删除。影响范围可接受但不可逆，值得看一眼删的是什么。',
    test: (n) =>
      hasProg(n, 'rm', 'del', 'rd', 'rmdir', 'remove-item') &&
      n.segments.some((s) => isRecursive(s.argv)),
  },
  {
    id: 'obf.eval',
    tier: 'confirm',
    title: 'eval 动态求值',
    why: 'eval 执行的是运行时拼出来的字符串。静态看不可见，而它存在的常见目的就是不让人看见。',
    test: (n) => hasProg(n, 'eval', 'invoke-expression', 'iex'),
  },
  {
    id: 'obf.dynamic-program',
    tier: 'confirm',
    title: '程序名本身是动态的',
    why: '被执行的二进制名由变量/命令替换拼出（如 $(echo cu)rl），任何基于程序名的判定都失效。名字藏起来就是要拦的信号。',
    test: (n) => n.segments.some((s) => /[$`%]/.test(s.argv[0] ?? '')),
  },
  {
    id: 'obf.destructive-inline',
    tier: 'confirm',
    title: '内联代码里藏着破坏性操作',
    why: '解释器的 -c/-e 载荷无法做语义分析，只能用内容兜底。命中说明这行代码里出现了删除/格式化/删库的字符串，必须人看。',
    test: (n) =>
      inlinePayloads(n).some(
        (p) =>
          /rm\s+-rf|mkfs|drop\s+(?:database|table)|format\s+[a-z]:|shutdown|\/etc\/passwd|:\(\)\s*\{/i.test(p) &&
          // Require an execution primitive too. `console.log("rm -rf")` is a
          // string literal; `os.system("rm -rf /")` is a command.
          /exec\(|system\(|popen|subprocess|spawn|child_process|os\./i.test(p),
      ),
  },
  {
    id: 'obf.inline-fetch-exec',
    tier: 'confirm',
    title: '内联代码里下载并执行',
    why: '解释器载荷同时出现网络拉取与 exec/eval/system —— 这是"远程代码执行"在 python/node 里的等价写法，和 curl|sh 是同一件事。',
    test: (n) =>
      inlinePayloads(n).some(
        (p) =>
          /(https?:\/\/|urlopen|requests\.|fetch\()/i.test(p) &&
          /(exec\(|eval\(|system\(|popen|subprocess|child_process)/i.test(p),
      ),
  },
  {
    id: 'fs.find-delete',
    tier: 'confirm',
    title: '用 find 删除文件',
    why: 'find -delete / -exec rm 绕过了 rm 这条规则，破坏力一模一样。检测单位是"删除行为"，不是"rm 这个程序"。',
    test: (n) => hasProg(n, 'find') && (anyArg(n, /^-delete$/) || /-exec\s+(rm|del|shred)\b/.test(allText(n))),
  },
  {
    id: 'fs.truncate',
    tier: 'confirm',
    title: '清空/覆写已有文件',
    why: 'truncate -s 0 会把文件内容抹成空，且不产生删除记录 —— 比 rm 更隐蔽。',
    test: (n) => hasProg(n, 'truncate', 'shred', 'sponge'),
  },
  {
    id: 'fs.dd-write',
    tier: 'confirm',
    title: 'dd 写入本地文件',
    why: 'dd 按块覆写，完全跳出文件系统语义，目标路径写错就是灾难。',
    test: (n) => hasProg(n, 'dd') && anyArg(n, /^of=/) && !anyArg(n, /^of=\/dev\//),
  },
  {
    id: 'git.force-push',
    tier: 'confirm',
    title: '强推非主干分支',
    why: '会覆盖远端分支历史。影响面限于该分支，但协作中仍然会打断别人。',
    test: (n) =>
      hasProg(n, 'git') &&
      argsOf(n, 'git').includes('push') &&
      argsOf(n, 'git').some((x) => /^--force$|^-f$|^--force-with-lease$/.test(x)),
  },
  {
    id: 'git.reset-hard',
    tier: 'confirm',
    title: '丢弃本地改动',
    why: 'reset --hard / clean -fd 会永久丢弃未提交的工作。Agent 经常用它来"清理干净"，代价是你的产出。',
    test: (n) => {
      if (!hasProg(n, 'git')) return false;
      const a = argsOf(n, 'git');
      if (a.includes('reset') && a.some((x) => /^--hard$/.test(x))) return true;
      if (a.includes('clean') && a.some((x) => /^-[a-zA-Z]*f/.test(x))) return true;
      if (a.includes('checkout') && a.some((x) => /^--force$|^-f$/.test(x))) return true;
      return false;
    },
  },
  {
    id: 'git.push-main',
    tier: 'confirm',
    title: '直接推送到主干',
    why: '绕过 PR 与 CI 检查直接落到 main。自动化流程里这通常应该是显式的人类动作。',
    test: (n) =>
      hasProg(n, 'git') &&
      argsOf(n, 'git').includes('push') &&
      argsOf(n, 'git').some((x) => /(^|:)(main|master)$/.test(x)),
  },
  {
    id: 'pkg.publish',
    tier: 'confirm',
    title: '发布到公共仓库',
    why: 'npm/cargo/twine/docker push 一旦成功，版本就永久存在于公共世界。发布动作应该是人类的决定，不是 Agent 的副产物。',
    test: (n) =>
      (hasProg(n, 'npm', 'yarn', 'pnpm') && argsOf(n, 'npm', 'yarn', 'pnpm').includes('publish')) ||
      (hasProg(n, 'cargo') && argsOf(n, 'cargo').includes('publish')) ||
      (hasProg(n, 'twine') && argsOf(n, 'twine').includes('upload')) ||
      (hasProg(n, 'gem') && argsOf(n, 'gem').includes('push')) ||
      (hasProg(n, 'docker') && argsOf(n, 'docker').includes('push')) ||
      (hasProg(n, 'dotnet') && argsOf(n, 'dotnet').includes('nuget')),
  },
  {
    id: 'pkg.global-install',
    tier: 'confirm',
    title: '全局安装 / 系统级包管理',
    why: '改动的是整台机器而不是当前项目，且会执行第三方安装脚本。Agent 做这件事的收益通常远小于风险。',
    test: (n) =>
      (hasProg(n, 'npm', 'yarn', 'pnpm') && argsOf(n, 'npm', 'yarn', 'pnpm').some((x) => /^(-g|--global)$/.test(x))) ||
      (hasProg(n, 'pip', 'pip3') && argsOf(n, 'pip', 'pip3').some((x) => /^--break-system-packages$/.test(x))) ||
      hasProg(n, ...SYSTEM_PKG),
  },
  {
    id: 'infra.apply',
    tier: 'confirm',
    title: '变更基础设施状态',
    why: 'terraform apply / kubectl apply / helm upgrade 会把"代码"变成真实资源变更，回滚成本高于代码回滚。',
    test: (n) => {
      if (hasProg(n, 'terraform') && argsOf(n, 'terraform').some((x) => ['apply', 'import'].includes(x))) return true;
      if (hasProg(n, 'kubectl') && argsOf(n, 'kubectl').some((x) => ['apply', 'delete', 'scale', 'patch'].includes(x)))
        return true;
      if (hasProg(n, 'helm') && argsOf(n, 'helm').some((x) => ['upgrade', 'install', 'rollback'].includes(x))) return true;
      if (hasProg(n, 'ansible-playbook')) return true;
      return false;
    },
  },
  {
    id: 'db.migrate',
    tier: 'confirm',
    title: '执行数据库迁移',
    why: '迁移通常不可自动回滚，且会作用在共享环境上。Agent 可以写迁移文件，但不该决定何时执行。',
    test: (n) => DB_MIGRATE.test(allText(n)),
  },
  {
    id: 'creds.read',
    tier: 'confirm',
    title: '读取密钥材料',
    why: '读私钥/令牌本身不破坏任何东西，但它是外发的第一步。值得知道 Agent 为什么需要看这个文件。',
    test: (n) => hasProg(n, ...CRED_READERS) && anyKeyMaterial(n),
  },
  {
    id: 'perm.broad',
    tier: 'confirm',
    title: '放宽权限',
    why: 'chmod 777 / chown -R 会制造长期的安全债，而且下一任维护者不会知道为什么。',
    test: (n) =>
      (hasProg(n, 'chmod') && anyArg(n, /^0?777$|^-R$/)) || (hasProg(n, 'chown') && anyArg(n, /^-R$/)),
  },
  {
    id: 'sql.drop-table',
    tier: 'confirm',
    title: '删除数据表',
    why: 'DROP TABLE / TRUNCATE 会清空数据。在开发库上很常见，在生产库上是事故。',
    test: (n) => sqlIsExecuted(n) && /drop\s+table|truncate\s+table/i.test(allText(n)),
  },
  {
    id: 'docker.privileged',
    tier: 'confirm',
    title: '特权容器 / 宿主目录挂载',
    why: '--privileged 或 -v /:/host 等于把宿主机控制权交给容器，跳出隔离边界。',
    test: (n) =>
      hasProg(n, 'docker') &&
      (anyArg(n, /^--privileged$/) || anyArg(n, /^\/:\/host/) || /-v\s+\/:\//.test(n.lower)),
  },

  // ======================= LOG =======================
  {
    id: 'pkg.install',
    tier: 'log',
    title: '安装依赖',
    why: '引入第三方代码，值得留痕（尤其是锁文件被改的时候），但不该打断流程。',
    test: (n) =>
      (hasProg(n, 'npm', 'pnpm', 'yarn') && argsOf(n, 'npm', 'pnpm', 'yarn').some((x) => ['install', 'i', 'add', 'ci'].includes(x))) ||
      (hasProg(n, 'pip', 'pip3', 'poetry', 'uv') && argsOf(n, 'pip', 'pip3', 'poetry', 'uv').some((x) => ['install', 'add', 'sync'].includes(x))) ||
      (hasProg(n, 'go') && argsOf(n, 'go').includes('get')) ||
      (hasProg(n, 'cargo') && argsOf(n, 'cargo').includes('add')) ||
      (hasProg(n, 'composer') && argsOf(n, 'composer').includes('require')),
  },
  {
    id: 'git.mutate',
    tier: 'log',
    title: '修改仓库状态',
    why: 'commit/merge/rebase/push 改变仓库状态，但可恢复。留痕即可。',
    test: (n) => {
      if (!hasProg(n, 'git')) return false;
      const a = argsOf(n, 'git');
      const always = ['commit', 'merge', 'rebase', 'tag', 'stash', 'cherry-pick', 'revert', 'push', 'checkout', 'switch', 'apply', 'am'];
      if (a.some((x) => always.includes(x))) return true;
      // `git branch` alone is a read; `git branch -D` is a delete.
      return a.includes('branch') && a.some((x) => /^(-d|-D|-m|-M|--delete|--move)$/.test(x));
    },
  },
  {
    id: 'net.fetch',
    tier: 'log',
    title: '访问网络',
    why: '出网是数据外流的唯一通道，也是提示注入回传的通道。记录目标主机，积少成多就是威胁情报。',
    test: (n) => hasProg(n, ...NETWORK_PROGS) || hasProg(n, 'curl', 'wget'),
  },
  {
    id: 'creds.dotenv',
    tier: 'log',
    title: '读取 .env',
    why: '.env 里通常是本地开发凭据。读它很正常，但如果紧接着出网，就该拦了。',
    test: (n) => hasProg(n, ...CRED_READERS) && anyArg(n, DOTENV),
  },
  {
    id: 'fs.write-redirect',
    tier: 'log',
    title: '重定向写入绝对路径',
    why: '写到当前项目之外的位置，超出了 Agent 的合理工作范围。',
    test: (n) => n.redirects.some((r) => /^([a-zA-Z]:[\\/]|\/)/.test(r)),
  },
  {
    id: 'proc.background',
    tier: 'log',
    title: '后台常驻进程',
    why: '后台进程会在 Agent 退出后继续运行，是最容易被遗忘的残留物。',
    test: (n) => n.segments.some((s) => s.nextOp === '&') || hasProg(n, 'nohup', 'start', 'daemonize'),
  },
];

export const RULES_BY_ID = new Map(RULES.map((r) => [r.id, r]));
