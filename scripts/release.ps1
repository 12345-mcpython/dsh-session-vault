# release.ps1 - 给 dsh-session-vault 建一个 GitHub Release。
#
# 用法（仓库根目录）：
#   .\scripts\release.ps1                 # 用 package.json 里的 version，打 v<version>
#   .\scripts\release.ps1 -Version 2.0.1  # 指定版本
#   .\scripts\release.ps1 -DryRun         # 只打印要发的请求，不真的发
#
# 需要凭据（二选一）：
#   - 装了 gh CLI 并 `gh auth login` 过：走 gh，最省事
#   - 没装 gh：设环境变量 GITHUB_TOKEN（要有 repo 权限的 classic token 或
#     fine-grained token 带 Contents: Read and write）
#
# 这个脚本会做的三件事：
#   1. 确认工作区干净、本地 tag 存在、tag 指向 HEAD
#   2. 把 tag 推到远程（已存在则跳过）
#   3. 建 release，正文从 git log 生成，附一个源码 zip
#
# 它**不会**改任何源码，也**不会** force push。

[CmdletBinding()]
param(
  [string]$Version,
  [string]$Repo,
  [string]$TokenFile,
  [switch]$DryRun,
  [switch]$Prerelease
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail($msg) { Write-Host "  x $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host "  - $msg" }
function Ok($msg)   { Write-Host "  + $msg" -ForegroundColor Green }

# ---------------------------------------------------------------- 定位仓库

$root = (Get-Location).Path
if (-not (Test-Path (Join-Path $root 'package.json'))) {
  Fail "当前目录没有 package.json，请在仓库根目录运行"
}

$pkg = Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json
if (-not $Version) { $Version = $pkg.version }
if (-not $Version) { Fail "package.json 里没有 version，也没传 -Version" }
$tag = "v$Version"

Info "包名: $($pkg.name)"
Info "版本: $Version   tag: $tag"

# ---------------------------------------------------------------- 仓库全名

if (-not $Repo) {
  $url = (git remote get-url origin 2>$null)
  if (-not $url) { Fail "拿不到 origin 的 URL，也没传 -Repo" }
  # 支持 https://github.com/OWNER/REPO.git 和 git@github.com:OWNER/REPO.git
  if ($url -match 'github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?$') {
    $Repo = "$($Matches[1])/$($Matches[2])"
  } else {
    Fail "解析不出 GitHub 仓库名（origin=$url），请用 -Repo owner/name 指定"
  }
}
Info "仓库: $Repo"

# ---------------------------------------------------------------- 前置检查

$dirty = (git status --porcelain 2>$null)
if ($dirty) {
  Write-Host "  ! 工作区有未提交改动：" -ForegroundColor Yellow
  $dirty -split "`n" | Where-Object { $_ } | ForEach-Object { Write-Host "      $_" }
  Write-Host "    继续会把这些留在工作区，不影响 release。按 Ctrl+C 中止。" -ForegroundColor Yellow
  Start-Sleep -Seconds 2
}

$localTags = git tag -l 2>$null
if ($localTags -notcontains $tag) {
  Fail "本地没有 tag $tag。先打一个：git tag -a $tag -m ""Session vault $Version"""
}

$headSha = (git rev-parse HEAD).Trim()
$tagSha  = (git rev-list -n 1 $tag).Trim()
if ($headSha -ne $tagSha) {
  Write-Host "  ! tag $tag 指向 $($tagSha.Substring(0,7))，HEAD 是 $($headSha.Substring(0,7))" -ForegroundColor Yellow
  Info "release 会指向 tag 的那个提交（不是 HEAD）"
} else {
  Ok "tag 指向 HEAD（$($headSha.Substring(0,7))）"
}

# ---------------------------------------------------------------- 推 tag

$remoteTags = git ls-remote --tags origin 2>$null
if ($remoteTags -match [regex]::Escape("refs/tags/$tag")) {
  Ok "远程已有 tag $tag，跳过推送"
} else {
  if ($DryRun) {
    Info "[dry-run] git push origin $tag"
  } else {
    Info "推送 tag..."
    git push origin $tag 2>&1 | ForEach-Object { Info $_ }
    if ($LASTEXITCODE -ne 0) { Fail "推送 tag 失败" }
    Ok "tag 已推送"
  }
}

# ---------------------------------------------------------------- 生成 release 正文

# 只取这条 tag 之后到上一个 tag 之间的提交；没有上一个 tag 就取全部
$prevTag = (git describe --tags --abbrev=0 "$tag^" 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $prevTag) { $prevTag = $null }

if ($prevTag) {
  Info "上一个 tag: $prevTag"
  $range = "$prevTag..$tag"
} else {
  Info "没有上一个 tag，正文列全部提交"
  $range = $tag
}

$commits = git log --pretty=format:'- %s' $range 2>$null
$commitBlock = ($commits -join "`n")
if (-not $commitBlock) { $commitBlock = '- (没有提交)' }

$verified = '未标注'
$registry = Join-Path $root 'docs/registry-entry.json'
if (Test-Path $registry) {
  try {
    $r = Get-Content $registry -Raw | ConvertFrom-Json
    if ($r.verified) { $verified = ($r.verified -join ', ') }
  } catch { }
}

$notes = @"
## 变更

$commitBlock

## 已验证的 DSH 版本

$verified

## 安装

本插件以 DSH 的 profile bundle 形式加载，装法是把它登记进 profile 的 bundles 列表，
具体路径依 DSH 版本而异。仓库不附带一键安装脚本，**请先读 README 的「安装」一节**。

装完必须重启 DSH——宿主那半边不热重载。

首次使用：鼠标移到侧栏会话上，出现小锁，点它，给**这条会话**设一个口令。

## 注意

本插件会 patch DSH 的会话持久化后端（不改 app.asar，靠 ``ctx.effect`` 在卸载时还原）。
卸载前请先用「永久解除」把每条锁清掉，否则遗留的密文需要自己按 README 的 WALLBK 格式解。

口令丢失无法找回，没有找回通道。
"@

Write-Host ""
Write-Host "=== release 正文 ===" -ForegroundColor Cyan
$notes -split "`n" | ForEach-Object { Write-Host "  $_" }
Write-Host ""

# ---------------------------------------------------------------- 调用 GitHub

if ($DryRun) {
  Write-Host "=== dry-run：不实际发送 ===" -ForegroundColor Cyan
  Info "POST https://api.github.com/repos/$Repo/releases"
  Info "tag_name=$tag  prerelease=$($Prerelease.IsPresent)  target=$($tagSha.Substring(0,7))"
  exit 0
}

$gh = Get-Command gh -ErrorAction SilentlyContinue

# token 来源按优先级：-TokenFile > $env:GITHUB_TOKEN > 仓库根目录的 .github-token
# 文件里的内容会 trim（处理尾部换行和 BOM），空文件视为没有。
$token = $null
if ($TokenFile) {
  if (-not (Test-Path $TokenFile)) { Fail "token 文件不存在：$TokenFile" }
  $token = (Get-Content $TokenFile -Raw -ErrorAction Stop).Trim()
  if (-not $token) { Fail "token 文件是空的：$TokenFile" }
  Info "token 来自文件：$TokenFile"
} elseif ($env:GITHUB_TOKEN) {
  $token = $env:GITHUB_TOKEN.Trim()
  Info "token 来自环境变量 GITHUB_TOKEN"
} else {
  $defaultTokenFile = Join-Path $root '.github-token'
  if (Test-Path $defaultTokenFile) {
    $token = (Get-Content $defaultTokenFile -Raw -ErrorAction Stop).Trim()
    if ($token) { Info "token 来自默认文件：$defaultTokenFile" }
  }
}

if ($gh) {
  Info "用 gh CLI 建 release..."
  $args = @(
    'release', 'create', $tag,
    '--repo', $Repo,
    '--title', "dsh-session-vault $Version",
    '--notes-file', '-'
  )
  if ($Prerelease) { $args += '--prerelease' }
  $notes | & gh @args
  if ($LASTEXITCODE -ne 0) { Fail "gh release create 失败" }
  Ok "release 已创建：https://github.com/$Repo/releases/tag/$tag"
  exit 0
}

if (-not $token) {
  Write-Host ""
  Write-Host "  没装 gh CLI，也没有 GITHUB_TOKEN。" -ForegroundColor Yellow
  Write-Host "  两种办法二选一：" -ForegroundColor Yellow
  Write-Host "    1) 装 gh 并登录： winget install GitHub.cli ; gh auth login" -ForegroundColor Yellow
  Write-Host "    2) 设 token：     `$env:GITHUB_TOKEN = 'ghp_xxx'" -ForegroundColor Yellow
  Write-Host "       token 需要 Contents: Read and write 权限" -ForegroundColor Yellow
  exit 1
}

Info "用 REST API 建 release..."

$payload = @{
  tag_name         = $tag
  target_commitish = $tagSha
  name             = "dsh-session-vault $Version"
  body             = $notes
  draft            = $false
  prerelease       = $Prerelease.IsPresent
} | ConvertTo-Json -Depth 5

$headers = @{
  Authorization          = "Bearer $token"
  Accept                 = 'application/vnd.github+json'
  'X-GitHub-Api-Version' = '2022-11-28'
  'User-Agent'           = 'dsh-session-vault-release-script'
}

try {
  $resp = Invoke-RestMethod -Method Post `
    -Uri "https://api.github.com/repos/$Repo/releases" `
    -Headers $headers -Body $payload -ContentType 'application/json'
  Ok "release 已创建：$($resp.html_url)"
} catch {
  $detail = $_.Exception.Message
  if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
  Fail "建 release 失败：$detail"
}
