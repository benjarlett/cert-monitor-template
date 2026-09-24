<?php
declare(strict_types=1);

/**
 * JSON API for the dashboard.
 *
 *   api.php?action=status            cached view of the hosting account
 *   api.php?action=refresh           force a fresh remote check, then return it
 *   api.php?action=cloud             the off-account monitor's recent runs (local, no network)
 *   api.php?action=preview&domain=…  run manage-site.sh --dry-run: checks only, changes nothing
 *   api.php?action=add&domain=…      run manage-site.sh for real (the page confirms first)
 *
 * Errors come back as JSON with an "error" key so the page can say something
 * useful instead of failing blank.
 */

require __DIR__ . '/config.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

/** Serve from cache when fresh, otherwise run the remote collector. */
function collect_status(bool $force): array
{
    if (!$force && is_file(CACHE_FILE)) {
        $age = time() - filemtime(CACHE_FILE);
        if ($age >= 0 && $age < CACHE_TTL) {
            $cached = json_decode((string) file_get_contents(CACHE_FILE), true);
            if (is_array($cached)) {
                $cached['served_from_cache'] = true;
                $cached['cache_age_seconds'] = $age;
                return $cached;
            }
        }
    }

    $argv = ssh_argv($force ? REMOTE_REFRESH : REMOTE_STATUS);
    [$exit, $stdout, $stderr] = run_argv($argv, $force ? 150 : 90);

    $decoded = json_decode($stdout, true);
    if ($exit !== 0 || !is_array($decoded)) {
        return [
            'error' => 'Could not reach the hosting account.',
            'exit_code' => $exit,
            'stderr' => trim($stderr),
            'stdout_head' => substr(trim($stdout), 0, 400),
        ];
    }

    if (!is_dir(CACHE_DIR)) {
        @mkdir(CACHE_DIR, 0700, true);
    }
    @file_put_contents(CACHE_FILE, json_encode($decoded, JSON_PRETTY_PRINT));

    $decoded['served_from_cache'] = false;
    $decoded['cache_age_seconds'] = 0;
    return $decoded;
}

/** Recent runs of the off-account monitor, straight from the local clone. */
function collect_cloud(): array
{
    $history = CLOUD_CLONE . '/.state/history.log';
    $lines = [];
    if (is_file($history)) {
        $all = file($history, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $lines = array_reverse(array_slice($all, -14));
    }
    [$exit, $stdout] = run_argv(['/usr/bin/git', '-C', CLOUD_CLONE, 'log',
        '--date=short', '--pretty=format:%h|%ad|%s', '-8'], 20);
    $commits = [];
    foreach (array_filter(explode("\n", $stdout)) as $line) {
        $parts = explode('|', $line, 3);
        if (count($parts) === 3) {
            $commits[] = ['hash' => $parts[0], 'date' => $parts[1], 'subject' => $parts[2]];
        }
    }
    return [
        'clone' => CLOUD_CLONE,
        'repo' => 'your-user/cert-expiry-monitor',
        'history' => $lines,
        'commits' => $commits,
        'git_ok' => $exit === 0,
    ];
}

/** Accept "https://www.example.co.uk/path" as readily as "example.co.uk". */
function normalise_domain(string $raw): string
{
    $domain = strtolower(trim($raw));
    $domain = preg_replace('#^https?://#', '', $domain) ?? $domain;
    $domain = preg_split('#[/?\s]#', $domain)[0] ?? $domain;
    $domain = rtrim($domain, '.');
    return preg_replace('#^www\.#', '', $domain) ?? $domain;
}

/**
 * Run the add helper on the hosting account.
 *
 * $dryRun maps to --dry-run, which performs every check without issuing,
 * deploying, or editing either monitor list. A real run passes --yes and the
 * owner label on stdin (only consulted for sites that are not served here).
 */
function manage_site(string $domain, bool $dryRun, string $owner): array
{
    $command = REMOTE_MANAGE . ' add ' . escapeshellarg($domain)
        . ($dryRun ? ' --dry-run' : ' --yes');
    [$exit, $stdout, $stderr] = run_argv(
        ssh_argv($command),
        $dryRun ? 150 : 300,
        $owner . "\n"
    );
    return [
        'domain' => $domain,
        'dry_run' => $dryRun,
        'exit_code' => $exit,
        'output' => trim($stdout),
        'stderr' => trim($stderr),
    ];
}

$action = $_REQUEST['action'] ?? 'status';
switch ($action) {
    case 'preview':
    case 'add':
        $domain = normalise_domain((string) ($_REQUEST['domain'] ?? ''));
        $owner = strtolower(trim((string) ($_REQUEST['owner'] ?? ''))) ?: 'other';

        if (!preg_match(DOMAIN_RE, $domain)) {
            echo json_encode(['error' => "That does not look like a domain: '" . $domain . "'"]);
            break;
        }
        if (!preg_match(OWNER_RE, $owner)) {
            echo json_encode(['error' => 'The owner label may only use letters, digits, dot, dash and underscore.']);
            break;
        }

        $result = manage_site($domain, $action === 'preview', $owner);
        if ($action === 'add' && $result['exit_code'] === 0) {
            // the list changed, so drop the cached status; the page forces a fresh read
            @unlink(CACHE_FILE);
        }
        echo json_encode($result);
        break;

    case 'refresh':
        echo json_encode(collect_status(true));
        break;

    case 'cloud':
        echo json_encode(collect_cloud());
        break;

    case 'status':
    default:
        echo json_encode(collect_status(false));
        break;
}
