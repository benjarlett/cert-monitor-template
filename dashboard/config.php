<?php
declare(strict_types=1);

/**
 * Configuration for the local cert-monitor dashboard.
 *
 * The dashboard is a read-only view over the hosting account, except for the
 * "Add a site" panel, which can run the same helper the command line uses. It
 * never issues, deploys or removes anything on its own: the helper probes first
 * and the page requires an explicit confirmation step.
 *
 * No secret is ever rendered: the ntfy topic exists only as a "configured" flag.
 */

// SSH access to the hosting account, using the dedicated local key.
const SSH_KEY = '~/.ssh/cert-monitor';
const SSH_HOST = 'youruser@your-host.example.com';
const SSH_PORT = '21098';

// Host keys verified against the runbook fingerprints. Kept in the app's own
// file so the page does not depend on ~/.ssh/known_hosts, and because the path
// contains no spaces (OpenSSH silently truncates a UserKnownHostsFile value that
// does).
const KNOWN_HOSTS = '~/.ssh/known_hosts';

// Remote commands. status.py assembles everything the page needs as one JSON blob.
const REMOTE_STATUS = 'python3 $HOME/.cert-monitor/status.py';
const REMOTE_REFRESH = 'python3 $HOME/.cert-monitor/status.py --refresh';
const REMOTE_MANAGE = '/home/youruser/.cert-monitor/manage-site.sh';

// Local clone of the off-account monitor, for its run history.
const CLOUD_CLONE = '/home/youruser/Sites/cert-monitor/cloud';

// Response cache, so reloading the page does not re-run the remote check.
const CACHE_DIR = '/home/youruser/Sites/cert-monitor/cache';
const CACHE_FILE = CACHE_DIR . '/status.json';
const CACHE_TTL = 300;

// Input validation for the add-a-site form. A shell is never involved, but these
// also stop nonsense reaching the helper.
const DOMAIN_RE = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i';
const OWNER_RE = '/^[a-z0-9][a-z0-9._-]{0,31}$/i';

/**
 * Build the argv for an ssh call. Returned as an array so proc_open never
 * involves a local shell, and the remote command is escaped for the remote one.
 */
function ssh_argv(string $remoteCommand): array
{
    return [
        '/usr/bin/ssh',
        '-i', SSH_KEY,
        '-p', SSH_PORT,
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'ConnectTimeout=20',
        '-o', 'UserKnownHostsFile=' . KNOWN_HOSTS,
        SSH_HOST,
        $remoteCommand,
    ];
}

/**
 * Run a local command and return [exitCode, stdout, stderr].
 * $stdin, when given, is written to the process before its input is closed.
 */
function run_argv(array $argv, int $timeoutSeconds = 90, ?string $stdin = null): array
{
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open($argv, $descriptors, $pipes);
    if (!is_resource($process)) {
        return [127, '', 'could not start the process'];
    }
    if ($stdin !== null) {
        fwrite($pipes[0], $stdin);
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $stdout = '';
    $stderr = '';
    $deadline = time() + $timeoutSeconds;
    while (true) {
        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
        $status = proc_get_status($process);
        if (!$status['running']) {
            break;
        }
        if (time() > $deadline) {
            proc_terminate($process, 9);
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            return [124, $stdout, trim($stderr . "\ntimed out after {$timeoutSeconds}s")];
        }
        usleep(150000);
    }
    $stdout .= stream_get_contents($pipes[1]);
    $stderr .= stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($process);

    return [$exit, $stdout, $stderr];
}
