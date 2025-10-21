#!/usr/local/bin/php
<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be executed from the command line\n");
    exit(1);
}

array_shift($argv);
$mode = $argv[0] ?? '';

switch ($mode) {
    case 'prepare':
        $backupFile = $argv[1] ?? '';
        $logFile = $argv[2] ?? '';
        $enabledFlag = $argv[3] ?? 'off';
        $targetsRaw = $argv[4] ?? '';
        $sourcesRaw = $argv[5] ?? '';
        $portsRaw = $argv[6] ?? '';

        $enabled = normalize_bool($enabledFlag);
        $targets = parse_targets($targetsRaw);
        $sources = parse_list($sourcesRaw);
        $ports = parse_ports($portsRaw);
        if (empty($ports)) {
            $ports = ['443', '80', '22'];
        }

        $changed = false;

        if (!is_readable($backupFile)) {
            log_message($logFile, sprintf('backup config "%s" is not readable', $backupFile));
            echo "CHANGED=0\n";
            exit(1);
        }

        $doc = new DOMDocument('1.0', 'UTF-8');
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = true;
        if (!$doc->load($backupFile)) {
            log_message($logFile, sprintf('failed to parse XML backup "%s"', $backupFile));
            echo "CHANGED=0\n";
            exit(1);
        }
        $xpath = new DOMXPath($doc);
        $filterNode = ensure_filter_node($doc, $xpath);

        $removed = remove_existing_rules($xpath, $filterNode);
        if ($removed > 0) {
            $changed = true;
            log_message($logFile, sprintf('removed %d existing management firewall rule(s)', $removed));
        }

        if ($enabled && empty($targets)) {
            log_message($logFile, 'management firewall enabled but no MGMT targets detected');
            $enabled = false;
        }

        if ($enabled && empty($sources)) {
            log_message($logFile, 'management firewall enabled but no allowed source addresses provided');
            $enabled = false;
        }

        if ($enabled) {
            $now = time();
            foreach ($targets as $target) {
                $iface = $target['interface'];
                $address = $target['address'];
                $label = get_interface_label($xpath, $iface);
                foreach ($sources as $source) {
                    foreach ($ports as $port) {
                        $descr = sprintf('[CTX-MGMT] Allow %s management TCP port %s', $label, $port);
                        append_rule($doc, $filterNode, [
                            'type' => 'pass',
                            'interface' => $iface,
                            'ipprotocol' => 'inet',
                            'protocol' => 'tcp',
                            'statetype' => 'keep state',
                            'source' => $source,
                            'destination' => $address,
                            'destination_port' => $port,
                            'descr' => $descr,
                            'timestamp' => $now,
                        ]);
                        $changed = true;
                    }
                }

                $descr4 = sprintf('[CTX-MGMT] Block %s outbound IPv4', $label);
                append_rule($doc, $filterNode, [
                    'type' => 'block',
                    'interface' => $iface,
                    'ipprotocol' => 'inet',
                    'direction' => 'out',
                    'source' => 'any',
                    'destination' => 'any',
                    'descr' => $descr4,
                    'timestamp' => $now,
                ]);
                $changed = true;

                $descr6 = sprintf('[CTX-MGMT] Block %s outbound IPv6', $label);
                append_rule($doc, $filterNode, [
                    'type' => 'block',
                    'interface' => $iface,
                    'ipprotocol' => 'inet6',
                    'direction' => 'out',
                    'source' => 'any',
                    'destination' => 'any',
                    'descr' => $descr6,
                    'timestamp' => $now,
                ]);
            }

            log_message($logFile, sprintf('provisioned management firewall rules for %d interface(s)', count($targets)));
        } else {
            if (!$enabled) {
                log_message($logFile, 'management firewall provisioning disabled by context or missing parameters');
            }
        }

        if ($changed) {
            $doc->save($backupFile);
        }

        echo 'CHANGED=' . ($changed ? '1' : '0') . PHP_EOL;
        exit(0);

    case 'apply':
        $logFile = $argv[1] ?? '';
        log_message($logFile, 'requesting pf filter reload for management firewall rules');
        require_once 'config.inc';
        require_once 'filter.inc';
        require_once 'util.inc';
        $result = filter_configure();
        if ($result === 0 || $result === true) {
            log_message($logFile, 'pf filter reload completed for management rules');
        } else {
            log_message($logFile, sprintf('pf filter reload returned %s', var_export($result, true)));
        }
        echo "APPLIED=1\n";
        exit(0);

    default:
        fwrite(STDERR, "Usage: firewall_mgmt.php prepare <backup> <log> <enabled> <targets> <sources> <ports> | apply <log>\n");
        exit(1);
}

function normalize_bool(string $value): bool
{
    $value = strtolower(trim($value));
    return in_array($value, ['1', 'true', 'yes', 'on', 'enabled'], true);
}

function parse_targets(string $raw): array
{
    $targets = [];
    $raw = trim($raw);
    if ($raw === '') {
        return $targets;
    }

    foreach (preg_split('/\s+/', $raw) as $token) {
        if ($token === '') {
            continue;
        }
        [$iface, $address] = array_pad(explode(':', $token, 2), 2, '');
        $iface = trim($iface);
        $address = trim($address);
        if ($iface === '' || $address === '') {
            continue;
        }
        $targets[] = ['interface' => $iface, 'address' => $address];
    }

    return $targets;
}

function parse_list(string $raw): array
{
    $raw = trim($raw);
    if ($raw === '') {
        return [];
    }
    $items = [];
    foreach (preg_split('/[\s,;]+/', $raw) as $part) {
        $part = trim($part);
        if ($part === '') {
            continue;
        }
        $items[$part] = true;
    }
    return array_keys($items);
}

function parse_ports(string $raw): array
{
    $ports = [];
    $raw = trim($raw);
    if ($raw === '') {
        return $ports;
    }

    foreach (preg_split('/[\s,;]+/', $raw) as $part) {
        $part = trim($part);
        if ($part === '') {
            continue;
        }
        if (ctype_digit($part)) {
            $port = (int)$part;
            if ($port >= 1 && $port <= 65535) {
                $ports[(string)$port] = true;
            }
        }
    }

    return array_keys($ports);
}

function log_message(string $logFile, string $message): void
{
    if ($logFile === '') {
        return;
    }
    $line = sprintf("%s [context-firewall] %s\n", date('c'), $message);
    file_put_contents($logFile, $line, FILE_APPEND);
}

function ensure_filter_node(DOMDocument $doc, DOMXPath $xpath): DOMElement
{
    $nodes = $xpath->query('/pfsense/filter');
    if ($nodes->length > 0) {
        return $nodes->item(0);
    }
    $root = $doc->documentElement;
    if (!$root instanceof DOMElement) {
        $root = $doc->appendChild($doc->createElement('pfsense'));
    }
    return $root->appendChild($doc->createElement('filter'));
}

function remove_existing_rules(DOMXPath $xpath, DOMElement $filterNode): int
{
    $count = 0;
    $nodes = $xpath->query('/pfsense/filter/rule[contains(descr, "[CTX-MGMT]")]');
    foreach ($nodes as $node) {
        if ($node instanceof DOMNode) {
            $filterNode->removeChild($node);
            $count++;
        }
    }
    return $count;
}

function get_interface_label(DOMXPath $xpath, string $iface): string
{
    $node = $xpath->query('//interfaces/' . $iface . '/descr')->item(0);
    if ($node instanceof DOMNode) {
        $label = trim($node->nodeValue ?? '');
        if ($label !== '') {
            return $label;
        }
    }
    return strtoupper($iface);
}

function append_rule(DOMDocument $doc, DOMElement $filterNode, array $data): void
{
    $rule = $filterNode->appendChild($doc->createElement('rule'));
    $rule->appendChild($doc->createElement('type', $data['type'] ?? 'pass'));
    $rule->appendChild($doc->createElement('interface', $data['interface'] ?? 'lan'));
    $rule->appendChild($doc->createElement('ipprotocol', $data['ipprotocol'] ?? 'inet'));

    if (!empty($data['direction'])) {
        $rule->appendChild($doc->createElement('direction', $data['direction']));
    }

    if (!empty($data['protocol'])) {
        $rule->appendChild($doc->createElement('protocol', $data['protocol']));
    }

    if (!empty($data['statetype'])) {
        $rule->appendChild($doc->createElement('statetype', $data['statetype']));
    }

    $tracker = $doc->createElement('tracker', generate_tracker());
    $rule->appendChild($tracker);

    $descrText = $data['descr'] ?? '';
    if ($descrText !== '') {
        $descrNode = $doc->createElement('descr');
        $descrNode->appendChild($doc->createCDATASection($descrText));
        $rule->appendChild($descrNode);
    }

    $timestamp = $data['timestamp'] ?? time();
    $rule->appendChild(build_timestamp_node($doc, 'created', $timestamp));
    $rule->appendChild(build_timestamp_node($doc, 'updated', $timestamp));

    $sourceNode = $rule->appendChild($doc->createElement('source'));
    append_address($doc, $sourceNode, $data['source'] ?? 'any');

    $destNode = $rule->appendChild($doc->createElement('destination'));
    append_address($doc, $destNode, $data['destination'] ?? 'any');

    if (!empty($data['destination_port'])) {
        $destNode->appendChild($doc->createElement('port', $data['destination_port']));
    }
}

function append_address(DOMDocument $doc, DOMElement $parent, string $value): void
{
    $value = trim($value);
    if ($value === '' || strtolower($value) === 'any') {
        $parent->appendChild($doc->createElement('any'));
        return;
    }

    if (preg_match('/^[A-Za-z0-9_]+$/', $value) && !preg_match('/\./', $value) && !preg_match('/:/', $value)) {
        $parent->appendChild($doc->createElement('network', $value));
        return;
    }

    $parent->appendChild($doc->createElement('address', $value));
}

function build_timestamp_node(DOMDocument $doc, string $name, int $timestamp): DOMElement
{
    $node = $doc->createElement($name);
    $node->appendChild($doc->createElement('time', (string)$timestamp));
    $node->appendChild($doc->createElement('username', 'context'));
    return $node;
}

function generate_tracker(): string
{
    static $offset = 0;
    $offset++;
    $base = (int)round(microtime(true) * 1000000);
    return (string)($base + $offset);
}
