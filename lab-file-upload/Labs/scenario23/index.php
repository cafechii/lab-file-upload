<?php
// File Upload · Scenario 23 — Web Shell Upload via Race Condition - FIXED 2026-09-28
// Now: allows php upload, keeps file for 2 sec after response, then deletes - race window after upload

$pageTitle = 'Web Shell Upload via Race Condition (TOCTOU)';
$scenarioNumber = 23;
$nextScenario = sprintf('../scenario%02d/', 24);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Cleanup old php files older than 2 seconds (race window)
foreach (glob($uploadsDir . '/*.{php,phtml,php5,phar}', GLOB_BRACE) as $oldFile) {
    if (is_file($oldFile) && (time() - filemtime($oldFile)) > 2) {
        @unlink($oldFile);
    }
}

$labDescription = [
    'File is uploaded and made public before antivirus scan deletes it.',
    'There is small time window (race condition) to execute file.',
    'Upload PHP file, then quickly request it before AV deletes.',
    'Standard: Race Condition / Time-of-Check Time-of-Use.',
    'Goal: Race to execute file before deletion.',
];

$labHint = [
    'Create shell.php with <?php echo \'pwned\'; ?>',
    'Upload it. Server saves file and shows link, but deletes after 2 seconds.',
    'You need to race: upload and immediately GET the file.',
    'Use Burp Intruder or Turbo Intruder: one thread uploads, other thread GETs /scenario23/uploads/shell.php',
    'Or use Python script to loop request quickly.',
    'If you are fast enough, you get execution before deletion.',
    'Standard: Race Condition Upload.',
];

$labRootCause = [
    'cwe' => 'CWE-362: Race Condition',
    'owasp' => 'OWASP: Race Condition Upload',
    'bad' => [
        'explanation' => [
        '<strong>Programmer uploaded file, made it public, then antivirus scanned and deleted it after 2 seconds.</strong> There is small time window where file exists and can be executed before deletion.',
        '<strong>Mistake:</strong> File is accessible before AV check completes. Upload -> save -> public -> AV scan -> delete. Attacker can race to request file before deletion.',
        '<strong>Why it happens:</strong> Developer wanted AV protection but implemented as after-upload check, not before.',
        ],
        'code' => [
        '// VULNERABLE - Race condition!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        'echo \'File uploaded: <a href="uploads/\' . $filename . \'">Link</a>\'; // Public immediately!',
        '// Then AV scans in background and deletes after 2 sec',
        '// Attacker races: upload shell.php and immediately GET /uploads/shell.php before AV deletes!',
        '?>',
        ],
        'impact' => 'Attacker uploads PHP shell, quickly requests it before AV deletes. If fast enough, gets RCE. Race condition window is small but exploitable with Intruder or script.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Scan file before making it public. Save to quarantine folder not accessible via web, scan, then move to public only if clean.',
        '<strong>Rule:</strong> Never make file public before validation completes.',
        ],
        'code' => [
        '// SECURE - Scan before public',
        '<?php',
        '$tmp = $_FILES[\'file\'][\'tmp_name\'];',
        '$quarantine = \'/tmp/quarantine/\' . bin2hex(random_bytes(16));',
        'move_uploaded_file($tmp, $quarantine);',
        '$result = shell_exec(\'clamscan \' . escapeshellarg($quarantine) . \' 2>&1\');',
        'if (strpos($result, \'FOUND\') !== false) {',
        '  unlink($quarantine);',
        '  die(\'Virus detected\');',
        '}',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'rename($quarantine, \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Save uploaded file to quarantine folder not accessible via web',
        'Scan file with AV before making public',
        'Only move to public folder if scan passes',
        'Use random filename',
        'Check extension whitelist before scan',
        'Set short timeout for scan',
        'Use in-memory scan if possible - don\'t save before scan',
        'Disable PHP execution in uploads as defense in depth',
        ],
    ],
];

$link = null;
$linkLabel = 'See the file';
$flash = null;

function isImageFile(string $path): bool
{
    $size = @getimagesize($path);
    if (!$size) return false;
    $mime = $size['mime'] ?? '';
    return in_array($mime, ['image/jpeg','image/png','image/gif'], true);
}

$file = $_FILES['fileToUpload'] ?? null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                  'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').'];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        $dest = $uploadsDir . '/' . $safeName;

        if (!move_uploaded_file($file['tmp_name'], $dest)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                      'body'  => 'The server could not save the file.'];
        } else {
            $link = 'uploads/' . rawurlencode($safeName);
            $isImage = isImageFile($dest);

            if (in_array($ext, ['jpg','jpeg','png','gif'], true) && $isImage) {
                http_response_code(202);
                $flash = ['kind' => 'info', 'title' => 'Image uploaded (202)',
                          'body'  => 'Image passed validation and kept. For race test, upload shell.php - it will stay 2 sec then AV deletes.'];
            } else {
                // PHP or other file - allow upload but warn it will be deleted after 2 sec (race window)
                touch($dest); // update mtime to now for 2 sec window
                if ($ext === 'php' || $ext === 'phtml' || $ext === 'php5') {
                    $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 23 - File uploaded, race window open!',
                              'body'  => 'shell.php uploaded! File exists for 2 seconds before AV deletes. Quickly GET /scenario23/uploads/' . $safeName . ' to execute! If you see pwned, you won the race.'];
                } else {
                    http_response_code(202);
                    $flash = ['kind' => 'info', 'title' => 'File uploaded (202) - race window 2 sec',
                              'body'  => 'File ' . $safeName . ' uploaded and exists for 2 seconds. GET /scenario23/uploads/' . $safeName . ' quickly before AV deletes it.'];
                }
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
        <span class="num">File Upload · SCENARIO 23 · UPLOAD</span>
        <h1>Race Condition (TOCTOU)</h1>
        <p>File exists briefly (2 sec) before AV deletes it. Upload shell.php then quickly GET it. Now allows .php upload.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <p style="font-size:12px; opacity:0.8;">Allows .php, .jpg, .png - PHP files stay 2 sec then deleted. Race to GET!</p>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit" name="submit" value="Upload">Upload</button>
            </form>
        </div>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">
                    Next scenario &rarr;
                </a>
            </div>
        <?php endif; ?>

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>" target="_blank" rel="noopener"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?> - Click quickly! 2 sec window</a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
