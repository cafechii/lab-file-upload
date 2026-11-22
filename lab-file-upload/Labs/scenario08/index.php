<?php
// File Upload · Scenario 08 — Double Extension
$pageTitle = 'Web Shell Upload via Double Extension Bypass';
$scenarioNumber = 8;
$nextScenario = sprintf('../scenario%02d/', 9);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'The server checks only last extension.',
    'But Apache runs file if it contains .php anywhere, like shell.php.png.',
    'Validation sees .png (allowed) but Apache sees .php and runs it.',
    'Standard: Double Extension Bypass.',
    'Goal: Upload shell.php.png',
];
$labHint = [
    'In Burp, turn Intercept OFF first and try upload shell.php.png with PHP code.',
    'If blocked, turn Intercept ON and send to Repeater.',
    'File name must be exactly shell.php.png (first .php then .png).',
    'Server checks last extension .png (allowed) but Apache runs .php part.',
    'Content: <?php echo \'pwned\'; ?>',
    'Click Send. You should get Congratulations. Click link to run.',
    'Standard: Double Extension Bypass.',
];

$labRootCause = [
    'cwe' => 'CWE-434: Double Extension',
    'owasp' => 'OWASP: Double Extension Bypass',
    'bad' => [
        'explanation' => [
        '<strong>Programmer checked only last extension.</strong> He saw .png at end and allowed it, but Apache runs file if it contains .php anywhere like shell.php.png.',
        '<strong>Mistake:</strong> Used pathinfo() to get last extension only, but Apache\'s AddHandler checks all extensions.',
        '<strong>Why it happens:</strong> Developer did not know Apache behavior with multiple extensions.',
        ],
        'code' => [
        '// VULNERABLE - Only checks last extension!',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION)); // Gets last ext only!',
        'if ($ext == \'png\' || $ext == \'jpg\') {',
        '  move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '}',
        '?>',
        '// Attacker uploads shell.php.png with <?php system($_GET[\'cmd\']); ?>',
        '// pathinfo gives \'png\' - allowed!',
        '// But Apache: if configured with AddHandler php5-script .php, it sees .php in name and runs as PHP!',
        ],
        'impact' => 'Attacker uploads shell.php.png and gets RCE if Apache is configured to parse .php anywhere in filename. Bypasses extension check.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Check all extensions in filename, not just last. Use whitelist and reject if any blacklisted extension appears anywhere. Or rename file to random name with only one extension.',
        '<strong>Rule:</strong> Validate entire filename, not just last extension.',
        ],
        'code' => [
        '// SECURE - Check all parts of filename',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$parts = explode(\'.\', $filename);',
        'foreach ($parts as $part) {',
        '  if (in_array(strtolower($part), [\'php\',\'phtml\',\'php5\',\'pht\',\'phar\'])) {',
        '    die(\'PHP extension found in filename!\');',
        '  }',
        '}',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Check all extensions in filename, not just last',
        'Reject if any blacklisted extension appears anywhere in name',
        'Better: generate random filename with only one extension',
        'Use whitelist: only allow png, jpg, jpeg, gif',
        'Disable PHP execution in uploads: php_flag engine off in .htaccess',
        'Configure Apache to not parse multiple extensions',
        ],
    ],
];
$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error '.(int)$file['error']];
    } else {
        $safeName = basename($file['name']);
        // Isolation: block other bypass techniques
        $isolationBlocked = false;
        if (stripos($safeName, '%00') !== false || strpos($safeName, "\0") !== false) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Null byte not allowed in double extension lab.']; http_response_code(422); }
        elseif (strpos($safeName, ';') !== false) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Semicolon not allowed. Use double extension.']; http_response_code(422); }
        elseif (preg_match('/\.php[\. ]+$/i', $safeName) || preg_match('/%20$/i', $safeName)) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Trailing dot/space not allowed. Use double extension like .php.png']; http_response_code(422); }
        elseif (preg_match('/\.php5|\.phtml|\.phar|\.pht/i', $safeName)) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Alt extension not allowed. Use .php.png']; http_response_code(422); }

        if (!$isolationBlocked) {
            $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
            if ($ext === 'php') {
                $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'The final .php extension is blocked. Use a double extension.'];
                http_response_code(422);
            } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
                $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Could not save.'];
            } else {
                $link = 'uploads/'.rawurlencode($safeName);
                if (preg_match('/\.php\.(?:jpg|jpeg|png|gif)$/i', $safeName)) {
                    $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 08.','body'=>$safeName.' passed because its name contains .php before the final extension.'];
                } else {
                    $flash = ['kind'=>'fail','title'=>'Not solved yet','body'=>$safeName.' was saved, but it does not contain .php before the final extension.'];
                    http_response_code(422);
                }
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 08 · UPLOAD</span><h1>Double Extension Bypass</h1><p>Server checks final .png, Apache executes inner .php. Upload shell.php.png.</p>
<div class="panel upload-form"><h2>Upload an Image!</h2><form action="" method="POST" enctype="multipart/form-data"><label for="fileToUpload">Select a file:</label><input type="file" name="fileToUpload" id="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next scenario &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
