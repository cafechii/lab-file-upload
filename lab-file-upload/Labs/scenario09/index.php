<?php
// File Upload · Scenario 09 — Null Byte Truncation
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via Null Byte Injection';
$scenarioNumber = 9;
$nextScenario = sprintf('../scenario%02d/', 10);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'Old PHP code stops filename at null byte %00.',
    'Validation sees shell.php%00.jpg as .jpg (allowed) but saves as shell.php.',
    'Modern PHP fixed this, but this lab simulates old behavior.',
    'Standard: Null Byte Bypass.',
    'Goal: Upload shell.php%00.jpg',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Open Burp Suite, Proxy > Intercept ON.',
    'Upload shell.php normally - it will be blocked.',
    'Send POST /scenario09/ request to Repeater.',
    'Change filename to shell.php%00.jpg (write percent zero zero). Lab does urldecode.',
    'Or try shell.php%00.png. Use Burp Decoder to insert real null byte 0x00.',
    'Content: <?php echo \'pwned\'; ?>',
    'Send. Server sees .jpg but saves as .php before null.',
    'Click link. Standard: Null Byte Injection. Works only with Repeater, not browser.',
];

$labRootCause = [
    'cwe' => 'CWE-158: Null Byte Injection',
    'owasp' => 'OWASP: Null Byte Bypass',
    'bad' => [
        'explanation' => [
        '<strong>Old PHP and C code stopped filename at null byte %00.</strong> Validation saw shell.php%00.jpg as .jpg (allowed) but file system saved as shell.php before null byte.',
        '<strong>Mistake:</strong> Used urldecode() on filename and then checked extension. Attacker sends shell.php%00.jpg, urldecode makes it shell.php null byte jpg, C function stops at null and saves as shell.php.',
        '<strong>Why it happens:</strong> Legacy code in C and old PHP used null byte as string terminator.',
        ],
        'code' => [
        '// VULNERABLE - Simulates old PHP null byte behavior!',
        '<?php',
        '$filename = urldecode($_FILES[\'file\'][\'name\']); // shell.php%00.jpg',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION)); // Sees jpg - allowed!',
        'if ($ext == \'jpg\' || $ext == \'png\') {',
        '  $realName = strtok($filename, "\\0"); // Stops at null, returns shell.php',
        '  move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $realName); // Saves as shell.php!',
        '}',
        '?>',
        '// Attacker: filename = shell.php%00.jpg - Validation sees jpg, but saved as shell.php - RCE!',
        ],
        'impact' => 'Attacker uses null byte %00 to truncate filename. Validation sees .jpg but file saved as .php. Gets RCE. Old PHP <5.3 vulnerable.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Modern PHP (5.3.4+) fixed null byte. But still, reject filenames with %00, null byte. Don\'t use urldecode on filename. Use basename() and whitelist.',
        '<strong>Rule:</strong> Reject null bytes and URL encoded null.',
        ],
        'code' => [
        '// SECURE - Reject null bytes',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        'if (strpos($filename, "\\0") !== false || strpos($filename, \'%00\') !== false) {',
        '  die(\'Null byte detected\');',
        '}',
        '$filename = basename($filename);',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Reject filenames containing null byte or %00',
        'Don\'t use urldecode() on filename',
        'Use basename() to get only filename, no path',
        'Use whitelist for extensions',
        'Use modern PHP version 7+ which fixed null byte',
        'Randomize filename',
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
        $decoded   = urldecode($file['name']);
        $checked   = strtolower(pathinfo($decoded, PATHINFO_EXTENSION));
        $truncated = strtok($decoded, "\0");
        // Keep traversal out of this lab: only the null-byte truncation should
        // change the final stored name.
        $stored    = basename($truncated !== false ? $truncated : $decoded);

        if (!in_array($checked, ['jpg', 'jpeg', 'png'], true)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'The filename does not end in .jpg or .png.'];
        } elseif ($stored === '' || !preg_match('/\.php$/i', $stored) || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $stored)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                      'body'  => 'The truncated filename is not a PHP filename.'];
        } else {
            $link  = 'uploads/' . rawurlencode($stored);
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 09.',
                      'body'  => 'The check saw .png, but storage used the truncated .php name.'];
        }
    }
}

// Keep the verdict meaningful to Burp as well as to the page.
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
        <span class="num">File Upload · SCENARIO 09 · UPLOAD</span>
        <h1>Null Byte Injection</h1>
        <p>Validation sees .jpg, filesystem truncates at %00 and saves as .php. Use Burp Repeater.</p>

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
