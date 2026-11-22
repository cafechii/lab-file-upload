<?php
// File Upload · Scenario 10 — Reflected Filename XSS
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Stored XSS via File Name Upload';
$scenarioNumber = 10;
$nextScenario = sprintf('../scenario%02d/', 11);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'The app shows uploaded filename without HTML escape.',
    'You can inject HTML or JavaScript via filename.',
    'This is Stored XSS via filename.',
    'Goal: Upload file with XSS payload in name.',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Turn Burp Intercept ON.',
    'Create any file, for example test.png, but set filename to <img src=x onerror=alert(document.domain)>.png',
    'In Burp, check Content-Disposition has XSS in filename.',
    'Click Forward. The page prints filename without escape and XSS runs.',
    'You will see alert popup in browser.',
    'Standard: Stored XSS via Filename.',
];

$labRootCause = [
    'cwe' => 'CWE-79: XSS via Filename',
    'owasp' => 'OWASP: Stored XSS in Upload',
    'bad' => [
        'explanation' => [
        '<strong>Programmer showed uploaded filename without HTML escaping.</strong> He printed filename directly in HTML page.',
        '<strong>Mistake:</strong> Used echo $_FILES[\'file\'][\'name\'] without htmlspecialchars(). Attacker can put <script> or <img onerror> in filename and it runs as JavaScript.',
        '<strong>Why it happens:</strong> Developer forgot that filename is user input and must be escaped like any other input.',
        ],
        'code' => [
        '// VULNERABLE - No HTML escaping on filename!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        'echo \'File uploaded: \' . $filename; // XSS here!',
        '?>',
        '// Attacker uploads file named <img src=x onerror=alert(document.domain)>.png',
        '// Browser sees <img> tag and runs onerror JavaScript! Stored XSS!',
        ],
        'impact' => 'Attacker injects XSS via filename. When victim visits page that shows filename, JavaScript runs. Can steal cookies, session, redirect to evil site. Stored XSS.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Always escape output with htmlspecialchars(). Treat filename as user input, not safe text.',
        '<strong>Rule:</strong> Escape all user input when printing in HTML.',
        ],
        'code' => [
        '// SECURE - Escape filename with htmlspecialchars',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$safeFilename = basename($filename);',
        '$ext = strtolower(pathinfo($safeFilename, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        'echo \'File uploaded: \' . htmlspecialchars($safeFilename, ENT_QUOTES);',
        '?>',
        ],
        'steps' => [
        'Always use htmlspecialchars() when printing filename in HTML',
        'Use ENT_QUOTES to escape both single and double quotes',
        'Generate random filename - don\'t use user filename in HTML at all',
        'Use basename() to remove path',
        'Validate extension whitelist',
        'Set Content-Security-Policy header to block inline scripts',
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
        $reflected = 'uploads/' . $file['name'];

        if (preg_match('/<[^>]*(onerror|onload|onclick|script)[^>]*>/i', $file['name'])) {
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 10.',
                      'body'  => 'The filename was reflected without escaping.'];
        } else {
            $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                      'body'  => 'The filename was displayed, but it did not contain executable markup.'];
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
        <span class="num">File Upload · SCENARIO 10 · UPLOAD</span>
        <h1>Stored XSS via Filename</h1>
        <p>Filename reflected without escaping. Inject XSS via filename using Burp.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit" name="submit" value="Upload">Upload</button>
            </form>
        </div>

        <?php if (isset($reflected) && $reflected !== null): ?>
            <div class="panel">
                <h2>Answer</h2>
                <!-- the flaw, on purpose: the name is echoed without escaping -->
                <p class="notice error">Your file <?= $reflected ?> was not uploaded!</p>
            </div>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">
                    Next scenario &rarr;
                </a>
            </div>
        <?php endif; ?>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
