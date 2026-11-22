<?php
// File Upload · Scenario 21 — Image Polyglot (Metadata Payload) - FIXED 2026-09-28
// Now: filters .php, only allows png/jpg, checks true polyglot inside metadata

$pageTitle = 'Web Shell Upload via Polyglot File (Image Metadata)';
$scenarioNumber = 21;
$nextScenario = sprintf('../scenario%02d/', 22);
$uploadsDir = __DIR__ . '/uploads';

function pngMetadataHasPhpPayload(string $path): bool
{
    $data = @file_get_contents($path);
    $signature = "\x89PNG\r\n\x1a\n";
    if ($data === false || !str_starts_with($data, $signature)) {
        return false;
    }
    $length = strlen($data);
    $offset = 8;
    while ($offset + 12 <= $length) {
        $chunkLength = unpack('N', substr($data, $offset, 4))[1] ?? 0;
        if ($chunkLength > $length - $offset - 12) return false;
        $type = substr($data, $offset + 4, 4);
        $chunkData = substr($data, $offset + 8, $chunkLength);
        $metadata = $chunkData;
        if ($type === 'zTXt') {
            $keywordEnd = strpos($chunkData, "\0");
            if ($keywordEnd !== false && isset($chunkData[$keywordEnd + 1]) && ord($chunkData[$keywordEnd + 1]) === 0) {
                $decoded = @gzuncompress(substr($chunkData, $keywordEnd + 2));
                if ($decoded !== false) $metadata = $decoded;
            }
        } elseif ($type === 'iTXt') {
            $keywordEnd = strpos($chunkData, "\0");
            if ($keywordEnd !== false && strlen($chunkData) > $keywordEnd + 2 && ord($chunkData[$keywordEnd + 1]) === 1) {
                $languageStart = $keywordEnd + 3;
                $languageEnd = strpos($chunkData, "\0", $languageStart);
                if ($languageEnd !== false) {
                    $translatedEnd = strpos($chunkData, "\0", $languageEnd + 1);
                    if ($translatedEnd !== false) {
                        $decoded = @gzuncompress(substr($chunkData, $translatedEnd + 1));
                        if ($decoded !== false) $metadata = $decoded;
                    }
                }
            }
        }
        if (in_array($type, ['tEXt', 'zTXt', 'iTXt', 'eXIf'], true) && strpos($metadata, '<?php') !== false) {
            return true;
        }
        $offset += 12 + $chunkLength;
        if ($type === 'IEND') break;
    }
    return false;
}

function jpegMetadataHasPhpPayload(string $path): bool
{
    $data = @file_get_contents($path);
    if ($data === false) return false;
    if (!str_starts_with($data, "\xFF\xD8")) return false; // not JPEG
    // True polyglot: PHP inside COM (FF FE) or APP1 EXIF or anywhere inside but before EOI and valid JPEG
    // Check if <?php exists and COM marker exists with PHP, or just <?php inside file and valid JPEG structure
    if (strpos($data, '<?php') === false) return false;
    // Ensure it's not just appended after EOI (FF D9) - check if <?php appears before last EOI
    $lastEoi = strrpos($data, "\xFF\xD9");
    $phpPos = strpos($data, '<?php');
    if ($lastEoi !== false && $phpPos !== false && $phpPos > $lastEoi) {
        // PHP after EOI = appended, not true polyglot
        return false;
    }
    // Check COM or APP segments contain PHP
    // Simple: if file contains FF FE and <?php, or FF E1 and <?php, it's likely inside metadata
    if (strpos($data, "\xFF\xFE") !== false || strpos($data, "\xFF\xE1") !== false || strpos($data, "\xFF\xE0") !== false) {
        return true;
    }
    // Fallback: if <?php exists anywhere inside JPEG and getimagesize passed, consider it polyglot
    return true;
}

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'A polyglot file is valid as both image and PHP.',
    'You can embed PHP in image EXIF or comment or after image data.',
    'Server validates image with getimagesize() but PHP code still inside.',
    'Goal: Create polyglot JPEG with PHP inside.',
];

$labHint = [
    'Create valid JPEG file.',
    'Use exiftool or hex editor to add PHP code in comment: <?php echo \'pwned\'; ?>',
    'Or create file that starts with JPEG header and contains PHP after.',
    'Save as shell.php.jpg or shell.jpg.php.',
    'Upload via form. Server sees valid image but file also contains PHP.',
    'Click link. If server renames to .php or Apache parses, it runs.',
    'Standard: Polyglot / Image Polyglot.',
];

$labRootCause = [
    'cwe' => 'CWE-434: Polyglot File',
    'owasp' => 'OWASP: Image Polyglot',
    'bad' => [
        'explanation' => [
        '<strong>Programmer validated image with getimagesize() but file can be polyglot - valid as both image and PHP.</strong> PHP code can be hidden in EXIF, comment, or after image data.',
        '<strong>Mistake:</strong> Thought getimagesize() ensures file is safe image, but polyglot file passes getimagesize() and still contains PHP code.',
        '<strong>Why it happens:</strong> Developer did not know image can contain PHP code in metadata or after EOF and still be valid image.',
        ],
        'code' => [
        '// VULNERABLE - getimagesize() bypassed by polyglot!',
        '<?php',
        'if (getimagesize($_FILES[\'file\'][\'tmp_name\']) === false) { die(\'Not image\'); }',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '// Attacker creates JPEG with PHP in EXIF:',
        '// exiftool -Comment="<?php system($_GET[\'cmd\']); ?>" image.jpg',
        '// Or append PHP after JPEG EOF: cat image.jpg shell.php > polyglot.jpg',
        '// getimagesize() sees JPEG - valid! But file contains PHP code!',
        '?>',
        ],
        'impact' => 'Attacker creates polyglot JPEG/PNG with PHP hidden in EXIF or after image data. Passes image validation but contains PHP code. Gets RCE if parsed as PHP.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Re-encode image to remove hidden code. Create new image from uploaded image using GD or Imagick, which strips metadata and extra data. Randomize filename.',
        '<strong>Rule:</strong> Re-create image to clean hidden code.',
        ],
        'code' => [
        '// SECURE - Re-encode image to remove hidden PHP',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        'if (getimagesize($_FILES[\'file\'][\'tmp_name\']) === false) { die(\'Not image\'); }',
        'if ($ext == \'jpg\' || $ext == \'jpeg\') {',
        '  $img = imagecreatefromjpeg($_FILES[\'file\'][\'tmp_name\']);',
        '  $newName = bin2hex(random_bytes(16)) . \'.jpg\';',
        '  imagejpeg($img, \'uploads/\' . $newName, 90);',
        '  imagedestroy($img);',
        '} elseif ($ext == \'png\') {',
        '  $img = imagecreatefrompng($_FILES[\'file\'][\'tmp_name\']);',
        '  $newName = bin2hex(random_bytes(16)) . \'.png\';',
        '  imagepng($img, \'uploads/\' . $newName);',
        '  imagedestroy($img);',
        '}',
        '?>',
        ],
        'steps' => [
        'Validate with getimagesize() as first check',
        'Re-encode image using GD library to remove hidden code and metadata',
        'Use imagecreatefromjpeg/png and imagejpeg/png to create new clean image',
        'Randomize filename',
        'Strip EXIF data',
        'Check MIME with finfo_file()',
        'Disable PHP execution in uploads',
        'Store outside web root',
        ],
    ],
];

$link = null;
$linkLabel = 'See the file';
$flash = null;

$file = $_FILES['fileToUpload'] ?? null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                  'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').'];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

        // Filter: block .php, only allow png/jpg/jpeg
        if ($ext === 'php' || stripos($safeName, '.php') !== false) {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'The .php extension is blocked. Upload PNG or JPG polyglot with PHP inside metadata. Only .png and .jpg allowed.'];
        } elseif (!in_array($ext, ['png','jpg','jpeg'], true)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'Only PNG and JPG allowed. You uploaded .' . $ext . '. Create true polyglot PNG/JPG.'];
        } else {
            $size = @getimagesize($file['tmp_name']);
            $mime = $size['mime'] ?? '';

            if (!$size || $size[0] < 1 || $size[1] < 1 || !in_array($mime, ['image/png','image/jpeg'], true)) {
                $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                          'body'  => 'The file is not a valid PNG/JPG image. getimagesize() failed. Use true polyglot.'];
            } else {
                $hasPhpPayload = false;
                if ($mime === 'image/png') {
                    $hasPhpPayload = pngMetadataHasPhpPayload($file['tmp_name']);
                } elseif ($mime === 'image/jpeg') {
                    $hasPhpPayload = jpegMetadataHasPhpPayload($file['tmp_name']);
                }

                if (!move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
                    $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                              'body'  => 'The server could not save the file.'];
                } else {
                    $link = 'uploads/' . rawurlencode($safeName);

                    if ($hasPhpPayload) {
                        $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 21.',
                                  'body'  => 'True polyglot! The file is valid ' . $ext . ' (' . $mime . ') and contains PHP in metadata (tEXt/COM). Bypassed image validation!'];
                    } else {
                        $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                                  'body'  => 'The PNG/JPG check passed, but the file has no PHP payload inside metadata. Embed <?php in tEXt (PNG) or COM (JPG) chunk, not appended after IEND.'];
                    }
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
        <span class="num">File Upload · SCENARIO 21 · UPLOAD</span>
        <h1>Image Polyglot (Shell in Metadata)</h1>
        <p>Valid PNG/JPG containing PHP in metadata. PHP extension blocked, only PNG/JPG allowed. Create true polyglot.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <p style="font-size:12px; opacity:0.8;">Only .png and .jpg allowed. .php is blocked. Embed PHP inside image metadata.</p>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".png,.jpg,.jpeg" />
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
