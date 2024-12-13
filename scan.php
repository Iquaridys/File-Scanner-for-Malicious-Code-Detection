<?php
// Directory to scan
$directory = __DIR__ . '/file'; // Change this to the directory you want to scan

// PHP functions to check
$functions_to_check = [
    'base64_decode', 'eval', 'gzinflate', 'str_rot13', 'shell_exec', 'exec', 'passthru', 'system', 
    'popen', 'proc_open', 'assert', 'create_function', 'highlight_file', 'phpinfo', 'file_put_contents', 
    'fopen', 'curl', 'chmod', 'unlink', 'include', 'require', 'include_once', 'require_once', 'mysql_query', 
    'mysqli_query', 'pg_query', 'proc_close', 'file_get_contents', 'getimagesize', 'glob', 
    'http_response_code', 'header', 'parse_ini_file', 'session_regenerate_id', 'unlink', 'filter_var', 
    'tmpfile', 'proc_nice', 'ini_set', 'getenv', 'putenv', 'mail', 'setcookie'
];

// Exfiltration patterns for PHP
$exfiltration_patterns_php = [
    'hex_encoding' => '/\\x[0-9A-Fa-f]{2}/i',
    'hexadecimal_number' => '/\b0x[0-9A-Fa-f]+\b/i',
    'hexadecimal_numeric_string' => '/\b["\']0x[0-9A-Fa-f]+\b["\']/i'
];

// Exfiltration patterns for CSS
$exfiltration_patterns_css = [
    'javascript_inline' => '/(on\w+)\s*=\s*["\'].*["\']/i',
    'import_external_url' => '/@import\s*["\'](http|https):\/\/[^\s"\'\)]+["\']/i',
    'javascript_in_css' => '/(expression\()|(\bjavascript:)/i', 
];

// JavaScript functions to check
$js_functions_to_check = [
    'eval',              
    'document.write',     
    'setTimeout',         
    'setInterval',       
    'XMLHttpRequest',    
    'fetch',              
    'axios',            
    'location.href',    
    'window.location',   
    'atob',                
    'btoa'                
];

// Exfiltration patterns for JS
$exfiltration_patterns_js = [
    'http_request' => '/\$\.(ajax|get|post)\s*\(\s*["\'](http|https):\/\/[^\']+/i', 
    'axios_request' => '/axios\s*\.\s*(get|post|put|delete)\s*\(\s*["\'](http|https):\/\/[^\']+/i', 
    'fetch_request' => '/fetch\s*\(\s*["\'](http|https):\/\/[^\']+/i', 
    'xhr_request' => '/new\s*XMLHttpRequest\s*\(\)/i',
    'jQuery_get' => '/\$\.(get|post)\s*\(\s*["\'](http|https):\/\/[^\']+/i', 
    'hex_identifiers' => '/\\x[0-9A-Fa-f]{2}/i',  
    'hexadecimal_number' => '/\b0x[0-9A-Fa-f]+\b/i',
    'hexadecimal_numeric_string' => '/\b["\']0x[0-9A-Fa-f]+\b["\']/i'
];

// Exfiltration patterns for TXT files
$exfiltration_patterns_txt = [
    'base64' => '/\bbase64\b/i',
    'eval' => '/\beval\b/i',
    'exec' => '/\bexec\b/i',
    'shell_exec' => '/\bshell_exec\b/i',
    'system' => '/\bsystem\b/i',
    'curl' => '/\bcurl\b/i',
    'file_get_contents' => '/\bfile_get_contents\b/i',
    'file_put_contents' => '/\bfile_put_contents\b/i',
    'unlink' => '/\bunlink\b/i',
    'getimagesize' => '/\bgetimagesize\b/i',
    'malicious_file_link' => '/"[^"]*\.(exe|bat|js|php|sh|pl|py|jar|cgi|html)"/i',
    'hex_identifiers' => '/\\x[0-9A-Fa-f]{2}/i',
    'hexadecimal_number' => '/\b0x[0-9A-Fa-f]+\b/i',
    'hexadecimal_numeric_string' => '/\b["\']0x[0-9A-Fa-f]+\b["\']/i',
    'base64_pattern' => '/(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}(?:[A-Za-z0-9+\/]{2})?=?=?)/',
    'ascii_control_pattern' => '/[\x00-\x1F\x7F]/'
];

// Exfiltration patterns for JSON files
$exfiltration_patterns_json = [
    'eval' => '/"eval"/i',
    'exec' => '/"exec"/i',
    'http_request' => '/"http(?:s)?":\/\/[^\"]+/i',
    'base64' => '/"base64"/i',
    'malicious_file_link' => '/"[^"]*\.(exe|bat|js|php|sh|pl|py|jar|cgi|html)"/i',
    'hex_identifiers' => '/\\x[0-9A-Fa-f]{2}/i',
    'hexadecimal_number' => '/\b0x[0-9A-Fa-f]+\b/i',
    'hexadecimal_numeric_string' => '/\b["\']0x[0-9A-Fa-f]+\b["\']/i',
    'base64_pattern' => '/(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}(?:[A-Za-z0-9+\/]{2})?=?=?)/',
    'ascii_control_pattern' => '/[\x00-\x1F\x7F]/',
];

// Initialize counters
$total_files_scanned = 0;
$suspicious_files_php = 0;
$suspicious_files_js = 0;
$suspicious_files_txt = 0;
$suspicious_files_json = 0;
$suspicious_files_css = 0;
$suspicious_php_files = [];
$suspicious_js_files = [];
$suspicious_txt_files = [];
$suspicious_json_files = [];
$suspicious_css_files = [];

// Scan the directory
try {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $file) {
        // Check for PHP, JS, TXT, JSON, or CSS files
        $file_extension = $file->getExtension();
        if (in_array($file_extension, ['php', 'js', 'txt', 'json', 'css'], true)) {
            $total_files_scanned++;
            $file_path = $file->getPathname();

            // Attempt to read the file
            $content = @file_get_contents($file_path);
            if ($content === false) {
                echo "Error: Could not read file: {$file_path}" . PHP_EOL;
                continue;
            }

            // Tokenize the content for PHP or JS
            $tokens = token_get_all($content);
            $line_number = 1;
            $suspicious_details = [];

            // Check for suspicious PHP functions
            if ($file_extension === 'php') {
                foreach ($tokens as $token) {
                    if (is_array($token)) {
                        [$id, $text, $start_line] = $token;
                        $line_number = $start_line;

                        if ($id === T_STRING && in_array($text, $functions_to_check, true)) {
                            $suspicious_details[] = [
                                'function' => $text,
                                'line' => $line_number
                            ];
                        }
                    }
                }

                // Check for exfiltration patterns in PHP
                foreach ($exfiltration_patterns_php as $name => $pattern) {
                    if (preg_match_all($pattern, $content, $matches)) {
                        foreach ($matches[0] as $match) {
                            $suspicious_details[] = [
                                'exfiltration_pattern' => $name,
                                'line' => $line_number,
                                'match' => $match
                            ];
                        }
                    }
                }

                if (!empty($suspicious_details)) {
                    $suspicious_files_php++;
                    $suspicious_php_files[] = [
                        'path' => $file_path,
                        'details' => $suspicious_details
                    ];
                }
            }

            // Check for suspicious JS functions and patterns
            if ($file_extension === 'js') {
                foreach ($js_functions_to_check as $js_function) {
                    if (strpos($content, $js_function) !== false) {
                        $suspicious_details[] = [
                            'js_function' => $js_function,
                            'line' => $line_number
                        ];
                    }
                }

                // Check for exfiltration patterns in JS
                foreach ($exfiltration_patterns_js as $name => $pattern) {
                    if (preg_match_all($pattern, $content, $matches)) {
                        foreach ($matches[0] as $match) {
                            $suspicious_details[] = [
                                'exfiltration_pattern' => $name,
                                'line' => $line_number,
                                'match' => $match
                            ];
                        }
                    }
                }

                if (!empty($suspicious_details)) {
                    $suspicious_files_js++;
                    $suspicious_js_files[] = [
                        'path' => $file_path,
                        'details' => $suspicious_details
                    ];
                }
            }

            // Check for suspicious TXT files
            if ($file_extension === 'txt') {
                // Check for suspicious keywords in TXT files
                foreach ($exfiltration_patterns_txt as $name => $pattern) {
                    if (preg_match($pattern, $content)) {
                        $suspicious_files_txt++;
                        $suspicious_txt_files[] = [
                            'path' => $file_path
                        ];
                        break;
                    }
                }
            }

            // Check for suspicious JSON files
            if ($file_extension === 'json') {
                // Check for suspicious patterns in JSON files
                foreach ($exfiltration_patterns_json as $name => $pattern) {
                    if (preg_match($pattern, $content)) {
                        $suspicious_files_json++;
                        $suspicious_json_files[] = [
                            'path' => $file_path
                        ];
                        break;
                    }
                }
            }

            if ($file_extension === 'css') {
                $suspicious_details = [];

                if (preg_match($exfiltration_patterns_css['javascript_inline'], $content)) {
                    $suspicious_details[] = 'Inline JavaScript event handler detected';
                }

                if (preg_match($exfiltration_patterns_css['import_external_url'], $content)) {
                    $suspicious_details[] = '@import statement with external URL found';
                }

                if (preg_match($exfiltration_patterns_css['javascript_in_css'], $content)) {
                    $suspicious_details[] = 'Potential JavaScript code found in CSS';
                }

                if (!empty($suspicious_details)) {
                    $suspicious_files_css++;
                    $suspicious_css_files[] = [
                        'path' => $file_path,
                        'details' => $suspicious_details
                    ];
                }
            }
        }
    }

    // Generate HTML output
    $html_output = "<html><head><title>Scan Results</title></head><body>";
    $html_output .= "<h1>Scan Results</h1>";
    $html_output .= "<p>Total Files Scanned: {$total_files_scanned}</p>";

    if ($suspicious_files_php > 0) {
        $html_output .= "<h2>Suspicious PHP Files</h2><table border='1'><tr><th>Details</th><th>File Path</th></tr>";
        foreach ($suspicious_php_files as $file) {
            $html_output .= "<tr><td>";
            foreach ($file['details'] as $detail) {
                if (isset($detail['function'])) {
                    $html_output .= "Function: " . htmlspecialchars($detail['function']) . " on Line: " . htmlspecialchars($detail['line']) . "<br>";
                }
                if (isset($detail['exfiltration_pattern'])) {
                    $html_output .= "Exfiltration Pattern: " . htmlspecialchars($detail['exfiltration_pattern']) . " on Line: " . htmlspecialchars($detail['line']) . " Match: " . htmlspecialchars($detail['match']) . "<br>";
                }
            }
            $html_output .= "</td><td><a href='file://" . htmlspecialchars($file['path']) . "' target='_blank'>" . htmlspecialchars($file['path']) . "</a></td></tr>";
        }
        $html_output .= "</table>";
    }

    if ($suspicious_files_js > 0) {
        $html_output .= "<h2>Suspicious JS Files</h2><table border='1'><tr><th>Details</th><th>File Path</th></tr>";
        foreach ($suspicious_js_files as $file) {
            $html_output .= "<tr><td>";
            foreach ($file['details'] as $detail) {
                if (isset($detail['js_function'])) {
                    $html_output .= "JS Function: " . htmlspecialchars($detail['js_function']) . " on Line: " . htmlspecialchars($detail['line']) . "<br>";
                }
                if (isset($detail['exfiltration_pattern'])) {
                    $html_output .= "Exfiltration Pattern: " . htmlspecialchars($detail['exfiltration_pattern']) . " on Line: " . htmlspecialchars($detail['line']) . " Match: " . htmlspecialchars($detail['match']) . "<br>";
                }
            }
            $html_output .= "</td><td><a href='file://" . htmlspecialchars($file['path']) . "' target='_blank'>" . htmlspecialchars($file['path']) . "</a></td></tr>";
        }
        $html_output .= "</table>";
    }

    if ($suspicious_files_css > 0) {
        $html_output .= "<h2>Suspicious CSS Files</h2><table border='1'><tr><th>Details</th><th>File Path</th></tr>";
        foreach ($suspicious_css_files as $file) {
            $html_output .= "<tr><td>";
            foreach ($file['details'] as $detail) {
                $html_output .= htmlspecialchars($detail) . "<br>";
            }
            $html_output .= "</td><td><a href='file://" . htmlspecialchars($file['path']) . "' target='_blank'>" . htmlspecialchars($file['path']) . "</a></td></tr>";
        }
        $html_output .= "</table>";
    }

    if ($suspicious_files_txt > 0) {
        $html_output .= "<h2>Suspicious TXT Files</h2><table border='1'><tr><th>File Path</th></tr>";
        foreach ($suspicious_txt_files as $file) {
            $html_output .= "<tr><td><a href='file://" . htmlspecialchars($file['path']) . "' target='_blank'>" . htmlspecialchars($file['path']) . "</a></td></tr>";
        }
        $html_output .= "</table>";
    }

    if ($suspicious_files_json > 0) {
        $html_output .= "<h2>Suspicious JSON Files</h2><table border='1'><tr><th>File Path</th></tr>";
        foreach ($suspicious_json_files as $file) {
            $html_output .= "<tr><td><a href='file://" . htmlspecialchars($file['path']) . "' target='_blank'>" . htmlspecialchars($file['path']) . "</a></td></tr>";
        }
        $html_output .= "</table>";
    }

    $html_output .= "</body></html>";

    // Save the HTML report
    $report_file = __DIR__ . '/scan_report.html';
    file_put_contents($report_file, $html_output);

    echo PHP_EOL . "Scan Complete! Report saved to: {$report_file}" . PHP_EOL;

} catch (Exception $e) {
    // Handle errors during directory traversal
    echo "Error: " . $e->getMessage() . PHP_EOL;
}
