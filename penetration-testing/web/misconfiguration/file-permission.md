# File Permission

## Check List

* [ ] Review and identify any rogue file permissions.

## Cheat Sheet

### Methodology

#### File Permission (Sensitive File)

{% stepper %}
{% step %}
Using the following commands to find access to files inside the web server, which are made with PHP, we can run whether we can write, read, or execute a file inside the web server
{% endstep %}

{% step %}
If a sensitive file is found, we can reach the vulnerability with high-level access
{% endstep %}
{% endstepper %}

***

### Check DIR/File Permissions

#### [namei](https://man7.org/linux/man-pages/man1/namei.1.html)

```bash
find /var/www/html -exec namei -l {} \;
```

#### [PHP](https://www.php.net/)

```php
<?php
// Dynamically get the current directory path
$directory = dirname(__FILE__);

// Function to check file and folder permissions and determine if they are unsafe
function checkPermissions($filePath)
{
    $permissions = fileperms($filePath);
    $issues = [];

    if (is_dir($filePath)) {
        if ($permissions & 0x0002) {
            $issues[] = "Writable";
        }
        if ($permissions & 0x0001) {
            $issues[] = "Executable";
        }
    } else {
        if ($permissions & 0x0002) {
            $issues[] = "Writable";
        }
        if (is_executable($filePath)) {
            $issues[] = "Executable";
        }
        if ($permissions & 0x0004) {
            $issues[] = "Readable";
        }
    }

    return !empty($issues) 
        ? implode(", ", $issues)
        : "Safe";
}

// Check if the directory exists
if (is_dir($directory)) {
    $files = scandir($directory);
    $files = array_diff($files, ['.', '..']);

    $isConsole = php_sapi_name() === 'cli';

    if ($isConsole) {
        echo "Directory: $directory\n";
        echo "----------------------------------------------- \n";
        foreach ($files as $file) {
            $filePath = $directory . DIRECTORY_SEPARATOR . $file;
            $type = is_dir($filePath) ? "Directory" : "File";
            $status = checkPermissions($filePath);
            echo "$file ($type): $status\n";
        }
    } else {
        echo "<strong>Directory:</strong> $directory<br>";
        echo "<hr>";
        echo "<ul>";
        foreach ($files as $file) {
            $filePath = $directory . DIRECTORY_SEPARATOR . $file;
            $type = is_dir($filePath) ? "Directory" : "File";
            $status = checkPermissions($filePath);
            echo "<li><strong>$file</strong> ($type): $status</li>";
        }
        echo "</ul>";
    }
} else {
    $message = "Directory not found.";
    echo php_sapi_name() === 'cli' ? "$message\n" : "<strong>$message</strong><br>";
}
?>
```

### Check Sensitive Files

```php
<?php

$sensitiveExtensions = ['.key', '.enc', '.pem', '.env', '.txt', 'wp-config.php', 'configuration.php', 'settings.php'];
$sensitiveKeys = [
    '/AUTH_KEY/i',
    '/SECURE_AUTH_KEY/i',
    '/LOGGED_IN_KEY/i',
    '/NONCE_KEY/i',
    '/DB_PASSWORD/i',
    '/DB_NAME/i',
    '/session_key/i',
    '/db_password/i',
    '/secret/i',
    '/hash_salt/i',
    '/database_hash_salt/i'
];

// Function to check if the file contains sensitive data
function checkSensitiveFile($filePath) {
    global $sensitiveKeys;
    
    // Check if the file exists
    if (!file_exists($filePath)) {
        return false;
    }
    
    // Read file contents
    $fileContents = file_get_contents($filePath);
    
    // Check for sensitive keys in the file content
    foreach ($sensitiveKeys as $keyPattern) {
        if (preg_match($keyPattern, $fileContents)) {
            return true;
        }
    }

    return false;
}

// Function to check the file extension
function checkSensitiveExtension($filePath) {
    global $sensitiveExtensions;
    
    foreach ($sensitiveExtensions as $extension) {
        if (stripos($filePath, $extension) !== false) {
            return true;
        }
    }

    return false;
}

// Function to recursively scan directory and return files that match sensitive criteria
function scanDirectory($directory) {
    $filesWithSensitiveData = [];
    
    // Scan directory for files
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
    
    foreach ($files as $file) {
        // Skip directories
        if ($file->isDir()) {
            continue;
        }

        $filePath = $file->getRealPath();
        
        // Check for sensitive data in file content or sensitive extensions
        if (checkSensitiveFile($filePath) || checkSensitiveExtension($filePath)) {
            $filesWithSensitiveData[] = $filePath;
        }
    }

    return $filesWithSensitiveData;
}

// Check if running in a web server environment or console
$isConsole = php_sapi_name() === 'cli';

// Define the directory to scan
if ($isConsole) {
    // For console: automatically detect the current working directory
    $directoryToScan = getcwd(); // Get current directory
} else {
    // Running on a web server
    $directoryToScan = $_SERVER['DOCUMENT_ROOT']; // Adjust based on the server root directory
}

// Get the sensitive files
$sensitiveFiles = scanDirectory($directoryToScan);

// Output the sensitive files
if (!empty($sensitiveFiles)) {
    if ($isConsole) {
        echo "Found sensitive files:\n";
        foreach ($sensitiveFiles as $file) {
            echo $file . "\n";
        }
    } else {
        echo "<strong>Found sensitive files:</strong><br>";
        echo "<hr>";
        echo "<ul>";
        foreach ($sensitiveFiles as $file) {
            echo "<li><strong>$file</strong></li>";
        }
        echo "</ul>";
    }
} else {
    if ($isConsole) {
        echo "No sensitive files found.\n";
    } else {
        echo "<strong>No sensitive files found.</strong><br>";
    }
}
?>
```

### Check Log DIR/Files

```php
<?php

// Get the directory of the current script
$directory = dirname(__FILE__);

// Define the log file paths relative to the script's directory
$logFiles = [
    // Apache and Nginx logs (assuming these are in standard locations)
    $directory . '/logs/apache2/access.log', // Example, adjust as needed
    $directory . '/logs/apache2/error.log',
    $directory . '/logs/nginx/access.log',
    $directory . '/logs/nginx/error.log',

    // Application logs (adjust these paths if necessary)
    $directory . '/logs/application.log',

    // WordPress log (relative path from current script directory)
    $directory . '/wp-content/debug.log', // WordPress log

    // Joomla logs (relative path from current script directory)
    $directory . '/logs/error.php', // Joomla error log
    $directory . '/logs/access.php', // Joomla access log

    // Drupal logs (relative path from current script directory)
    $directory . '/sites/default/files/logs/drupal.log', // Drupal log
];

// Define patterns to look for sensitive information (e.g., SQL queries, IPs, tokens)
$sensitivePatterns = [
    '/(SELECT|INSERT|UPDATE|DELETE).*FROM/i',  // SQL queries
    '/(\b\w{32,}\b)/',  // Possible API keys (simple regex for long alphanumeric strings)
    '/(password|token|secret)/i',  // Keywords related to sensitive data
    '/\b(?:\d{1,3}\.){3}\d{1,3}\b/',  // IP addresses (simple regex for IPv4)
];

// Function to read logs and search for sensitive information
function scanLogs($logFiles, $sensitivePatterns)
{
    foreach ($logFiles as $logFile)
    {
        if (file_exists($logFile))
        {
            echo "Scanning file: $logFile\n";

            // Open the log file for reading
            $handle = fopen($logFile, 'r');
            if ($handle)
            {
                // Read the file line by line
                while (($line = fgets($handle)) !== false)
                {
                    // Check each pattern for sensitive data
                    foreach ($sensitivePatterns as $pattern)
                    {
                        if (preg_match($pattern, $line))
                        {
                            echo "Sensitive data found: $line\n";
                        }
                    }
                }
                fclose($handle);
            } else {
                echo "Error: Unable to open file $logFile\n";
            }
        }
    }
}

// Run the log scanning function
scanLogs($logFiles, $sensitivePatterns);
?>
```

### Check Executable Files

```php
<?php
// Get the current script's directory
$directory = dirname(__FILE__);

// List of executable file extensions
$extensions = ['php', 'exe', 'jar', 'class', 'asp', 'phar'];

// Function to scan directory recursively
function scanDirectory($directory, $extensions)
{
    // Check if the directory exists and is readable
    if (!is_readable($directory))
    {
        return;
    }

    $files = scandir($directory);
    $isConsole = php_sapi_name() === 'cli';
    
    foreach ($files as $file)
    {
        $file_path = $directory . DIRECTORY_SEPARATOR . $file;

        // Skip '.' and '..' directories
        if ($file == '.' || $file == '..') continue;

        if (is_dir($file_path))
        {
            // Recursively scan subdirectories
            scanDirectory($file_path, $extensions);
        } else {
            // Get the file extension
            $file_extension = pathinfo($file, PATHINFO_EXTENSION);
            if (in_array(strtolower($file_extension), $extensions))
            {
                if ($isConsole) {
                echo "Executable file found: " . $file_path . "\n";
                }else {
                    echo "<ul>";
                    echo "<li> Executable file found: " . $file_path . "</li>";
                    echo "</ul>";
                }
            }
        }
    }
}

// Start scanning from the directory where this script is located
scanDirectory($directory, $extensions);
?>
```

### Check Database Files

```php
<?php
// Get the current script's directory
$directory = dirname(__FILE__);

// List of database file extensions
$extensions = ['db', 'sql', 'sqlite', 'sqlite3', 'mdb'];

// Function to scan directory recursively
function scanDirectory($directory, $extensions)
{
    // Check if the directory exists and is readable
    if (!is_readable($directory)) {
        return;
    }

    $files = scandir($directory);
    $isConsole = php_sapi_name() === 'cli';


    foreach ($files as $file)
    {
        $file_path = $directory . DIRECTORY_SEPARATOR . $file;

        // Skip '.' and '..' directories
        if ($file == '.' || $file == '..') continue;

        if (is_dir($file_path))
        {
            // Recursively scan subdirectories
            scanDirectory($file_path, $extensions);
        } else {
            // Get the file extension
            $file_extension = pathinfo($file, PATHINFO_EXTENSION);
            if (in_array(strtolower($file_extension), $extensions))
            {
                if ($isConsole) {
                    echo "Database file found: $file_path \n";
                }else {
                    echo "<ul>";
                    echo "<li> Database file found: $file_path </li>";
                    echo "</ul>";
                }
            }
        }
    }
}

// Start scanning from the directory where this script is located
scanDirectory($directory, $extensions);
?>
```

### Check Temp DIR/Files

```php
<?php
// Get the current script's directory
$directory = dirname(__FILE__);

// List of temp file extensions
$extensions = ['tmp', 'log', 'bak', 'swp', 'swp1', 'swo', 'temp'];

// Common temporary directories to scan
$temp_dirs = ['/tmp', '/var/tmp', '/usr/tmp', '/tmp/'];

function scanDirectory($directory, $extensions)
{
    // Check if the directory exists and is readable
    if (!is_readable($directory))
    {
        return;
    }

    $files = scandir($directory);
    foreach ($files as $file)
    {
        $file_path = $directory . DIRECTORY_SEPARATOR . $file;

        // Skip '.' and '..' directories
        if ($file == '.' || $file == '..') continue;
        $isConsole = php_sapi_name() === 'cli';

        if (is_dir($file_path)) {
            // Recursively scan subdirectories
            scanDirectory($file_path, $extensions);
        } else {
            // Get the file extension
            $file_extension = pathinfo($file, PATHINFO_EXTENSION);
            if (in_array(strtolower($file_extension), $extensions))
            {
                if ($isConsole) {
                    echo "Temp file found: $file_path \n";
                } else {   
                    echo "<ul>";
                    echo "<li> Temp file found: $file_path </li>";
                    echo "</ul>";
                }
            }
        }
    }
}

// Start scanning from the directory where this script is located
scanDirectory($directory, $extensions);

// Scan common temp directories
foreach ($temp_dirs as $temp_dir)
{
    if (is_dir($temp_dir))
    {
        if (php_sapi_name() === 'cli') {
            echo "Scanning common temp directory: $temp_dir \n";
        } else {   
            echo "<ul>";
            echo "<li> Scanning common temp directory: $temp_dir </li>";
            echo "</ul>";
        }
        scanDirectory($temp_dir, $extensions);
    }
}
?>
```

### Check Upload DIR/Files

```php
<?php
// Get the current script's directory
$directory = dirname(__FILE__);

// List of common file extensions used for uploads
$extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xlsx', 'txt', 'mp4', 'mp3', 'zip', 'tar', 'rar', 'csv'];

// Common upload directories to scan (you can customize these)
$upload_dirs = [
    '/uploads',  // General uploads directory
    '/files',    // Another common directory
    '/media',    // Used for media files
    '/user_uploads',  // Custom directory
    '/public/uploads',  // Public upload directory
    
    // CMS-specific upload directories
    '/wp-content/uploads', // WordPress
    '/wp-content/plugins', // WordPress plugins (potential upload locations)
    '/wp-content/themes', // WordPress themes (some CMS files may end up here)
    
    '/joomla/administrator/components/com_media', // Joomla
    '/joomla/images',  // Joomla images directory

    '/sites/default/files', // Drupal
    '/sites/default/files/private', // Drupal private files
    '/files', // Common in some CMSs or custom setups for Drupal
    
    '/content/uploads', // Magento (some configurations)
    '/pub/media', // Magento 2
    
    '/content/uploads/images', // PrestaShop
    '/themes/custom/images' // PrestaShop theme images
];

function scanDirectory($directory, $extensions)
{
    // Check if the directory exists and is readable
    if (!is_readable($directory))
    {
        return;
    }

    $files = scandir($directory);
    foreach ($files as $file)
    {
        $file_path = $directory . DIRECTORY_SEPARATOR . $file;

        // Skip '.' and '..' directories
        if ($file == '.' || $file == '..') continue;
        
        if (is_dir($file_path)) {
            // Recursively scan subdirectories
            scanDirectory($file_path, $extensions);
        } else {
            // Get the file extension
            $file_extension = pathinfo($file, PATHINFO_EXTENSION);
            if (in_array(strtolower($file_extension), $extensions))
            {
                if (php_sapi_name() === 'cli') {
                    echo "Upload file found: $file_path \n";
                } else {   
                    echo "<ul>";
                    echo "<li> Upload file found: $file_path </li>";
                    echo "</ul>";
                }
            }
        }
    }
}

// Start scanning from the directory where this script is located
scanDirectory($directory, $extensions);

// Scan common upload directories
foreach ($upload_dirs as $upload_dir)
{
    if (is_dir($upload_dir)) 
    {
        if (php_sapi_name() === 'cli') {
            echo "Scanning upload directory: $upload_dir  \n";
        } else {   
            echo "<ul>";
            echo "<li> Scanning upload directory: $upload_dir </li>";
            echo "</ul>";
        }
        scanDirectory($upload_dir, $extensions);
    }
}
?>
```
