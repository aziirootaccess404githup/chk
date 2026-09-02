<?php
ob_start();
error_reporting(0);
ini_set('display_errors', 0);
// ============================================================
// Exazon Research — Survey Dashboard v5 FINAL
// File: hub/index.php
// Fixes: client_name, median, qc pill, loi null, speeder query
// Added: IR Drift, Partials, EPC, Today stats, Gross Margin
// ============================================================

session_start();
define('DASHBOARD_PIN',     '8181');
define('DB_HOST',           'localhost');
define('DB_NAME',           'u994909610_Exaverify');
define('DB_USER',           'u994909610_Exaverify');
define('DB_PASS',           'Exaverify@8181');
define('SPEEDER_THRESHOLD', 180);
define('TG_TOKEN',  '8993325167:AAH8T70ipodxea-mjr4S5xlXf6GhYRCHYjQ');
define('TG_CHAT_ID','887381966');
define('ALERT_EMAIL',       'info@exazonresearch.com');

// ── PIN AUTH (stage 1) ──────────────────────────────────────
if (isset($_POST['pin'])) {
    if ($_POST['pin'] === DASHBOARD_PIN) $_SESSION['ex_auth'] = true;
    else $pinError = true;
}
if (isset($_GET['logout'])) { session_destroy(); header('Location: index.php'); exit; }
if (empty($_SESSION['ex_auth'])) { showLogin($pinError ?? false); exit; }

// ── TEAM MEMBER LOGIN (stage 2 — individual, role-based) ──────
$pdo = getDB();
ensureTables($pdo);
// Ghost Entry Detection's no_entry_record column is ensured here, early —
// before any Overview/stats/chart query below can reference it. It used to
// only get added much later (right before the Fraud tab's ghost-entries
// list), which left every query in between silently unable to exclude
// ghost entries from stats, and would fatal-error referencing an
// as-yet-nonexistent column on a brand new database's very first load.
try { $pdo->exec("ALTER TABLE survey_responses ADD COLUMN no_entry_record TINYINT(1) DEFAULT 0"); } catch (PDOException $e) {}
// Parent/child project structure columns — ensured early for the same
// reason (Overview/Projects/Billing rollup queries below all reference
// parent_sid / is_parent).
exz_ensure_parent_sid_column($pdo);
exz_ensure_is_parent_column($pdo);
exz_ensure_survey_starts_geo_columns($pdo);
// Bootstrap: seed one default superadmin if the team table is empty,
// so the dashboard is never permanently locked out.
try {
    $cnt = $pdo->query("SELECT COUNT(*) FROM exz_team")->fetchColumn();
    if ((int)$cnt === 0) {
        $pdo->prepare("INSERT INTO exz_team (name,email,password_hash,role) VALUES (?,?,?,?)")
            ->execute(['Super Admin', 'admin@exazonresearch.com', password_hash('Exazon@Admin1', PASSWORD_BCRYPT), 'superadmin']);
    }
} catch (Exception $e) {}

if (isset($_POST['team_login'])) {
    $temail = trim($_POST['team_email'] ?? '');
    $tpass  = trim($_POST['team_password'] ?? '');
    $tm = $pdo->prepare("SELECT * FROM exz_team WHERE email=? AND is_active=1 LIMIT 1");
    $tm->execute([$temail]);
    $trow = $tm->fetch();
    if ($trow && !empty($trow['password_hash']) && password_verify($tpass, $trow['password_hash'])) {
        $_SESSION['ex_team_id']   = $trow['id'];
        $_SESSION['ex_team_name'] = $trow['name'];
        $_SESSION['ex_team_role'] = $trow['role'];
    } else {
        $teamLoginError = true;
    }
}
if (isset($_GET['team_logout'])) {
    unset($_SESSION['ex_team_id'], $_SESSION['ex_team_name'], $_SESSION['ex_team_role']);
    header('Location: index.php'); exit;
}
if (empty($_SESSION['ex_team_id'])) { showTeamLogin($teamLoginError ?? false); exit; }

function exz_current_team_role(): string { return $_SESSION['ex_team_role'] ?? 'viewer'; }
function exz_is_superadmin(): bool { return exz_current_team_role() === 'superadmin'; }
function exz_is_manager(): bool { return in_array(exz_current_team_role(), ['superadmin','manager']); }

// ── UPDATE PROFILE (self-service, name/email only — role stays admin-controlled) ──
$up_msg = ''; $up_err = '';
if (isset($_POST['update_profile'])) {
    $new_name = trim($_POST['up_name'] ?? '');
    $new_email = trim($_POST['up_email'] ?? '');
    if (!$new_name || !$new_email) {
        $up_err = 'Please fill in both Name and Email.';
    } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $up_err = 'Email is not in a valid format.';
    } else {
        $pdo_up = getDB();
        try {
            $pdo_up->prepare("UPDATE exz_team SET name=?, email=? WHERE id=?")
                ->execute([$new_name, $new_email, $_SESSION['ex_team_id']]);
            $_SESSION['ex_team_name'] = $new_name;
            exz_log_audit_local($pdo_up, 'update_profile', "Team member ID: ".$_SESSION['ex_team_id']);
            $up_msg = 'Profile updated successfully.';
        } catch (Exception $e) {
            $up_err = 'This email is already in use by another account.';
        }
    }
}

// ── CHANGE PASSWORD (self-service, any logged-in team member) ──
$cp_msg = ''; $cp_err = '';
if (isset($_POST['change_password'])) {
    $pdo_cp = getDB();
    $cur_pass = $_POST['cp_current'] ?? '';
    $new_pass = $_POST['cp_new'] ?? '';
    $conf_pass = $_POST['cp_confirm'] ?? '';
    $tm = $pdo_cp->prepare("SELECT * FROM exz_team WHERE id=?");
    $tm->execute([$_SESSION['ex_team_id']]);
    $trow = $tm->fetch();
    if (!$trow || empty($trow['password_hash']) || !password_verify($cur_pass, $trow['password_hash'])) {
        $cp_err = 'Current password is incorrect.';
    } elseif (strlen($new_pass) < 6) {
        $cp_err = 'New password must be at least 6 characters long.';
    } elseif ($new_pass !== $conf_pass) {
        $cp_err = 'New password and Confirm password do not match.';
    } else {
        $pdo_cp->prepare("UPDATE exz_team SET password_hash=? WHERE id=?")
            ->execute([password_hash($new_pass, PASSWORD_BCRYPT), $_SESSION['ex_team_id']]);
        exz_log_audit_local($pdo_cp, 'change_password', "Team member ID: ".$_SESSION['ex_team_id']);
        $cp_msg = 'Password updated successfully.';
    }
}

// ── DB ────────────────────────────────────────────────────────
function getDB() {
    static $pdo;
    if ($pdo) return $pdo;
    $pdo = new PDO(
        "mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4",
        DB_USER, DB_PASS,
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
         PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]
    );
    return $pdo;
}

// ── CLIENT EXTRA COLUMNS (client_uid — for client-level redirect URLs) ──
// NOTE: this file (index.php) does not share code with inc_exz.php (used
// by vendor.php/track.php/client_redirect.php) - it has its own local
// getDB()/ensureTables(), so these two helpers are duplicated here too,
// matching that existing pattern, rather than adding a require() that
// could pull in unrelated behavior from inc_exz.php.
if (!function_exists('exz_ensure_client_extra_columns')) {
    function exz_ensure_client_extra_columns(PDO $db): void {
        try {
            $db->exec("ALTER TABLE exz_clients ADD COLUMN client_uid VARCHAR(20) DEFAULT NULL");
        } catch (PDOException $e) {
            // Column already exists — ignore (error 1060 = duplicate column)
        }
    }
}
if (!function_exists('exz_generate_client_uid')) {
    function exz_generate_client_uid(PDO $db): string {
        do {
            $code = 'CLT' . substr(bin2hex(random_bytes(4)), 0, 6);
            $chk = $db->prepare("SELECT id FROM exz_clients WHERE client_uid=? LIMIT 1");
            $chk->execute([$code]);
        } while ($chk->fetchColumn());
        return $code;
    }
}

// ── SHORT LINK (exaverify.php?c=CODE) — a compact, optional alternative to
// the full vendor.php?sid=...&vid=...&uid=[UID] entry link. Purely
// additive — the regular vendor.php entry link keeps working exactly as
// before, side by side.
if (!function_exists('exz_ensure_short_code_column')) {
    function exz_ensure_short_code_column(PDO $db): void {
        try {
            $db->exec("ALTER TABLE exz_project_vendors ADD COLUMN short_code VARCHAR(10) DEFAULT NULL");
        } catch (PDOException $e) {
            // Column already exists — ignore (error 1060 = duplicate column)
        }
    }
}
if (!function_exists('exz_ensure_click_quota_column')) {
    function exz_ensure_click_quota_column(PDO $db): void {
        try {
            $db->exec("ALTER TABLE exz_project_vendors ADD COLUMN click_quota INT UNSIGNED DEFAULT NULL");
        } catch (PDOException $e) {}
    }
}
if (!function_exists('exz_ensure_prescreener_toggle_column')) {
    function exz_ensure_prescreener_toggle_column(PDO $db): void {
        try {
            $db->exec("ALTER TABLE exz_project_vendors ADD COLUMN show_prescreener TINYINT(1) DEFAULT 0");
        } catch (PDOException $e) {}
    }
}
function exz_ensure_parent_sid_column(PDO $db): void {
    try {
        $db->exec("ALTER TABLE project_settings ADD COLUMN parent_sid VARCHAR(50) DEFAULT NULL");
    } catch (PDOException $e) {}
    try {
        $db->exec("ALTER TABLE project_settings ADD INDEX idx_parent_sid (parent_sid)");
    } catch (PDOException $e) {}
}
function exz_ensure_is_parent_column(PDO $db): void {
    try {
        $db->exec("ALTER TABLE project_settings ADD COLUMN is_parent TINYINT(1) DEFAULT 0");
    } catch (PDOException $e) {}
}
function exz_ensure_survey_starts_geo_columns(PDO $db): void {
    foreach (['device VARCHAR(20) DEFAULT NULL', 'country VARCHAR(100) DEFAULT NULL', 'city VARCHAR(100) DEFAULT NULL'] as $col) {
        try { $db->exec("ALTER TABLE survey_starts ADD COLUMN $col"); } catch (PDOException $e) {}
    }
}
function exz_ensure_status_synonyms_table(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS `exz_status_synonyms` (
        `id`          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `survey_id`   VARCHAR(50) DEFAULT NULL,
        `synonym`     VARCHAR(50) NOT NULL,
        `maps_to`     VARCHAR(20) NOT NULL,
        `created_at`  DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_syn (survey_id, synonym)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}
function exz_seed_default_status_synonyms(PDO $db): void {
    $chk = $db->query("SELECT COUNT(*) FROM exz_status_synonyms WHERE survey_id IS NULL")->fetchColumn();
    if ($chk > 0) return;
    $defaults = [
        ['success','complete'], ['ok','complete'], ['done','complete'], ['finish','complete'], ['finished','complete'],
        ['screenout','terminate'], ['screen-out','terminate'], ['screen_out','terminate'],
        ['disqualified','terminate'], ['disqualify','terminate'], ['ineligible','terminate'],
        ['reject','terminate'], ['rejected','terminate'], ['fail','terminate'], ['failed','terminate'],
        ['overquota','quotafull'], ['over-quota','quotafull'], ['over_quota','quotafull'],
        ['flagged','qc'],
    ];
    $ins = $db->prepare("INSERT IGNORE INTO exz_status_synonyms (survey_id, synonym, maps_to) VALUES (NULL, ?, ?)");
    foreach ($defaults as [$syn, $target]) $ins->execute([$syn, $target]);
}
if (!function_exists('exz_ensure_project_timeline_columns')) {
    function exz_ensure_project_timeline_columns(PDO $db): void {
        try { $db->exec("ALTER TABLE project_settings ADD COLUMN start_date DATE DEFAULT NULL"); } catch (PDOException $e) {}
        try { $db->exec("ALTER TABLE project_settings ADD COLUMN end_date DATE DEFAULT NULL"); } catch (PDOException $e) {}
        try { $db->exec("ALTER TABLE project_settings ADD COLUMN project_manager VARCHAR(100) DEFAULT ''"); } catch (PDOException $e) {}
    }
}
if (!function_exists('exz_ensure_vendor_extra_columns')) {
    function exz_ensure_vendor_extra_columns(PDO $db): void {
        try { $db->exec("ALTER TABLE exz_vendors ADD COLUMN panel_size INT UNSIGNED DEFAULT NULL"); } catch (PDOException $e) {}
        try { $db->exec("ALTER TABLE exz_vendors ADD COLUMN availability_status VARCHAR(20) DEFAULT 'open'"); } catch (PDOException $e) {}
    }
}
if (!function_exists('exz_ensure_postback_status_columns')) {
    function exz_ensure_postback_status_columns(PDO $db): void {
        try { $db->exec("ALTER TABLE survey_responses ADD COLUMN postback_status VARCHAR(20) DEFAULT 'pending'"); } catch (PDOException $e) {}
        try { $db->exec("ALTER TABLE survey_responses ADD COLUMN postback_at DATETIME DEFAULT NULL"); } catch (PDOException $e) {}
    }
}
if (!function_exists('exz_ensure_pm_activity_table')) {
    function exz_ensure_pm_activity_table(PDO $db): void {
        $db->exec("CREATE TABLE IF NOT EXISTS exz_project_activity_log (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            survey_id VARCHAR(50) NOT NULL,
            user_name VARCHAR(100) DEFAULT '',
            activity VARCHAR(150) NOT NULL,
            sub_activity VARCHAR(150) DEFAULT '',
            duration_minutes INT DEFAULT 0,
            notes TEXT DEFAULT NULL,
            logged_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            KEY idx_survey (survey_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}
if (!function_exists('exz_ensure_country_links_table')) {
    function exz_ensure_country_links_table(PDO $db): void {
        $db->exec("CREATE TABLE IF NOT EXISTS exz_project_country_links (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            survey_id VARCHAR(50) NOT NULL,
            country VARCHAR(100) NOT NULL,
            live_url VARCHAR(500) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_sid_country (survey_id, country)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}
if (!function_exists('exz_generate_short_code')) {
    function exz_generate_short_code(PDO $db): string {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I, avoids confusion
        do {
            $code = '';
            for ($i = 0; $i < 5; $i++) $code .= $chars[random_int(0, strlen($chars) - 1)];
            $chk = $db->prepare("SELECT id FROM exz_project_vendors WHERE short_code=? LIMIT 1");
            $chk->execute([$code]);
        } while ($chk->fetchColumn());
        return $code;
    }
}

// ── BROWSER COLUMN (for IP Tracker) ───────────────────────────
if (!function_exists('exz_ensure_browser_column')) {
    function exz_ensure_browser_column(PDO $db): void {
        try {
            $db->exec("ALTER TABLE survey_responses ADD COLUMN browser VARCHAR(30) DEFAULT ''");
        } catch (PDOException $e) {}
    }
}

// ── QUESTION LIBRARY + PRESCREEN TEMPLATES ────────────────────
if (!function_exists('exz_ensure_question_library_tables')) {
    function exz_ensure_question_library_tables(PDO $db): void {
        $db->exec("CREATE TABLE IF NOT EXISTS exz_question_library (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            country VARCHAR(100) DEFAULT '',
            language VARCHAR(50) DEFAULT '',
            control_type VARCHAR(30) DEFAULT 'text',
            title VARCHAR(200) NOT NULL,
            question_text TEXT NOT NULL,
            min_length INT DEFAULT NULL,
            max_length INT DEFAULT NULL,
            text_type VARCHAR(30) DEFAULT '',
            options TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $db->exec("CREATE TABLE IF NOT EXISTS exz_prescreen_templates (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            template_name VARCHAR(150) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $db->exec("CREATE TABLE IF NOT EXISTS exz_prescreen_template_questions (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            template_id INT UNSIGNED NOT NULL,
            question_id INT UNSIGNED NOT NULL,
            sort_order INT DEFAULT 0,
            KEY idx_template (template_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}
if (!function_exists('exz_ensure_project_template_column')) {
    function exz_ensure_project_template_column(PDO $db): void {
        try {
            $db->exec("ALTER TABLE project_settings ADD COLUMN prescreen_template_id INT UNSIGNED DEFAULT NULL");
        } catch (PDOException $e) {}
    }
}

// ── BLOCKED IP LIST ──────────────────────────────────────────
if (!function_exists('exz_ensure_blocked_ips_table')) {
    function exz_ensure_blocked_ips_table(PDO $db): void {
        $db->exec("CREATE TABLE IF NOT EXISTS exz_blocked_ips (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(64) NOT NULL,
            comment VARCHAR(255) DEFAULT NULL,
            blocked_by VARCHAR(100) DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_ip (ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}

// ── WHATSAPP ──────────────────────────────────────────────────
function sendWhatsApp($msg) {
    // Telegram Bot Alert — settings-table value wins; hardcoded value is
    // only a fallback until Alert Settings is saved for the first time.
    try {
        $pdo = getDB();
        $tok = $pdo->query("SELECT setting_value FROM exz_settings WHERE setting_key='telegram_bot_token'")->fetchColumn();
        $chat= $pdo->query("SELECT setting_value FROM exz_settings WHERE setting_key='telegram_chat_id'")->fetchColumn();
    } catch (Exception $e) { $tok = false; $chat = false; }
    $token   = $tok  ?: TG_TOKEN;
    $chat_id = $chat ?: TG_CHAT_ID;
    if (!$token || !$chat_id) return;
    $url = "https://api.telegram.org/bot".$token."/sendMessage";
    $ctx = stream_context_create(['http'=>[
        'method'  => 'POST',
        'header'  => 'Content-Type: application/x-www-form-urlencoded',
        'content' => http_build_query(['chat_id'=>$chat_id,'text'=>$msg,'parse_mode'=>'HTML']),
        'timeout' => 5
    ]]);
    @file_get_contents($url, false, $ctx);
}

// ── EMAIL ─────────────────────────────────────────────────────
function sendEmail($subject, $body) {
    try {
        $pdo = getDB();
        $em = $pdo->query("SELECT setting_value FROM exz_settings WHERE setting_key='alert_email'")->fetchColumn();
    } catch (Exception $e) { $em = false; }
    $to = $em ?: ALERT_EMAIL;
    @mail($to, $subject, $body,
        "From: dashboard@exazonresearch.com\r\nContent-Type: text/html; charset=UTF-8");
}

// ── ENSURE TABLES ─────────────────────────────────────────────
function ensureTables($pdo) {
    // Main responses table
    $pdo->exec("CREATE TABLE IF NOT EXISTS `survey_responses` (
        `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `survey_id`   VARCHAR(50)  NOT NULL,
        `respondent`  VARCHAR(100) NOT NULL,
        `status`      VARCHAR(30)  NOT NULL,
        `source`      VARCHAR(100) DEFAULT '',
        `client_name` VARCHAR(100) DEFAULT '',
        `ip`          VARCHAR(45)  DEFAULT '',
        `device`      VARCHAR(20)  DEFAULT '',
        `country`     VARCHAR(100) DEFAULT '',
        `city`        VARCHAR(100) DEFAULT '',
        `loi_seconds` INT          DEFAULT NULL,
        `is_duplicate` TINYINT(1)  DEFAULT 0,
        `created_at`  DATETIME     DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_survey  (`survey_id`),
        INDEX idx_status  (`status`),
        INDEX idx_created (`created_at`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Notes table
    $pdo->exec("CREATE TABLE IF NOT EXISTS `dashboard_notes` (
        `id`         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `note`       TEXT NOT NULL,
        `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Survey starts — logged when a respondent enters (vendor.php/entry.php),
    // used to compute a reliable, self-measured LOI at completion time.
    $pdo->exec("CREATE TABLE IF NOT EXISTS `survey_starts` (
        `id`         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `uid`        VARCHAR(255) NOT NULL,
        `sid`        VARCHAR(50)  NOT NULL,
        `source`     VARCHAR(50)  DEFAULT 'direct',
        `vendor_id`  INT UNSIGNED DEFAULT NULL,
        `ip`         VARCHAR(45)  DEFAULT '',
        `start_time` DATETIME     DEFAULT CURRENT_TIMESTAMP,
        KEY idx_uid_sid (`uid`,`sid`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Project settings (target + CPI + vendor cost)
    $pdo->exec("CREATE TABLE IF NOT EXISTS `project_settings` (
        `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `survey_id`    VARCHAR(50) NOT NULL UNIQUE,
        `target`       INT UNSIGNED DEFAULT 0,
        `cpi`          DECIMAL(10,2) DEFAULT 0.00,
        `vendor_cost`  DECIMAL(10,2) DEFAULT 0.00,
        `created_at`   DATETIME DEFAULT CURRENT_TIMESTAMP,
        `updated_at`   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Client portal accounts table
    $pdo->exec("CREATE TABLE IF NOT EXISTS `portal_clients` (
        `id`               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `username`         VARCHAR(60) NOT NULL UNIQUE,
        `password_hash`    VARCHAR(255) NOT NULL,
        `client_name`      VARCHAR(100) NOT NULL,
        `client_id`        INT UNSIGNED DEFAULT NULL,
        `allowed_projects` TEXT DEFAULT NULL,
        `is_active`        TINYINT(1) DEFAULT 1,
        `last_login`       DATETIME DEFAULT NULL,
        `created_at`       DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Clients master data (separate from portal login accounts)
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_clients` (
        `id`             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `client_name`    VARCHAR(150) NOT NULL,
        `contact_person` VARCHAR(100) DEFAULT '',
        `email`          VARCHAR(150) DEFAULT '',
        `phone`          VARCHAR(40)  DEFAULT '',
        `notes`          TEXT DEFAULT NULL,
        `created_at`     DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Vendors / panel sources master data
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_vendors` (
        `id`             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `vendor_name`    VARCHAR(150) NOT NULL,
        `contact_person` VARCHAR(100) DEFAULT '',
        `email`          VARCHAR(150) DEFAULT '',
        `phone`          VARCHAR(40)  DEFAULT '',
        `notes`          TEXT DEFAULT NULL,
        `created_at`     DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Vendor <-> Project assignment (many vendors can be assigned per project)
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_project_vendors` (
        `id`         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `survey_id`  VARCHAR(50) NOT NULL,
        `vendor_id`  INT UNSIGNED NOT NULL,
        `status`     VARCHAR(20) DEFAULT 'active',
        `cpi`        DECIMAL(10,2) DEFAULT NULL,
        `max_limit`  INT UNSIGNED DEFAULT NULL,
        `assigned_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_proj_vendor (`survey_id`,`vendor_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Audit log — tracks delete/critical actions across the dashboard
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_audit_log` (
        `id`           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `action`       VARCHAR(60) NOT NULL,
        `detail`       VARCHAR(255) DEFAULT '',
        `performed_by` VARCHAR(100) DEFAULT NULL,
        `performed_at` DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    try { $pdo->exec("ALTER TABLE exz_audit_log ADD COLUMN performed_by VARCHAR(100) DEFAULT NULL"); } catch (PDOException $e) {}

    // Share links — no-login read-only Client Report Link + JSON API token
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_share_links` (
        `id`          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `survey_id`   VARCHAR(50) NOT NULL,
        `token`       VARCHAR(64) NOT NULL UNIQUE,
        `is_revoked`  TINYINT(1) DEFAULT 0,
        `created_at`  DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Screener (pre-survey) answers — captured before the client survey starts
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_screener_answers` (
        `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `survey_id`     VARCHAR(50) NOT NULL,
        `respondent`    VARCHAR(255) NOT NULL,
        `question_key`  VARCHAR(100) NOT NULL,
        `question_text` VARCHAR(255) DEFAULT '',
        `answer_value`  TEXT DEFAULT NULL,
        `created_at`    DATETIME DEFAULT CURRENT_TIMESTAMP,
        KEY idx_survey_respondent (`survey_id`,`respondent`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Invoice / billing status per project
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_invoice_status` (
        `survey_id`    VARCHAR(50) PRIMARY KEY,
        `status`       VARCHAR(20) DEFAULT 'unpaid',
        `invoice_no`   VARCHAR(50) DEFAULT '',
        `notes`        TEXT DEFAULT NULL,
        `updated_at`   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // UID mapping — reverse-lookup table for encrypted respondent IDs
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_uid_mapping` (
        `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `original_uid`  VARCHAR(255) NOT NULL,
        `encrypted_uid` VARCHAR(255) NOT NULL,
        `survey_id`     VARCHAR(50) DEFAULT NULL,
        `source`        VARCHAR(50) DEFAULT 'vendor',
        `created_at`    DATETIME DEFAULT CURRENT_TIMESTAMP,
        KEY idx_enc (`encrypted_uid`),
        KEY idx_orig_sid (`original_uid`,`survey_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Settings — key/value config (alert email, telegram token/chat, etc.)
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_settings` (
        `setting_key`   VARCHAR(100) PRIMARY KEY,
        `setting_value` TEXT DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Team members — role-based access (superadmin/manager/viewer)
    $pdo->exec("CREATE TABLE IF NOT EXISTS `exz_team` (
        `id`         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `name`       VARCHAR(100) NOT NULL,
        `email`      VARCHAR(150) DEFAULT '',
        `password_hash` VARCHAR(255) DEFAULT NULL,
        `role`       VARCHAR(20) DEFAULT 'viewer',
        `is_active`  TINYINT(1) DEFAULT 1,
        `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Safe column migrations for existing tables
    try {
        $cols = $pdo->query("SHOW COLUMNS FROM survey_responses")->fetchAll(PDO::FETCH_COLUMN);
        $need = [
            'client_name' => "ALTER TABLE survey_responses ADD COLUMN client_name VARCHAR(100) DEFAULT '' AFTER source",
            'city'        => "ALTER TABLE survey_responses ADD COLUMN city VARCHAR(100) DEFAULT '' AFTER country",
            'loi_seconds' => "ALTER TABLE survey_responses ADD COLUMN loi_seconds INT DEFAULT NULL",
            'is_duplicate'=> "ALTER TABLE survey_responses ADD COLUMN is_duplicate TINYINT(1) DEFAULT 0",
            'device'      => "ALTER TABLE survey_responses ADD COLUMN device VARCHAR(20) DEFAULT ''",
            'status_locked' => "ALTER TABLE survey_responses ADD COLUMN status_locked TINYINT(1) DEFAULT 0",
            'vendor_id'   => "ALTER TABLE survey_responses ADD COLUMN vendor_id INT UNSIGNED DEFAULT NULL",
        ];
        foreach ($need as $col => $sql) {
            if (!in_array($col, $cols)) { try { $pdo->exec($sql); } catch(Exception $e){} }
        }
        // Migrate old 'client' column data if exists
        if (in_array('client', $cols)) {
            try { $pdo->exec("UPDATE survey_responses SET client_name=client WHERE client_name='' AND client!=''"); } catch(Exception $e){}
        }

        // project_settings: add management columns (name, client, status, pin, color, type)
        $ps_cols = $pdo->query("SHOW COLUMNS FROM project_settings")->fetchAll(PDO::FETCH_COLUMN);
        $ps_need = [
            'project_name' => "ALTER TABLE project_settings ADD COLUMN project_name VARCHAR(150) DEFAULT '' AFTER survey_id",
            'client_id'    => "ALTER TABLE project_settings ADD COLUMN client_id INT UNSIGNED DEFAULT NULL",
            'status'       => "ALTER TABLE project_settings ADD COLUMN status VARCHAR(20) DEFAULT 'active'",
            'is_pinned'    => "ALTER TABLE project_settings ADD COLUMN is_pinned TINYINT(1) DEFAULT 0",
            'color_tag'    => "ALTER TABLE project_settings ADD COLUMN color_tag VARCHAR(20) DEFAULT ''",
            'project_type' => "ALTER TABLE project_settings ADD COLUMN project_type VARCHAR(20) DEFAULT 'direct'",
            'notes'        => "ALTER TABLE project_settings ADD COLUMN notes TEXT DEFAULT NULL",
        ];
        foreach ($ps_need as $col => $sql) {
            if (!in_array($col, $ps_cols)) { try { $pdo->exec($sql); } catch(Exception $e){} }
        }

        // project_settings: add live URL + encryption toggle
        $ps2_cols = $pdo->query("SHOW COLUMNS FROM project_settings")->fetchAll(PDO::FETCH_COLUMN);
        $ps2_need = [
            'live_url'    => "ALTER TABLE project_settings ADD COLUMN live_url TEXT DEFAULT NULL",
            'encrypt_uid' => "ALTER TABLE project_settings ADD COLUMN encrypt_uid TINYINT(1) DEFAULT 1",
            'ir'          => "ALTER TABLE project_settings ADD COLUMN ir DECIMAL(5,2) DEFAULT 0",
            'loi'         => "ALTER TABLE project_settings ADD COLUMN loi INT DEFAULT 0",
            'test_url'    => "ALTER TABLE project_settings ADD COLUMN test_url TEXT DEFAULT NULL",
            'description' => "ALTER TABLE project_settings ADD COLUMN description TEXT DEFAULT NULL",
            'auto_report_enabled'   => "ALTER TABLE project_settings ADD COLUMN auto_report_enabled TINYINT(1) DEFAULT 0",
            'auto_report_freq'      => "ALTER TABLE project_settings ADD COLUMN auto_report_freq VARCHAR(10) DEFAULT 'weekly'",
            'auto_report_email'     => "ALTER TABLE project_settings ADD COLUMN auto_report_email VARCHAR(150) DEFAULT ''",
            'auto_report_last_sent' => "ALTER TABLE project_settings ADD COLUMN auto_report_last_sent DATETIME DEFAULT NULL",
            'target_countries'      => "ALTER TABLE project_settings ADD COLUMN target_countries VARCHAR(500) DEFAULT NULL",
        ];
        foreach ($ps2_need as $col => $sql) {
            if (!in_array($col, $ps2_cols)) { try { $pdo->exec($sql); } catch(Exception $e){} }
        }

        // exz_vendors: add postback URLs + end-behavior
        $v_cols = $pdo->query("SHOW COLUMNS FROM exz_vendors")->fetchAll(PDO::FETCH_COLUMN);
        $v_need = [
            'complete_url'  => "ALTER TABLE exz_vendors ADD COLUMN complete_url VARCHAR(500) DEFAULT NULL",
            'terminate_url' => "ALTER TABLE exz_vendors ADD COLUMN terminate_url VARCHAR(500) DEFAULT NULL",
            'screenout_url' => "ALTER TABLE exz_vendors ADD COLUMN screenout_url VARCHAR(500) DEFAULT NULL",
            'quotafull_url' => "ALTER TABLE exz_vendors ADD COLUMN quotafull_url VARCHAR(500) DEFAULT NULL",
            'end_behavior'  => "ALTER TABLE exz_vendors ADD COLUMN end_behavior VARCHAR(20) DEFAULT 'show_page'",
            'status'        => "ALTER TABLE exz_vendors ADD COLUMN status VARCHAR(20) DEFAULT 'active'",
        ];
        foreach ($v_need as $col => $sql) {
            if (!in_array($col, $v_cols)) { try { $pdo->exec($sql); } catch(Exception $e){} }
        }

        // exz_clients: add status column
        try {
            $cl_cols = $pdo->query("SHOW COLUMNS FROM exz_clients")->fetchAll(PDO::FETCH_COLUMN);
            if (!in_array('status', $cl_cols)) {
                $pdo->exec("ALTER TABLE exz_clients ADD COLUMN status VARCHAR(20) DEFAULT 'active'");
            }
        } catch(Exception $e){}

        // portal_clients: link to master Clients record (client_id) if missing
        try {
            $pc_cols = $pdo->query("SHOW COLUMNS FROM portal_clients")->fetchAll(PDO::FETCH_COLUMN);
            if (!in_array('client_id', $pc_cols)) {
                $pdo->exec("ALTER TABLE portal_clients ADD COLUMN client_id INT UNSIGNED DEFAULT NULL");
            }
        } catch(Exception $e){}

        // exz_project_vendors: add per-project vendor status if missing
        try {
            $pv_cols = $pdo->query("SHOW COLUMNS FROM exz_project_vendors")->fetchAll(PDO::FETCH_COLUMN);
            if (!in_array('status', $pv_cols)) {
                $pdo->exec("ALTER TABLE exz_project_vendors ADD COLUMN status VARCHAR(20) DEFAULT 'active'");
            }
            if (!in_array('cpi', $pv_cols)) {
                $pdo->exec("ALTER TABLE exz_project_vendors ADD COLUMN cpi DECIMAL(10,2) DEFAULT NULL");
            }
            if (!in_array('max_limit', $pv_cols)) {
                $pdo->exec("ALTER TABLE exz_project_vendors ADD COLUMN max_limit INT UNSIGNED DEFAULT NULL");
            }
            // One-time backfill: existing assignments with no CPI set yet
            // get the project's own Vendor Cost, so they don't show $0.00.
            // Guarded by a flag so it never re-runs and overwrite later
            // intentional per-vendor CPI edits (including a deliberate 0).
            $already_backfilled = $pdo->query("SELECT setting_value FROM exz_settings WHERE setting_key='pv_cpi_backfilled_v1'")->fetchColumn();
            if (!$already_backfilled) {
                $pdo->exec("UPDATE exz_project_vendors pv
                    JOIN project_settings ps ON ps.survey_id = pv.survey_id
                    SET pv.cpi = ps.vendor_cost
                    WHERE pv.cpi IS NULL OR pv.cpi = 0");
                $pdo->prepare("INSERT INTO exz_settings (setting_key,setting_value) VALUES ('pv_cpi_backfilled_v1','1')
                    ON DUPLICATE KEY UPDATE setting_value='1'")->execute();
            }
        } catch(Exception $e){}

        // exz_team: add password_hash if table already existed without it
        try {
            $t_cols = $pdo->query("SHOW COLUMNS FROM exz_team")->fetchAll(PDO::FETCH_COLUMN);
            if (!in_array('password_hash', $t_cols)) {
                $pdo->exec("ALTER TABLE exz_team ADD COLUMN password_hash VARCHAR(255) DEFAULT NULL");
            }
        } catch(Exception $e){}
    } catch(Exception $e){}
}

// ── CSV EXPORT ────────────────────────────────────────────────
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $pdo = getDB(); ensureTables($pdo);
    $rows = exz_get_export_rows($pdo, $_GET);
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="exazon_'.date('Ymd_His').'.csv"');
    $out = fopen('php://output','w');
    fputcsv($out,['Survey ID','Respondent ID','Vendor','Status','Source','Client','IP','Device','Country','City','LOI(sec)','LOI(min)','Duplicate','Timestamp']);
    foreach($rows as $r) {
        $loi_min = $r['loi_seconds'] ? round($r['loi_seconds']/60,1).'m' : '-';
        // Explicit column order matching the header exactly — relying on
        // associative-array insertion order (array_values) broke this: the
        // 'loi_min' key was always appended AFTER is_duplicate/created_at
        // internally, silently shifting LOI(min)/Duplicate/Timestamp one
        // column to the right of what the header row promised, in every
        // export this system has ever generated.
        fputcsv($out, [
            $r['survey_id'], $r['respondent'], $r['vendor_name'] ?? '', $r['status'], $r['source'] ?? '', $r['client_name'] ?? '',
            $r['ip'] ?? '', $r['device'] ?? '', $r['country'] ?? '', $r['city'] ?? '',
            $r['loi_seconds'] ?? '', $loi_min, ($r['is_duplicate'] ?? 0) ? 'Yes' : 'No', $r['created_at'],
        ]);
    }
    fclose($out); exit;
}

// ── JSON EXPORT ───────────────────────────────────────────────
if (isset($_GET['export']) && $_GET['export'] === 'json') {
    $pdo = getDB(); ensureTables($pdo);
    $rows = exz_get_export_rows($pdo, $_GET);
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="exazon_'.date('Ymd_His').'.json"');
    echo json_encode($rows, JSON_PRETTY_PRINT);
    exit;
}

// ── EXCEL (XLSX) EXPORT ──────────────────────────────────────────
if (isset($_GET['export']) && $_GET['export'] === 'xlsx') {
    $pdo = getDB(); ensureTables($pdo);
    if (!class_exists('ZipArchive')) {
        http_response_code(500);
        die('Excel export needs the PHP zip extension, which isn\'t enabled on this server. Use CSV or JSON export instead, or ask your host to enable php-zip.');
    }
    $rows = exz_get_export_rows($pdo, $_GET);
    $headers = ['Survey ID','Respondent ID','Vendor','Status','Source','Client','IP','Device','Country','City','LOI (sec)','LOI (min)','Duplicate','Timestamp'];
    $xlsx_rows = [];
    foreach ($rows as $r) {
        $xlsx_rows[] = [
            $r['survey_id'], $r['respondent'], $r['vendor_name'] ?? '', $r['status'], $r['source'] ?? '', $r['client_name'] ?? '',
            $r['ip'] ?? '', $r['device'] ?? '', $r['country'] ?? '', $r['city'] ?? '',
            $r['loi_seconds'] ?? '', $r['loi_seconds'] ? round($r['loi_seconds']/60,1).'m' : '',
            ($r['is_duplicate'] ?? 0) ? 'Yes' : 'No', $r['created_at'],
        ];
    }
    $bytes = exz_array_to_xlsx($headers, $xlsx_rows);
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="exazon_'.date('Ymd_His').'.xlsx"');
    header('Content-Length: '.strlen($bytes));
    echo $bytes; exit;
}

// ── DATABASE BACKUP (full SQL dump — superadmin only) ──────────
if (isset($_GET['backup']) && $_GET['backup'] === '1') {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    header('Content-Type: application/sql');
    header('Content-Disposition: attachment; filename="exaverify_backup_'.date('Ymd_His').'.sql"');
    $out = fopen('php://output', 'w');
    fwrite($out, "-- ExaVerify full database backup\n-- Generated: ".date('Y-m-d H:i:s')."\n\n");
    fwrite($out, "SET FOREIGN_KEY_CHECKS=0;\n\n");
    try {
        $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
        foreach ($tables as $table) {
            // Structure
            $createRow = $pdo->query("SHOW CREATE TABLE `$table`")->fetch();
            $createSql = $createRow['Create Table'] ?? $createRow[1] ?? '';
            fwrite($out, "-- ----------------------------\n-- Table: $table\n-- ----------------------------\n");
            fwrite($out, "DROP TABLE IF EXISTS `$table`;\n");
            fwrite($out, $createSql . ";\n\n");
            // Data
            $rowCount = (int)$pdo->query("SELECT COUNT(*) FROM `$table`")->fetchColumn();
            if ($rowCount > 0) {
                $chunkSize = 500;
                for ($offset = 0; $offset < $rowCount; $offset += $chunkSize) {
                    $stmt = $pdo->query("SELECT * FROM `$table` LIMIT $chunkSize OFFSET $offset");
                    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                        $cols = array_map(fn($c) => "`$c`", array_keys($row));
                        $vals = array_map(function($v) use ($pdo) {
                            if ($v === null) return 'NULL';
                            return $pdo->quote((string)$v);
                        }, array_values($row));
                        fwrite($out, "INSERT INTO `$table` (" . implode(',', $cols) . ") VALUES (" . implode(',', $vals) . ");\n");
                    }
                }
                fwrite($out, "\n");
            }
        }
    } catch (Exception $e) {
        fwrite($out, "-- ERROR during backup: " . $e->getMessage() . "\n");
    }
    fwrite($out, "SET FOREIGN_KEY_CHECKS=1;\n");
    fclose($out);
    exit;
}

// ── AUDIT LOG EXCEL EXPORT (just the audit trail, not a full DB dump) ────
if (isset($_GET['audit_export']) && $_GET['audit_export'] === 'xlsx') {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    if (!class_exists('ZipArchive')) {
        http_response_code(500);
        die('Excel export needs the PHP zip extension, which isn\'t enabled on this server. Use the full SQL backup instead, or ask your host to enable php-zip.');
    }
    $rows = $pdo->query("SELECT action, detail, performed_by, performed_at FROM exz_audit_log ORDER BY id DESC")->fetchAll();
    $headers = ['Action', 'Detail', 'Performed By', 'Timestamp'];
    $xlsx_rows = [];
    foreach ($rows as $r) {
        $xlsx_rows[] = [$r['action'], $r['detail'], $r['performed_by'] ?: 'Unknown', $r['performed_at']];
    }
    $bytes = exz_array_to_xlsx($headers, $xlsx_rows);
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="exaverify_audit_log_'.date('Ymd_His').'.xlsx"');
    header('Content-Length: '.strlen($bytes));
    echo $bytes; exit;
}


if (isset($_GET['export_screener'])) {
    $pdo = getDB(); ensureTables($pdo);
    $where = '1=1'; $params = [];
    if (!empty($_GET['scr_sid'])) { $where .= ' AND survey_id=?'; $params[] = $_GET['scr_sid']; }
    $stmt = $pdo->prepare("SELECT survey_id,respondent,question_key,answer_value,created_at FROM exz_screener_answers WHERE $where ORDER BY created_at ASC");
    $stmt->execute($params);
    $pivot = [];
    foreach ($stmt->fetchAll() as $r) {
        $k = $r['respondent'].'|'.$r['survey_id'];
        if (!isset($pivot[$k])) $pivot[$k] = ['uid'=>$r['respondent'],'sid'=>$r['survey_id'],'gender'=>'','age_group'=>'','education'=>'','income'=>'','device_self'=>'','date'=>$r['created_at']];
        if (isset($pivot[$k][$r['question_key']])) $pivot[$k][$r['question_key']] = $r['answer_value'];
    }
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="screener_data_'.date('Ymd_His').'.csv"');
    $out = fopen('php://output','w');
    fputcsv($out, ['UID','SID','Gender','Age','Education','Income','Device','Date']);
    foreach($pivot as $r) fputcsv($out, array_values($r));
    fclose($out); exit;
}
// ── SCREENER DATA: DELETE / BULK DELETE (per respondent group) ──
if (isset($_GET['del_screener'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $parts = explode('|', $_GET['del_screener'], 2);
    if (count($parts) === 2) {
        $pdo->prepare("DELETE FROM exz_screener_answers WHERE respondent=? AND survey_id=?")->execute([$parts[0], $parts[1]]);
    }
    header('Location: index.php#screener'); exit;
}
if (isset($_POST['bulk_delete_screener'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $keys = array_filter(explode(',', $_POST['screener_ids'] ?? ''));
    $del = $pdo->prepare("DELETE FROM exz_screener_answers WHERE respondent=? AND survey_id=?");
    foreach ($keys as $k) {
        $parts = explode('|', $k, 2);
        if (count($parts) === 2) $del->execute([$parts[0], $parts[1]]);
    }
    if ($keys) {
        exz_log_audit_local($pdo, 'bulk_delete_screener', count($keys)." respondent(s)");
    }
    header('Location: index.php#screener'); exit;
}

// ── SAVE PROJECT SETTINGS ─────────────────────────────────────
if (isset($_POST['save_settings'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo      = getDB();
    ensureTables($pdo);
    $ps_sid   = trim($_POST['ps_sid']      ?? '');
    $ps_tgt   = intval($_POST['ps_target'] ?? 0);
    $ps_cpi   = floatval($_POST['ps_cpi']  ?? 0);
    $ps_vcost = floatval($_POST['ps_vcost']?? 0);
    if ($ps_sid) {
        try {
            $pdo->prepare("INSERT INTO project_settings (survey_id,target,cpi,vendor_cost)
                VALUES (?,?,?,?)
                ON DUPLICATE KEY UPDATE target=VALUES(target),cpi=VALUES(cpi),vendor_cost=VALUES(vendor_cost)")
                ->execute([$ps_sid, $ps_tgt, $ps_cpi, $ps_vcost]);
        } catch(Exception $e) {
            error_log("Settings save error: ".$e->getMessage());
        }
    }
    header('Location: index.php#projects'); exit;
}

// ── NOTES ─────────────────────────────────────────────────────
if (isset($_POST['save_note'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $t = trim($_POST['note_text'] ?? '');
    if ($t) $pdo->prepare("INSERT INTO dashboard_notes (note) VALUES (?)")->execute([$t]);
    header('Location: index.php#notes'); exit;
}
if (isset($_GET['del_note'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    getDB()->prepare("DELETE FROM dashboard_notes WHERE id=?")->execute([intval($_GET['del_note'])]);
    header('Location: index.php#notes'); exit;
}

// ── PROJECT MANAGEMENT (Direct + TP, full CRUD) ────────────────
if (isset($_POST['save_project'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    exz_ensure_question_library_tables($pdo);
    exz_ensure_project_template_column($pdo);
    exz_ensure_project_timeline_columns($pdo);
    exz_ensure_parent_sid_column($pdo);
    exz_ensure_is_parent_column($pdo);
    $sid    = trim($_POST['pr_sid']    ?? '');
    if ($sid && preg_match('/^[A-Za-z0-9_-]+$/', $sid)) {
        // Merge with existing row so a partial form (e.g. Live URL only) never wipes other fields
        $ex = $pdo->prepare("SELECT * FROM project_settings WHERE survey_id=?"); $ex->execute([$sid]);
        $existing = $ex->fetch() ?: [];
        $name   = trim($_POST['pr_name']    ?? ($existing['project_name'] ?? ''));
        $client = isset($_POST['pr_client']) && $_POST['pr_client'] !== '' ? intval($_POST['pr_client']) : ($existing['client_id'] ?? null);
        $cpi    = isset($_POST['pr_cpi'])    && $_POST['pr_cpi']    !== '' ? floatval($_POST['pr_cpi'])    : ($existing['cpi'] ?? 0);
        $vcost  = isset($_POST['pr_vcost'])  && $_POST['pr_vcost']  !== '' ? floatval($_POST['pr_vcost'])  : ($existing['vendor_cost'] ?? 0);
        $target = isset($_POST['pr_target']) && $_POST['pr_target'] !== '' ? intval($_POST['pr_target'])  : ($existing['target'] ?? 0);
        $ptype  = trim($_POST['pr_type']    ?? '') ?: ($existing['project_type'] ?? 'direct');
        $liveurl= isset($_POST['pr_liveurl']) && $_POST['pr_liveurl'] !== '' ? trim($_POST['pr_liveurl']) : ($existing['live_url'] ?? '');
        $testurl= isset($_POST['pr_testurl']) && $_POST['pr_testurl'] !== '' ? trim($_POST['pr_testurl']) : ($existing['test_url'] ?? '');
        $desc   = isset($_POST['pr_description']) ? trim($_POST['pr_description']) : ($existing['description'] ?? '');
        $countries = isset($_POST['pr_countries']) ? trim($_POST['pr_countries']) : ($existing['target_countries'] ?? '');
        $encrypt= isset($_POST['pr_encrypt']) ? 1 : (isset($existing['encrypt_uid']) ? $existing['encrypt_uid'] : 1);
        $ptemplate = isset($_POST['pr_template']) && $_POST['pr_template'] !== '' ? intval($_POST['pr_template']) : ($existing['prescreen_template_id'] ?? null);
        $startdate = isset($_POST['pr_start_date']) && $_POST['pr_start_date'] !== '' ? $_POST['pr_start_date'] : ($existing['start_date'] ?? null);
        $enddate   = isset($_POST['pr_end_date']) && $_POST['pr_end_date'] !== '' ? $_POST['pr_end_date'] : ($existing['end_date'] ?? null);
        $pmanager  = isset($_POST['pr_manager']) ? trim($_POST['pr_manager']) : ($existing['project_manager'] ?? '');

        // ── Parent/Child Structure — separate from the "Type" (Direct/TP) field ──
        $structure = trim($_POST['pr_structure'] ?? '');
        if ($structure === '') {
            // No selector submitted at all (e.g. an older cached form, or an
            // API-style POST) — preserve whatever this SID already had rather
            // than silently resetting an existing parent/child link on every
            // unrelated save (Live URL tweak, etc).
            $is_parent  = intval($existing['is_parent'] ?? 0);
            $parent_sid = ($existing['parent_sid'] ?? null) ?: null;
        } else {
            $childChk = $pdo->prepare("SELECT 1 FROM project_settings WHERE parent_sid=? LIMIT 1");
            $childChk->execute([$sid]);
            $currently_has_children = (bool)$childChk->fetchColumn();

            if ($structure === 'parent') {
                if (!empty($existing['parent_sid'])) {
                    header("Location: index.php?msg=".urlencode("'$sid' is itself a child project — it can't also be a parent (no nesting beyond 2 levels). Remove its parent link first.")."#projects"); exit;
                }
                $is_parent = 1; $parent_sid = null;
            } elseif ($structure === 'child') {
                $wanted_parent = trim($_POST['pr_parent_sid'] ?? '');
                if ($currently_has_children) {
                    header("Location: index.php?msg=".urlencode("'$sid' already has child projects — it can't become a child itself. Reassign or remove its children first.")."#projects"); exit;
                }
                if ($wanted_parent === '' || $wanted_parent === $sid) {
                    header("Location: index.php?msg=".urlencode("Pick a valid parent project for '$sid'.")."#projects"); exit;
                }
                $pchk = $pdo->prepare("SELECT is_parent, parent_sid FROM project_settings WHERE survey_id=?");
                $pchk->execute([$wanted_parent]);
                $prow = $pchk->fetch();
                if (!$prow || !$prow['is_parent'] || !empty($prow['parent_sid'])) {
                    header("Location: index.php?msg=".urlencode("'$wanted_parent' isn't a valid parent project (it must be marked as a Parent, and not itself be a child).")."#projects"); exit;
                }
                $is_parent = 0; $parent_sid = $wanted_parent;
            } else { // standalone
                if ($currently_has_children) {
                    header("Location: index.php?msg=".urlencode("'$sid' has child projects attached — reassign or remove them before making it Standalone.")."#projects"); exit;
                }
                $is_parent = 0; $parent_sid = null;
            }
        }

        try {
            $pdo->prepare("INSERT INTO project_settings (survey_id,project_name,client_id,cpi,vendor_cost,target,project_type,live_url,test_url,description,target_countries,encrypt_uid,prescreen_template_id,start_date,end_date,project_manager,parent_sid,is_parent,status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active')
                ON DUPLICATE KEY UPDATE project_name=VALUES(project_name),client_id=VALUES(client_id),
                cpi=VALUES(cpi),vendor_cost=VALUES(vendor_cost),target=VALUES(target),project_type=VALUES(project_type),
                live_url=VALUES(live_url),test_url=VALUES(test_url),description=VALUES(description),
                target_countries=VALUES(target_countries),encrypt_uid=VALUES(encrypt_uid),prescreen_template_id=VALUES(prescreen_template_id),
                start_date=VALUES(start_date),end_date=VALUES(end_date),project_manager=VALUES(project_manager),
                parent_sid=VALUES(parent_sid),is_parent=VALUES(is_parent)")
                ->execute([$sid,$name,$client,$cpi,$vcost,$target,$ptype,$liveurl,$testurl,$desc,$countries,$encrypt,$ptemplate,$startdate,$enddate,$pmanager,$parent_sid,$is_parent]);

            exz_log_audit_local($pdo, 'save_project', "SID: $sid");
        } catch(Exception $e){ error_log("save_project: ".$e->getMessage()); }
    }
    header('Location: index.php#projects'); exit;
}

// ── BULK PROJECT IMPORT (CSV) ──────────────────────────────────
// Lets a manager create many projects in one go instead of filling the
// Add/Update Project form individually for each one — genuinely useful
// when a client sends a batch of surveys at once (e.g. 10 projects in a
// single email). Reuses the exact same INSERT...ON DUPLICATE KEY UPDATE
// pattern as the single-project form above, so behavior stays identical
// (re-importing the same SID safely updates rather than duplicating).
if (isset($_POST['bulk_import_projects'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    exz_ensure_parent_sid_column($pdo);
    exz_ensure_is_parent_column($pdo);
    $results = ['created' => 0, 'updated' => 0, 'errors' => []];
    $csv_parent_links = []; // sid => wanted_parent_sid, resolved in a second pass below
    if (!empty($_FILES['bulk_csv']['tmp_name']) && is_uploaded_file($_FILES['bulk_csv']['tmp_name'])) {
        $fh = fopen($_FILES['bulk_csv']['tmp_name'], 'r');
        if ($fh) {
            $header = fgetcsv($fh);
            // Normalize header names so column-order/case in the uploaded file
            // doesn't matter, only that these column-names exist somewhere.
            $header = array_map(fn($h) => strtolower(trim($h ?? '')), $header ?: []);
            $col = array_flip($header);
            $row_num = 1;
            while (($row = fgetcsv($fh)) !== false) {
                $row_num++;
                $get = fn($key) => isset($col[$key], $row[$col[$key]]) ? trim($row[$col[$key]]) : '';
                $sid = $get('sid');
                if (!$sid) { continue; } // skip genuinely blank rows
                if (!preg_match('/^[A-Za-z0-9_-]+$/', $sid)) {
                    $results['errors'][] = "Row $row_num (SID: $sid): invalid SID — letters, numbers, underscore, hyphen only.";
                    continue;
                }
                $name    = $get('project_name') ?: $sid;
                $cpi     = $get('cpi') !== '' ? floatval($get('cpi')) : 0;
                $target  = $get('target') !== '' ? intval($get('target')) : 0;
                $liveurl = $get('live_url');
                $client_name = $get('client_name');
                $client_id = null;
                if ($client_name) {
                    $cc = $pdo->prepare("SELECT id FROM exz_clients WHERE client_name = ? LIMIT 1");
                    $cc->execute([$client_name]);
                    $client_id = $cc->fetchColumn();
                    if (!$client_id) {
                        // Genuinely new client name — create it rather than silently
                        // dropping the association, matching how the single-project
                        // form's client dropdown would require it to already exist,
                        // but a bulk-CSV shouldn't force a separate manual step first.
                        $pdo->prepare("INSERT INTO exz_clients (client_name, status) VALUES (?, 'active')")->execute([$client_name]);
                        $client_id = $pdo->lastInsertId();
                    }
                }
                $wanted_parent = $get('parent_sid');
                if ($wanted_parent !== '') $csv_parent_links[$sid] = $wanted_parent;
                try {
                    $existed = $pdo->prepare("SELECT 1 FROM project_settings WHERE survey_id=?");
                    $existed->execute([$sid]);
                    $was_existing = (bool)$existed->fetchColumn();

                    $pdo->prepare("INSERT INTO project_settings (survey_id,project_name,client_id,cpi,target,live_url,encrypt_uid,status)
                        VALUES (?,?,?,?,?,?,1,'active')
                        ON DUPLICATE KEY UPDATE project_name=VALUES(project_name),client_id=VALUES(client_id),
                        cpi=VALUES(cpi),target=VALUES(target),live_url=VALUES(live_url)")
                        ->execute([$sid,$name,$client_id,$cpi,$target,$liveurl]);

                    if ($was_existing) { $results['updated']++; } else { $results['created']++; }
                } catch (Exception $e) {
                    $results['errors'][] = "Row $row_num (SID: $sid): " . $e->getMessage();
                }
            }
            fclose($fh);

            // ── Second pass: resolve parent_sid links now that every row in this
            // batch exists. Handled separately from the row-by-row insert above so
            // a child's parent can appear anywhere in the CSV — before or after —
            // without needing a strict "parents first" row order.
            foreach ($csv_parent_links as $child_sid => $wanted_parent) {
                if ($wanted_parent === $child_sid) {
                    $results['errors'][] = "SID $child_sid: can't be its own parent — skipped.";
                    continue;
                }
                $pchk = $pdo->prepare("SELECT is_parent, parent_sid FROM project_settings WHERE survey_id=?");
                $pchk->execute([$wanted_parent]);
                $prow = $pchk->fetch();
                if (!$prow) {
                    $results['errors'][] = "SID $child_sid: parent_sid '$wanted_parent' doesn't exist (in this file or the system) — skipped.";
                    continue;
                }
                // The intended parent must not itself be a child (no 3-level
                // nesting) — including a parent link defined elsewhere in this
                // same CSV batch.
                if (!empty($prow['parent_sid']) || isset($csv_parent_links[$wanted_parent])) {
                    $results['errors'][] = "SID $child_sid: '$wanted_parent' is itself a child — can't nest 2 levels deep — skipped.";
                    continue;
                }
                $cchk = $pdo->prepare("SELECT is_parent FROM project_settings WHERE survey_id=?");
                $cchk->execute([$child_sid]);
                $crow = $cchk->fetch();
                if ($crow && !empty($crow['is_parent'])) {
                    $hasKids = $pdo->prepare("SELECT 1 FROM project_settings WHERE parent_sid=? LIMIT 1");
                    $hasKids->execute([$child_sid]);
                    if ($hasKids->fetchColumn()) {
                        $results['errors'][] = "SID $child_sid: already has its own children — can't also become a child — skipped.";
                        continue;
                    }
                }
                $pdo->prepare("UPDATE project_settings SET parent_sid=?, is_parent=0 WHERE survey_id=?")->execute([$wanted_parent, $child_sid]);
                if (empty($prow['is_parent'])) {
                    $pdo->prepare("UPDATE project_settings SET is_parent=1 WHERE survey_id=?")->execute([$wanted_parent]);
                }
            }

            exz_log_audit_local($pdo, 'bulk_import_projects', "Created: {$results['created']}, Updated: {$results['updated']}, Errors: " . count($results['errors']));
        }
    }
    $_SESSION['bulk_import_results'] = $results;
    header('Location: index.php?bulk_import_done=1#projects'); exit;
}
if (isset($_GET['toggle_project'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $sid = trim($_GET['toggle_project']);
    $cur = $pdo->prepare("SELECT status FROM project_settings WHERE survey_id=?"); $cur->execute([$sid]);
    $now = $cur->fetchColumn();
    $next = ($now === 'active') ? 'paused' : 'active';
    $pdo->prepare("UPDATE project_settings SET status=? WHERE survey_id=?")->execute([$next,$sid]);
    header('Location: index.php#projects'); exit;
}
if (isset($_GET['pin_project'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("UPDATE project_settings SET is_pinned=IF(is_pinned=1,0,1) WHERE survey_id=?")->execute([trim($_GET['pin_project'])]);
    header('Location: index.php#projects'); exit;
}
if (isset($_POST['set_project_color'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("UPDATE project_settings SET color_tag=? WHERE survey_id=?")
        ->execute([trim($_POST['color_tag'] ?? ''), trim($_POST['pc_sid'] ?? '')]);
    header('Location: index.php#projects'); exit;
}
if (isset($_GET['duplicate_project'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $orig = trim($_GET['duplicate_project']);
    $row = $pdo->prepare("SELECT * FROM project_settings WHERE survey_id=?"); $row->execute([$orig]);
    $p = $row->fetch();
    if ($p) {
        $newSid = $orig.'_COPY'.rand(100,999);
        $pdo->prepare("INSERT INTO project_settings (survey_id,project_name,client_id,cpi,vendor_cost,target,project_type,status)
            VALUES (?,?,?,?,?,?,?,'active')")
            ->execute([$newSid,$p['project_name'].' (Copy)',$p['client_id'],$p['cpi'],$p['vendor_cost'],$p['target'],$p['project_type']]);
        exz_log_audit_local($pdo, 'duplicate_project', "From $orig to $newSid");
    }
    header('Location: index.php#projects'); exit;
}
if (isset($_GET['delete_project'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $sid = trim($_GET['delete_project']);
    $childChk = $pdo->prepare("SELECT COUNT(*) FROM project_settings WHERE parent_sid=?");
    $childChk->execute([$sid]);
    $childCount = (int)$childChk->fetchColumn();
    if ($childCount > 0) {
        header("Location: index.php?msg=".urlencode("'$sid' has $childCount child project(s) attached — reassign or delete them first before deleting this parent.")."#projects"); exit;
    }
    $pdo->prepare("DELETE FROM project_settings WHERE survey_id=?")->execute([$sid]);
    exz_log_audit_local($pdo, 'delete_project', "SID: $sid");
    header('Location: index.php#projects'); exit;
}
if (isset($_POST['bulk_delete_projects'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $sids = array_filter(array_map('trim', explode(',', $_POST['project_sids'] ?? '')));
    if ($sids) {
        // Skip any SID that still has children attached — deleting a parent
        // out from under its children would leave them pointing at a
        // parent_sid that no longer exists (a silent orphan).
        $blocked = [];
        $deletable = [];
        foreach ($sids as $s) {
            $cc = $pdo->prepare("SELECT COUNT(*) FROM project_settings WHERE parent_sid=?");
            $cc->execute([$s]);
            if ((int)$cc->fetchColumn() > 0) { $blocked[] = $s; } else { $deletable[] = $s; }
        }
        if ($deletable) {
            $in = implode(',', array_fill(0, count($deletable), '?'));
            $pdo->prepare("DELETE FROM project_settings WHERE survey_id IN ($in)")->execute($deletable);
            exz_log_audit_local($pdo, 'bulk_delete_projects', count($deletable)." project(s): ".implode(',', $deletable));
        }
        if ($blocked) {
            header("Location: index.php?msg=".urlencode(count($deletable)." deleted. Skipped (has children — reassign/delete children first): ".implode(', ', $blocked))."#projects"); exit;
        }
    }
    header('Location: index.php#projects'); exit;
}
if (isset($_POST['save_project_note'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("UPDATE project_settings SET notes=? WHERE survey_id=?")
        ->execute([trim($_POST['pn_text'] ?? ''), trim($_POST['pn_sid'] ?? '')]);
    header('Location: index.php#projects'); exit;
}

// ── CLIENTS (master data, separate from portal login accounts) ─
if (isset($_POST['save_master_client'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    exz_ensure_client_extra_columns($pdo);
    try {
        $pdo->exec("ALTER TABLE exz_clients ADD COLUMN s2s_outbound_enabled TINYINT(1) DEFAULT 0");
        $pdo->exec("ALTER TABLE exz_clients ADD COLUMN s2s_outbound_endpoint VARCHAR(500) DEFAULT NULL");
        $pdo->exec("ALTER TABLE exz_clients ADD COLUMN s2s_outbound_token VARCHAR(200) DEFAULT NULL");
    } catch (PDOException $e) {}
    $cid   = intval($_POST['mc_id'] ?? 0);
    $name  = trim($_POST['mc_name']  ?? '');
    $cp    = trim($_POST['mc_contact']?? '');
    $email = trim($_POST['mc_email'] ?? '');
    $phone = trim($_POST['mc_phone'] ?? '');
    $status= ($_POST['mc_status'] ?? 'active') === 'inactive' ? 'inactive' : 'active';
    $s2s_enabled = isset($_POST['mc_s2s_enabled']) ? 1 : 0;
    $s2s_endpoint = trim($_POST['mc_s2s_endpoint'] ?? '');
    $s2s_token = trim($_POST['mc_s2s_token'] ?? '');
    if ($name) {
        if ($cid) {
            $pdo->prepare("UPDATE exz_clients SET client_name=?,contact_person=?,email=?,phone=?,status=?,s2s_outbound_enabled=?,s2s_outbound_endpoint=?,s2s_outbound_token=? WHERE id=?")
                ->execute([$name,$cp,$email,$phone,$status,$s2s_enabled,$s2s_endpoint,$s2s_token,$cid]);
        } else {
            $newClientUid = exz_generate_client_uid($pdo);
            $pdo->prepare("INSERT INTO exz_clients (client_name,contact_person,email,phone,status,client_uid,s2s_outbound_enabled,s2s_outbound_endpoint,s2s_outbound_token) VALUES (?,?,?,?,?,?,?,?,?)")
                ->execute([$name,$cp,$email,$phone,$status,$newClientUid,$s2s_enabled,$s2s_endpoint,$s2s_token]);
        }
    }
    header('Location: index.php#clientsmaster'); exit;
}
if (isset($_GET['del_master_client'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $id = intval($_GET['del_master_client']);
    $pdo->prepare("DELETE FROM exz_clients WHERE id=?")->execute([$id]);
    exz_log_audit_local($pdo, 'delete_client', "Client ID: $id");
    header('Location: index.php#clientsmaster'); exit;
}
if (isset($_POST['bulk_delete_clients'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $ids = array_filter(array_map('intval', explode(',', $_POST['client_ids'] ?? '')));
    if ($ids) {
        $in = implode(',', array_fill(0, count($ids), '?'));
        $pdo->prepare("DELETE FROM exz_clients WHERE id IN ($in)")->execute($ids);
        exz_log_audit_local($pdo, 'bulk_delete_clients', count($ids)." client(s): ".implode(',', $ids));
    }
    header('Location: index.php#clientsmaster'); exit;
}

// ── VENDORS (master data + project assignment) ─────────────────
if (isset($_POST['save_vendor'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    exz_ensure_vendor_extra_columns($pdo);
    $vid   = intval($_POST['v_id'] ?? 0);
    $name  = trim($_POST['v_name']  ?? '');
    $cp    = trim($_POST['v_contact']?? '');
    $email = trim($_POST['v_email'] ?? '');
    $phone = trim($_POST['v_phone'] ?? '');
    $curl  = trim($_POST['v_complete_url'] ?? '');
    $turl  = trim($_POST['v_terminate_url'] ?? '');
    $surl  = trim($_POST['v_screenout_url'] ?? '');
    $qurl  = trim($_POST['v_quotafull_url'] ?? '');
    $beh   = ($_POST['v_end_behavior'] ?? 'show_page') === 'redirect' ? 'redirect' : 'show_page';
    $status= ($_POST['v_status'] ?? 'active') === 'inactive' ? 'inactive' : 'active';
    $panelsize = $_POST['v_panel_size'] !== '' ? intval($_POST['v_panel_size']) : null;
    $availstatus = ($_POST['v_availability'] ?? 'open') === 'closed' ? 'closed' : 'open';
    if ($name) {
        if ($vid) {
            $pdo->prepare("UPDATE exz_vendors SET vendor_name=?,contact_person=?,email=?,phone=?,complete_url=?,terminate_url=?,screenout_url=?,quotafull_url=?,end_behavior=?,status=?,panel_size=?,availability_status=? WHERE id=?")
                ->execute([$name,$cp,$email,$phone,$curl,$turl,$surl,$qurl,$beh,$status,$panelsize,$availstatus,$vid]);
        } else {
            $pdo->prepare("INSERT INTO exz_vendors (vendor_name,contact_person,email,phone,complete_url,terminate_url,screenout_url,quotafull_url,end_behavior,status,panel_size,availability_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
                ->execute([$name,$cp,$email,$phone,$curl,$turl,$surl,$qurl,$beh,$status,$panelsize,$availstatus]);
        }
    }
    header('Location: index.php#vendors'); exit;
}
if (isset($_GET['toggle_vendor'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $id = intval($_GET['toggle_vendor']);
    $cur = $pdo->prepare("SELECT status FROM exz_vendors WHERE id=?");
    $cur->execute([$id]);
    $curStatus = $cur->fetchColumn();
    $newStatus = ($curStatus === 'inactive') ? 'active' : 'inactive';
    $pdo->prepare("UPDATE exz_vendors SET status=? WHERE id=?")->execute([$newStatus, $id]);
    header('Location: index.php#vendors'); exit;
}
if (isset($_GET['del_vendor'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $id = intval($_GET['del_vendor']);
    $pdo->prepare("DELETE FROM exz_vendors WHERE id=?")->execute([$id]);
    $pdo->prepare("DELETE FROM exz_project_vendors WHERE vendor_id=?")->execute([$id]);
    exz_log_audit_local($pdo, 'delete_vendor', "Vendor ID: $id");
    header('Location: index.php#vendors'); exit;
}
if (isset($_POST['bulk_delete_vendors'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $ids = array_filter(array_map('intval', explode(',', $_POST['vendor_ids'] ?? '')));
    if ($ids) {
        $in = implode(',', array_fill(0, count($ids), '?'));
        $pdo->prepare("DELETE FROM exz_vendors WHERE id IN ($in)")->execute($ids);
        $pdo->prepare("DELETE FROM exz_project_vendors WHERE vendor_id IN ($in)")->execute($ids);
        exz_log_audit_local($pdo, 'bulk_delete_vendors', count($ids)." vendor(s): ".implode(',', $ids));
    }
    header('Location: index.php#vendors'); exit;
}
// ── BLOCKED IP LIST — add/unblock handlers ──────────────────
// ── QUESTION LIBRARY — add/edit/delete handlers ──────────────
if (isset($_POST['save_question'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    exz_ensure_question_library_tables($pdo);
    $qid = intval($_POST['q_id'] ?? 0);
    $data = [
        trim($_POST['q_country'] ?? ''),
        trim($_POST['q_language'] ?? ''),
        trim($_POST['q_control_type'] ?? 'text'),
        trim($_POST['q_title'] ?? ''),
        trim($_POST['q_text'] ?? ''),
        $_POST['q_min_length'] !== '' ? intval($_POST['q_min_length']) : null,
        $_POST['q_max_length'] !== '' ? intval($_POST['q_max_length']) : null,
        trim($_POST['q_text_type'] ?? ''),
        trim($_POST['q_options'] ?? ''), // comma-separated from the form, stored as-is (JSON-ish simple list)
    ];
    if ($data[3] && $data[4]) { // title + question text required
        if ($qid) {
            $pdo->prepare("UPDATE exz_question_library SET country=?,language=?,control_type=?,title=?,question_text=?,min_length=?,max_length=?,text_type=?,options=? WHERE id=?")
                ->execute(array_merge($data, [$qid]));
        } else {
            $pdo->prepare("INSERT INTO exz_question_library (country,language,control_type,title,question_text,min_length,max_length,text_type,options) VALUES (?,?,?,?,?,?,?,?,?)")
                ->execute($data);
        }
    }
    header('Location: index.php#questionlibrary'); exit;
}
if (isset($_GET['delete_question'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("DELETE FROM exz_question_library WHERE id=?")->execute([intval($_GET['delete_question'])]);
    $pdo->prepare("DELETE FROM exz_prescreen_template_questions WHERE question_id=?")->execute([intval($_GET['delete_question'])]);
    header('Location: index.php#questionlibrary'); exit;
}

// ── PRESCREEN TEMPLATES — add/delete + attach/detach questions ──
if (isset($_POST['save_template'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    exz_ensure_question_library_tables($pdo);
    $tname = trim($_POST['t_name'] ?? '');
    if ($tname) {
        $pdo->prepare("INSERT INTO exz_prescreen_templates (template_name) VALUES (?)")->execute([$tname]);
    }
    header('Location: index.php#prescreentemplates'); exit;
}
if (isset($_GET['delete_template'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $tid = intval($_GET['delete_template']);
    $pdo->prepare("DELETE FROM exz_prescreen_templates WHERE id=?")->execute([$tid]);
    $pdo->prepare("DELETE FROM exz_prescreen_template_questions WHERE template_id=?")->execute([$tid]);
    header('Location: index.php#prescreentemplates'); exit;
}
if (isset($_POST['attach_question'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $tid = intval($_POST['at_template_id'] ?? 0);
    $qid = intval($_POST['at_question_id'] ?? 0);
    if ($tid && $qid) {
        $chk = $pdo->prepare("SELECT id FROM exz_prescreen_template_questions WHERE template_id=? AND question_id=?");
        $chk->execute([$tid, $qid]);
        if (!$chk->fetchColumn()) {
            $maxOrd = $pdo->prepare("SELECT COALESCE(MAX(sort_order),0)+1 FROM exz_prescreen_template_questions WHERE template_id=?");
            $maxOrd->execute([$tid]);
            $pdo->prepare("INSERT INTO exz_prescreen_template_questions (template_id, question_id, sort_order) VALUES (?,?,?)")
                ->execute([$tid, $qid, $maxOrd->fetchColumn()]);
        }
    }
    header("Location: index.php?edit_template=$tid#prescreentemplates"); exit;
}
if (isset($_GET['detach_question'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $tid = intval($_GET['tid'] ?? 0);
    $pdo->prepare("DELETE FROM exz_prescreen_template_questions WHERE id=?")->execute([intval($_GET['detach_question'])]);
    header("Location: index.php?edit_template=$tid#prescreentemplates"); exit;
}

if (isset($_POST['add_blocked_ip'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    exz_ensure_blocked_ips_table($pdo);
    $bip = trim($_POST['bip_ip'] ?? '');
    $bcm = trim($_POST['bip_comment'] ?? '');
    if ($bip) {
        try {
            $pdo->prepare("INSERT IGNORE INTO exz_blocked_ips (ip, comment, blocked_by) VALUES (?,?,?)")
                ->execute([$bip, $bcm, $_SESSION['ex_team_name'] ?? 'Admin']);
        } catch (Exception $e) {}
    }
    header('Location: index.php#blockedips'); exit;
}
if (isset($_GET['unblock_ip'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("DELETE FROM exz_blocked_ips WHERE id=?")->execute([intval($_GET['unblock_ip'])]);
    header('Location: index.php#blockedips'); exit;
}

if (isset($_POST['assign_vendor'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    exz_ensure_short_code_column($pdo);
    $sid = trim($_POST['av_sid'] ?? '');
    $vid = intval($_POST['av_vendor'] ?? 0);
    if ($sid && $vid) {
        try {
            $newShortCode = exz_generate_short_code($pdo);
            $pdo->prepare("INSERT IGNORE INTO exz_project_vendors (survey_id,vendor_id,short_code) VALUES (?,?,?)")->execute([$sid,$vid,$newShortCode]);
        } catch(Exception $e){}
    }
    header('Location: index.php#projects'); exit;
}
if (isset($_GET['unassign_vendor'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("DELETE FROM exz_project_vendors WHERE survey_id=? AND vendor_id=?")
        ->execute([trim($_GET['sid'] ?? ''), intval($_GET['unassign_vendor'])]);
    header('Location: index.php#projects'); exit;
}

// ── TEAM MANAGEMENT ────────────────────────────────────────────
if (isset($_POST['save_team_member'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    $tid   = intval($_POST['tm_id'] ?? 0);
    $name  = trim($_POST['tm_name']  ?? '');
    $email = trim($_POST['tm_email'] ?? '');
    $pass  = trim($_POST['tm_password'] ?? '');
    $role  = in_array($_POST['tm_role'] ?? '', ['superadmin','manager','viewer']) ? $_POST['tm_role'] : 'viewer';
    if ($name && $email) {
        if ($tid) {
            if ($pass) {
                $pdo->prepare("UPDATE exz_team SET name=?,email=?,role=?,password_hash=? WHERE id=?")
                    ->execute([$name,$email,$role,password_hash($pass, PASSWORD_BCRYPT),$tid]);
            } else {
                $pdo->prepare("UPDATE exz_team SET name=?,email=?,role=? WHERE id=?")->execute([$name,$email,$role,$tid]);
            }
        } else {
            $hash = $pass ? password_hash($pass, PASSWORD_BCRYPT) : null;
            $pdo->prepare("INSERT INTO exz_team (name,email,password_hash,role) VALUES (?,?,?,?)")->execute([$name,$email,$hash,$role]);
        }
    }
    header('Location: index.php#team'); exit;
}
// ── BILLING: save invoice status per project ────────────────────
if (isset($_POST['save_invoice_status'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $bill_sid = trim($_POST['bi_sid'] ?? '');
    $bill_status = in_array($_POST['bi_status'] ?? '', ['unpaid','invoiced','paid']) ? $_POST['bi_status'] : 'unpaid';
    $bill_invno = trim($_POST['bi_invoice_no'] ?? '');
    $bill_notes = trim($_POST['bi_notes'] ?? '');
    $pdo->prepare("INSERT INTO exz_invoice_status (survey_id,status,invoice_no,notes) VALUES (?,?,?,?)
        ON DUPLICATE KEY UPDATE status=VALUES(status),invoice_no=VALUES(invoice_no),notes=VALUES(notes)")
        ->execute([$bill_sid, $bill_status, $bill_invno, $bill_notes]);
    exz_log_audit_local($pdo, 'update_invoice_status', "SID: $bill_sid -> $bill_status");
    header('Location: index.php#billing'); exit;
}

// ── ALERT SETTINGS: save Telegram/Email config ─────────────────
if (isset($_POST['save_alert_settings'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    $tok  = trim($_POST['as_tg_token'] ?? '');
    $chat = trim($_POST['as_tg_chat']  ?? '');
    $email= trim($_POST['as_email']    ?? '');
    $save = function($key, $val) use ($pdo) {
        $pdo->prepare("INSERT INTO exz_settings (setting_key,setting_value) VALUES (?,?)
                       ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)")->execute([$key, $val]);
    };
    $save('telegram_bot_token', $tok);
    $save('telegram_chat_id', $chat);
    $save('alert_email', $email);
    exz_log_audit_local($pdo, 'save_alert_settings', 'Alert Settings updated');
    header('Location: index.php?msg='.urlencode('Settings saved').'#alerts'); exit;
}
// ── STATUS SYNONYM MAPPING — add/remove ─────────────────────────
if (isset($_POST['add_status_synonym'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    exz_ensure_status_synonyms_table($pdo);
    exz_seed_default_status_synonyms($pdo);
    $syn = strtolower(trim($_POST['syn_word'] ?? ''));
    $target = trim($_POST['syn_target'] ?? '');
    $scope_sid = trim($_POST['syn_sid'] ?? '') ?: null; // blank = global default
    $valid_targets = ['complete','terminate','qc','quality','quotafull'];
    if ($syn && in_array($target, $valid_targets)) {
        try {
            $pdo->prepare("INSERT INTO exz_status_synonyms (survey_id, synonym, maps_to) VALUES (?,?,?)
                ON DUPLICATE KEY UPDATE maps_to=VALUES(maps_to)")
                ->execute([$scope_sid, $syn, $target]);
            exz_log_audit_local($pdo, 'add_status_synonym', "$syn -> $target (".($scope_sid ?: 'global').")");
        } catch (Exception $e) {
            header('Location: index.php?msg='.urlencode('Could not save — that word may already be mapped for this scope.').'#alerts'); exit;
        }
    }
    header('Location: index.php#alerts'); exit;
}
if (isset($_GET['del_status_synonym'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("DELETE FROM exz_status_synonyms WHERE id=?")->execute([intval($_GET['del_status_synonym'])]);
    header('Location: index.php#alerts'); exit;
}
function exz_audit_actor(): string {
    // Who's actually logged in and performing this action right now — falls
    // back to a clear label for cron/automation contexts where there's no
    // logged-in team session at all (e.g. cron_client_reports.php).
    return $_SESSION['ex_team_name'] ?? 'System (Automated)';
}
function exz_log_audit_local($pdo, $action, $detail) {
    try { $pdo->prepare("INSERT INTO exz_audit_log (action,detail,performed_by) VALUES (?,?,?)")->execute([$action,$detail,exz_audit_actor()]); } catch(Exception $e){}
}
// ── SHARED EXPORT ROWS — real responses + Pending/Click Only entries ────
// Used by CSV, JSON, and Excel export so all three formats show identical
// data. $estat: empty = everything; a real status (complete/terminate/qc/
// quality/quotafull/unmatched) = only survey_responses rows with that exact
// status; 'pending' or 'click_only' = only the synthetic orphaned-entry rows
// (survey_starts with no matching completion), so a person filtering
// specifically for "just show me the ones with no signal back yet" can
// export just that subset instead of it only being visible on-screen.
function exz_get_export_rows(PDO $pdo, array $filters): array {
    $rows = [];
    $real_statuses = ['complete','terminate','qc','quality','quotafull','unmatched'];
    $want_real = empty($filters['estat']) || in_array($filters['estat'], $real_statuses);
    $want_synthetic = empty($filters['estat']) || in_array($filters['estat'], ['pending','click_only']);

    if ($want_real) {
        $where = '1=1'; $params = [];
        if (!empty($filters['esid']))  { $where .= ' AND sr.survey_id=?'; $params[] = $filters['esid']; }
        if (!empty($filters['estat']) && in_array($filters['estat'], $real_statuses)) { $where .= ' AND sr.status=?'; $params[] = $filters['estat']; }
        if (!empty($filters['esrc']))  { $where .= ' AND sr.source=?';    $params[] = $filters['esrc']; }
        if (!empty($filters['evid']))  { $where .= ' AND sr.vendor_id=?'; $params[] = $filters['evid']; }
        if (!empty($filters['edatefrom'])) { $where .= ' AND DATE(sr.created_at) >= ?'; $params[] = $filters['edatefrom']; }
        if (!empty($filters['edateto']))   { $where .= ' AND DATE(sr.created_at) <= ?'; $params[] = $filters['edateto']; }
        $stmt = $pdo->prepare("SELECT sr.survey_id,sr.respondent,v.vendor_name,sr.status,sr.source,sr.client_name,sr.ip,sr.device,sr.country,sr.city,sr.loi_seconds,sr.is_duplicate,sr.created_at
            FROM survey_responses sr LEFT JOIN exz_vendors v ON v.id = sr.vendor_id
            WHERE $where ORDER BY sr.created_at DESC");
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
    }
    if ($want_synthetic) {
        try {
            $swhere = 'sr.id IS NULL'; $sparams = [];
            if (!empty($filters['esid'])) { $swhere .= ' AND ss.sid=?'; $sparams[] = $filters['esid']; }
            if (!empty($filters['evid'])) { $swhere .= ' AND ss.vendor_id=?'; $sparams[] = $filters['evid']; }
            if (!empty($filters['edatefrom'])) { $swhere .= ' AND DATE(ss.start_time) >= ?'; $sparams[] = $filters['edatefrom']; }
            if (!empty($filters['edateto']))   { $swhere .= ' AND DATE(ss.start_time) <= ?'; $sparams[] = $filters['edateto']; }
            $oe = $pdo->prepare("SELECT ss.sid AS survey_id, ss.uid AS respondent, v.vendor_name, ss.source, ss.ip, ss.device, ss.country, ss.city, ss.start_time AS created_at,
                    ps.project_type, c.client_name
                FROM survey_starts ss
                LEFT JOIN survey_responses sr ON sr.survey_id = ss.sid AND sr.respondent = ss.uid
                LEFT JOIN project_settings ps ON ps.survey_id = ss.sid
                LEFT JOIN exz_clients c ON c.id = ps.client_id
                LEFT JOIN exz_vendors v ON v.id = ss.vendor_id
                WHERE $swhere ORDER BY ss.start_time DESC");
            $oe->execute($sparams);
            foreach ($oe->fetchAll() as $orow) {
                $orow['status'] = (($orow['project_type'] ?? 'direct') === 'tp') ? 'click_only' : 'pending';
                if (!empty($filters['estat']) && $filters['estat'] !== $orow['status']) continue;
                // device/country/city now come straight from survey_starts
                // (captured at entry time — see vendor.php) instead of being
                // hardcoded blank. LOI genuinely can't exist without a
                // completion timestamp, so that one stays null.
                $orow['loi_seconds'] = null; $orow['is_duplicate'] = 0;
                unset($orow['project_type']);
                $rows[] = $orow;
            }
        } catch (Exception $e) {}
    }
    usort($rows, fn($a,$b) => strcmp($b['created_at'] ?? '', $a['created_at'] ?? ''));
    return $rows;
}
// ── Minimal, dependency-free XLSX writer ─────────────────────────
// Builds a valid single-sheet .xlsx from a header row + data rows using only
// PHP's built-in ZipArchive (no PhpSpreadsheet/Composer needed). Every cell
// is written as an inline string, which keeps this simple and avoids the
// shared-strings-table bookkeeping a "proper" writer needs — perfectly fine
// for the row/column counts this dashboard ever exports.
function exz_array_to_xlsx(array $headers, array $rows): string {
    $esc = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_XML1, 'UTF-8');
    $colLetter = function(int $n): string {
        $s = '';
        while ($n >= 0) { $s = chr($n % 26 + 65) . $s; $n = intdiv($n, 26) - 1; }
        return $s;
    };
    $sheetRows = '';
    $rIdx = 1;
    $cells = [];
    foreach ($headers as $ci => $h) $cells[] = '<c r="'.$colLetter($ci).$rIdx.'" t="inlineStr"><is><t>'.$esc($h).'</t></is></c>';
    $sheetRows .= '<row r="'.$rIdx.'">'.implode('', $cells).'</row>';
    foreach ($rows as $row) {
        $rIdx++;
        $cells = [];
        $ci = 0;
        foreach ($row as $val) {
            $cells[] = '<c r="'.$colLetter($ci).$rIdx.'" t="inlineStr"><is><t>'.$esc($val ?? '').'</t></is></c>';
            $ci++;
        }
        $sheetRows .= '<row r="'.$rIdx.'">'.implode('', $cells).'</row>';
    }
    $sheetXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        .'<sheetData>'.$sheetRows.'</sheetData></worksheet>';

    $contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        .'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        .'<Default Extension="xml" ContentType="application/xml"/>'
        .'<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        .'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        .'</Types>';
    $rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        .'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        .'</Relationships>';
    $workbookXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        .'<sheets><sheet name="Export" sheetId="1" r:id="rId1"/></sheets></workbook>';
    $workbookRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        .'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        .'</Relationships>';

    $tmpFile = tempnam(sys_get_temp_dir(), 'xlsx');
    $zip = new ZipArchive();
    $zip->open($tmpFile, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    $zip->addFromString('[Content_Types].xml', $contentTypes);
    $zip->addFromString('_rels/.rels', $rootRels);
    $zip->addFromString('xl/workbook.xml', $workbookXml);
    $zip->addFromString('xl/_rels/workbook.xml.rels', $workbookRels);
    $zip->addFromString('xl/worksheets/sheet1.xml', $sheetXml);
    $zip->close();
    $bytes = file_get_contents($tmpFile);
    unlink($tmpFile);
    return $bytes;
}
function exz_noperm_redirect() {
    $ret = preg_replace('/[^a-z0-9]/i', '', $_REQUEST['ret_tab'] ?? '');
    header('Location: index.php?err=noperm' . ($ret ? '#'.$ret : ''));
}

// ── AUDIT LOG: delete single / clear all ───────────────────────
if (isset($_GET['del_audit'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("DELETE FROM exz_audit_log WHERE id=?")->execute([intval($_GET['del_audit'])]);
    header('Location: index.php#auditlog'); exit;
}
if (isset($_GET['clear_audit'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->exec("TRUNCATE TABLE exz_audit_log");
    header('Location: index.php#auditlog'); exit;
}

if (isset($_GET['toggle_team'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("UPDATE exz_team SET is_active=IF(is_active=1,0,1) WHERE id=?")->execute([intval($_GET['toggle_team'])]);
    header('Location: index.php#team'); exit;
}
if (isset($_GET['del_team'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $id = intval($_GET['del_team']);
    $pdo->prepare("DELETE FROM exz_team WHERE id=?")->execute([$id]);
    exz_log_audit_local($pdo, 'delete_team_member', "Team ID: $id");
    header('Location: index.php#team'); exit;
}

// ── CLIENT PORTAL MANAGEMENT ──────────────────────────────────
if (isset($_POST['add_client'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB(); ensureTables($pdo);
    $cl_user = trim($_POST['cl_username'] ?? '');
    $cl_pass = trim($_POST['cl_password'] ?? '');
    $cl_masterid = intval($_POST['cl_masterid'] ?? 0) ?: null;
    $cl_proj = trim($_POST['cl_projects'] ?? ''); // optional manual extra SIDs, comma-separated
    // Client name is pulled from the linked master Client record (single source of truth)
    $cl_name = 'Client';
    if ($cl_masterid) {
        $mc = $pdo->prepare("SELECT client_name FROM exz_clients WHERE id=?"); $mc->execute([$cl_masterid]);
        $cl_name = $mc->fetchColumn() ?: 'Client';
    }
    if ($cl_user && $cl_pass && $cl_masterid) {
        try {
            $hash = password_hash($cl_pass, PASSWORD_BCRYPT);
            $pdo->prepare("INSERT INTO portal_clients (username,password_hash,client_name,client_id,allowed_projects)
                VALUES (?,?,?,?,?)
                ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash),
                client_name=VALUES(client_name), client_id=VALUES(client_id), allowed_projects=VALUES(allowed_projects)")
                ->execute([$cl_user, $hash, $cl_name, $cl_masterid, $cl_proj]);
        } catch(Exception $e){ error_log("Add client: ".$e->getMessage()); }
    }
    header('Location: index.php#clients'); exit;
}
if (isset($_GET['toggle_client'])) {
    if (!exz_is_manager()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $pdo->prepare("UPDATE portal_clients SET is_active=IF(is_active=1,0,1) WHERE id=?")
        ->execute([intval($_GET['toggle_client'])]);
    header('Location: index.php#clients'); exit;
}
if (isset($_GET['del_client'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    getDB()->prepare("DELETE FROM portal_clients WHERE id=?")->execute([intval($_GET['del_client'])]);
    header('Location: index.php#clients'); exit;
}

// ── DELETE RESPONSES ──────────────────────────────────────────
if (isset($_POST['delete_responses'])) {
    if (!exz_is_superadmin()) { exz_noperm_redirect(); exit; }
    $pdo = getDB();
    $ids = $_POST['del_ids'] ?? [];
    if (!empty($ids)) {
        // Two kinds of selections can arrive together in one bulk-delete:
        // real survey_responses rows (plain numeric id), and Pending/Click
        // Only entries (no survey_responses row exists yet — these are
        // "start:<sid>:<uid>" markers instead, deleted from survey_starts
        // by matching sid+uid, since they have no id of their own).
        $real_ids = [];
        $starts_to_delete = []; // [sid, uid] pairs
        foreach ($ids as $val) {
            if (is_string($val) && str_starts_with($val, 'start:')) {
                $parts = explode(':', $val, 3);
                if (count($parts) === 3) $starts_to_delete[] = [$parts[1], $parts[2]];
            } elseif (ctype_digit((string)$val)) {
                $real_ids[] = (int)$val;
            }
        }
        if (!empty($real_ids)) {
            $placeholders = implode(',', array_fill(0, count($real_ids), '?'));
            $pdo->prepare("DELETE FROM survey_responses WHERE id IN ($placeholders)")->execute($real_ids);
        }
        if (!empty($starts_to_delete)) {
            $stmt = $pdo->prepare("DELETE FROM survey_starts WHERE sid=? AND uid=?");
            foreach ($starts_to_delete as [$sid, $uid]) { $stmt->execute([$sid, $uid]); }
        }
        exz_log_audit_local($pdo, 'delete_responses', count($real_ids)." response(s), ".count($starts_to_delete)." pending/click-only entr".(count($starts_to_delete)===1?'y':'ies'));
    }
    header('Location: index.php#responses'); exit;
}

// ── DAILY REPORT ──────────────────────────────────────────────
if (isset($_GET['send_report'])) {
    $pdo = getDB();
    $ts = $pdo->query("SELECT
        SUM(status='complete') as c, SUM(status='terminate') as t,
        SUM(status='quotafull') as q,
        SUM(status='qc' OR status='quality') as ql,
        COUNT(*) as total
        FROM survey_responses WHERE DATE(created_at)=CURDATE() AND no_entry_record=0")->fetch();
    $ir_t = ($ts['c']+$ts['t'])>0 ? round($ts['c']/($ts['c']+$ts['t'])*100,1) : 0;
    $msg  = "📊 Exazon Daily — ".date('d M Y')."\n✅ Complete: {$ts['c']}\n❌ Terminate: {$ts['t']}\n📋 QF: {$ts['q']}\n⚑ QC: {$ts['ql']}\n📈 IR: {$ir_t}%";
    sendWhatsApp($msg);
    sendEmail("Exazon Daily Report — ".date('d M Y'),
        "<h2>Daily Report</h2><p>✅ {$ts['c']} Completes</p><p>❌ {$ts['t']} Terminates</p><p>📋 {$ts['q']} Quota Full</p><p>⚑ {$ts['ql']} Quality Fail</p><p>📈 IR: {$ir_t}%</p>");
    header('Location: index.php?report_sent=1'.(isset($_GET['ret']) ? '#'.preg_replace('/[^a-z0-9]/i','',$_GET['ret']) : '')); exit;
}

// ── LOAD ALL DATA ─────────────────────────────────────────────
$pdo = getDB();
ensureTables($pdo);

// Overall stats — FIX: handle both 'qc' and 'quality', loi_seconds NULL safe
// Ghost entries (no_entry_record=1) excluded throughout Overview — a completion
// with no real entry-link record isn't a genuine response, so it shouldn't
// count toward Total/Completes/IR/LOI/etc, matching how it's already excluded
// from quota checks and vendor postbacks in pages/track.php.
$stats = $pdo->query("SELECT
    COUNT(*) as total,
    SUM(status='complete')  as completes,
    SUM(status='terminate') as terminates,
    SUM(status='quotafull') as quotafull,
    SUM(status='qc' OR status='quality') as quality,
    SUM(is_duplicate=1)     as duplicates,
    COUNT(DISTINCT survey_id) as projects,
    ROUND(AVG(CASE WHEN status='complete' AND loi_seconds IS NOT NULL AND loi_seconds>0 THEN loi_seconds END)) as avg_loi,
    MIN(CASE WHEN status='complete' AND loi_seconds IS NOT NULL AND loi_seconds>0 THEN loi_seconds END) as min_loi,
    SUM(CASE WHEN loi_seconds IS NOT NULL AND loi_seconds>0 AND loi_seconds<".SPEEDER_THRESHOLD." THEN 1 ELSE 0 END) as speeders,
    SUM(CASE WHEN source='direct'     THEN 1 ELSE 0 END) as direct_count,
    SUM(CASE WHEN source='thirdparty' THEN 1 ELSE 0 END) as tp_count
FROM survey_responses WHERE no_entry_record=0")->fetch();

// Median LOI — PHP side (safe, no subquery crash)
try {
    $loi_vals = $pdo->query("SELECT loi_seconds FROM survey_responses WHERE status='complete' AND loi_seconds IS NOT NULL AND loi_seconds>0 AND no_entry_record=0 ORDER BY loi_seconds")->fetchAll(PDO::FETCH_COLUMN);
    $cnt = count($loi_vals);
    $stats['median_loi'] = $cnt > 0 ? $loi_vals[intdiv($cnt,2)] : 0;
} catch(Exception $e){ $stats['median_loi'] = 0; }

// Today's stats
$today = $pdo->query("SELECT
    COUNT(*) as total,
    SUM(status='complete')  as completes,
    SUM(status='terminate') as terminates,
    SUM(status='quotafull') as quotafull,
    SUM(status='qc' OR status='quality') as quality
FROM survey_responses WHERE DATE(created_at)=CURDATE() AND no_entry_record=0")->fetch();

// Partials: entered (survey_starts) but never completed/terminated
$partials = 0;
try {
    $entered  = $pdo->query("SELECT COUNT(DISTINCT uid) FROM survey_starts")->fetchColumn();
    $finished = $pdo->query("SELECT COUNT(DISTINCT respondent) FROM survey_responses WHERE no_entry_record=0")->fetchColumn();
    $partials = max(0, intval($entered) - intval($finished));
} catch(Exception $e){ $partials = 0; }

// IR overall
$ir = ($stats['completes'] + $stats['terminates']) > 0
    ? round($stats['completes'] / ($stats['completes'] + $stats['terminates']) * 100, 1) : 0;

// IR Drift — last 50 responses
$ir_drift = null;
$ir_drift_alert = false;
try {
    $last50 = $pdo->query("SELECT status FROM survey_responses WHERE status IN ('complete','terminate') AND no_entry_record=0 ORDER BY created_at DESC LIMIT 50")->fetchAll(PDO::FETCH_COLUMN);
    $l50c = count(array_filter($last50, fn($s) => $s === 'complete'));
    $ir_drift = count($last50) > 0 ? round($l50c / count($last50) * 100, 1) : null;
    if ($ir_drift !== null && $ir_drift < 20 && count($last50) >= 10) {
        $ir_drift_alert = true;
        sendWhatsApp("🚨 IR Drift Alert!\nExazon Dashboard\nLast 50 responses IR: {$ir_drift}%\nBelow 20% threshold — check immediately!");
    }
} catch(Exception $e){}

// Project settings
$proj_settings = [];
try {
    foreach($pdo->query("SELECT * FROM project_settings")->fetchAll() as $ps)
        $proj_settings[$ps['survey_id']] = $ps;
} catch(Exception $e){}

// Projects list
$projects = $pdo->query("SELECT survey_id,
    MAX(client_name) as client_name,
    MAX(source) as source,
    COUNT(*) as total,
    SUM(status='complete')  as completes,
    SUM(status='terminate') as terminates,
    SUM(status='quotafull') as quotafull,
    SUM(status='qc' OR status='quality') as quality,
    SUM(is_duplicate=1) as duplicates,
    SUM(CASE WHEN loi_seconds IS NOT NULL AND loi_seconds>0 AND loi_seconds<".SPEEDER_THRESHOLD." THEN 1 ELSE 0 END) as speeders,
    ROUND(AVG(CASE WHEN status='complete' AND loi_seconds IS NOT NULL AND loi_seconds>0 THEN loi_seconds END)) as avg_loi,
    MIN(created_at) as first_response,
    MAX(created_at) as last_response
FROM survey_responses WHERE no_entry_record=0 GROUP BY survey_id ORDER BY MAX(created_at) DESC")->fetchAll();

// Revenue + Gross Margin
$total_revenue = 0; $total_cost = 0;
foreach($projects as $p) {
    $ps = $proj_settings[$p['survey_id']] ?? null;
    $total_revenue += $p['completes'] * ($ps['cpi'] ?? 0);
    $total_cost    += $p['completes'] * ($ps['vendor_cost'] ?? 0);
}
$gross_margin = $total_revenue - $total_cost;

// EPC — Earnings Per Click
$epc = $stats['total'] > 0 && $total_revenue > 0
    ? round($total_revenue / $stats['total'], 2) : 0;

// Speeders list
$speeders_list = $pdo->query("SELECT survey_id,respondent,status,loi_seconds,ip,country,device,source,created_at
FROM survey_responses WHERE loi_seconds IS NOT NULL AND loi_seconds>0 AND loi_seconds<".SPEEDER_THRESHOLD." AND no_entry_record=0
ORDER BY created_at DESC LIMIT 50")->fetchAll();

// Duplicates list
$dup_rows = $pdo->query("SELECT survey_id,respondent,status,loi_seconds,ip,country,device,source,created_at
FROM survey_responses WHERE is_duplicate=1 AND no_entry_record=0 ORDER BY created_at DESC LIMIT 50")->fetchAll();

// Ghost entries — completions with no matching entry-link record (survey_starts)
try { $pdo->exec("ALTER TABLE survey_responses ADD COLUMN no_entry_record TINYINT(1) DEFAULT 0"); } catch (PDOException $e) {}
$ghost_entries = $pdo->query("SELECT survey_id,respondent,status,loi_seconds,ip,country,device,source,created_at
FROM survey_responses WHERE no_entry_record=1 ORDER BY created_at DESC LIMIT 50")->fetchAll();

// ── Same-IP Fraud Detection ─────────────────────────────────────
// (1) Same IP, multiple different respondents, on ONE project
$ip_same_project = [];
try {
    $ip_same_project = $pdo->query("SELECT ip, survey_id, COUNT(DISTINCT respondent) as uid_count, GROUP_CONCAT(DISTINCT respondent SEPARATOR ', ') as uids
        FROM survey_responses WHERE ip!='' AND ip IS NOT NULL
        GROUP BY ip, survey_id HAVING uid_count > 1 ORDER BY uid_count DESC LIMIT 30")->fetchAll();
} catch(Exception $e){}
// (2) Same IP appearing across MULTIPLE different projects
$ip_cross_project = [];
try {
    $ip_cross_project = $pdo->query("SELECT ip, COUNT(DISTINCT survey_id) as proj_count, GROUP_CONCAT(DISTINCT survey_id SEPARATOR ', ') as sids
        FROM survey_responses WHERE ip!='' AND ip IS NOT NULL
        GROUP BY ip HAVING proj_count > 1 ORDER BY proj_count DESC LIMIT 30")->fetchAll();
} catch(Exception $e){}

// Trend — date-range filterable (defaults to last 7 days)
$trend_from = trim($_GET['trend_from'] ?? '');
$trend_to   = trim($_GET['trend_to']   ?? '');
if ($trend_from && $trend_to) {
    $trend_where = "created_at >= ? AND created_at < DATE_ADD(?, INTERVAL 1 DAY)";
    $trend_params = [$trend_from, $trend_to];
} else {
    $trend_where = "created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
    $trend_params = [];
}
$trend_stmt = $pdo->prepare("SELECT DATE(created_at) as day,
    SUM(status='complete')  as c,
    SUM(status='terminate') as t,
    SUM(status='quotafull') as q,
    SUM(status='qc' OR status='quality') as ql
FROM survey_responses WHERE $trend_where AND no_entry_record=0
GROUP BY DATE(created_at) ORDER BY day ASC");
$trend_stmt->execute($trend_params);
$trend = $trend_stmt->fetchAll();

// Hourly today
$hourly = $pdo->query("SELECT HOUR(created_at) as hr, COUNT(*) as cnt,
    SUM(status='complete') as c
FROM survey_responses WHERE DATE(created_at)=CURDATE() AND no_entry_record=0
GROUP BY HOUR(created_at) ORDER BY hr")->fetchAll();

// Device, source, country
$devices   = $pdo->query("SELECT COALESCE(NULLIF(device,''),'unknown') as device, COUNT(*) as cnt FROM survey_responses WHERE no_entry_record=0 GROUP BY device ORDER BY cnt DESC")->fetchAll();
$sources   = $pdo->query("SELECT COALESCE(NULLIF(source,''),'unknown') as source, COUNT(*) as cnt FROM survey_responses WHERE no_entry_record=0 GROUP BY source ORDER BY cnt DESC LIMIT 10")->fetchAll();
$countries = $pdo->query("SELECT country, COUNT(*) as cnt FROM survey_responses WHERE country!='' AND no_entry_record=0 GROUP BY country ORDER BY cnt DESC LIMIT 10")->fetchAll();

// Vendor scorecard
$vendors = $pdo->query("SELECT source,
    COUNT(*) as total,
    SUM(status='complete')  as completes,
    SUM(status='terminate') as terminates,
    SUM(is_duplicate=1)     as dups,
    SUM(CASE WHEN loi_seconds IS NOT NULL AND loi_seconds>0 AND loi_seconds<".SPEEDER_THRESHOLD." THEN 1 ELSE 0 END) as speeders,
    ROUND(AVG(CASE WHEN status='complete' AND loi_seconds IS NOT NULL AND loi_seconds>0 THEN loi_seconds END)) as avg_loi
FROM survey_responses WHERE source!='' AND no_entry_record=0
GROUP BY source ORDER BY total DESC LIMIT 15")->fetchAll();

// Response log
$tableWhere = '1=1'; $tableParams = [];
if (!empty($_GET['fStatus']))  { $tableWhere .= ' AND sr.status=?';    $tableParams[] = $_GET['fStatus']; }
if (!empty($_GET['fProject'])) { $tableWhere .= ' AND sr.survey_id=?'; $tableParams[] = $_GET['fProject']; }
if (!empty($_GET['fSource']))  { $tableWhere .= ' AND sr.source=?';    $tableParams[] = $_GET['fSource']; }
$stmt = $pdo->prepare("SELECT sr.*, um.original_uid AS original_uid
    FROM survey_responses sr
    LEFT JOIN exz_uid_mapping um ON um.encrypted_uid = sr.respondent AND um.survey_id = sr.survey_id
    WHERE $tableWhere ORDER BY sr.created_at DESC LIMIT 500");
$stmt->execute($tableParams);
$rows = $stmt->fetchAll();

// ── Orphaned entries — survey_starts with no matching survey_responses row ──
// These never went through track.php at all (respondent abandoned mid-survey,
// or — for a Third Party project — there's no redirect back to us at all, so
// completion can structurally never be reported). Shown as "Pending" (Direct
// project — a completion signal may still arrive) or "Click Only" (Third
// Party — it structurally never will), so the team can at least see that
// traffic genuinely arrived, distinct from a real complete/terminate/etc.
try {
    $oe = $pdo->query("SELECT ss.uid AS respondent, ss.sid AS survey_id, ss.source, ss.vendor_id, ss.ip, ss.device, ss.country, ss.city, ss.start_time AS created_at,
            ps.project_type, c.client_name
        FROM survey_starts ss
        LEFT JOIN survey_responses sr ON sr.survey_id = ss.sid AND sr.respondent = ss.uid
        LEFT JOIN project_settings ps ON ps.survey_id = ss.sid
        LEFT JOIN exz_clients c ON c.id = ps.client_id
        WHERE sr.id IS NULL
        ORDER BY ss.start_time DESC LIMIT 500")->fetchAll();
    foreach ($oe as &$orow) {
        $orow['status']        = (($orow['project_type'] ?? 'direct') === 'tp') ? 'click_only' : 'pending';
        $orow['id']            = null;
        // device/country/city now come straight from survey_starts (captured
        // at entry time in vendor.php) instead of being hardcoded blank.
        $orow['loi_seconds']   = null;
        $orow['original_uid']  = null;
        $orow['is_duplicate']  = 0;
    }
    unset($orow);
    // Merge with real responses, keep newest-first, cap back to the same
    // 500-row window the response log always used.
    $rows = array_merge($rows, $oe);
    usort($rows, fn($a,$b) => strcmp($b['created_at'] ?? '', $a['created_at'] ?? ''));
    $rows = array_slice($rows, 0, 500);
} catch (Exception $e) {}

// Notes
try { $notes = $pdo->query("SELECT * FROM dashboard_notes ORDER BY created_at DESC")->fetchAll(); }
catch(Exception $e){ $notes = []; }

// Client portal accounts
$clients_list = [];
try { $clients_list = $pdo->query("SELECT id,username,client_name,allowed_projects,is_active,last_login,created_at FROM portal_clients ORDER BY created_at DESC")->fetchAll(); }
catch(Exception $e){ $clients_list = []; }

// ── Master Clients (project/billing use, separate from portal logins) ──
exz_ensure_client_extra_columns($pdo);
$master_clients = [];
try {
    $missing = $pdo->query("SELECT id FROM exz_clients WHERE client_uid IS NULL OR client_uid=''")->fetchAll();
    foreach ($missing as $mrow) {
        $newUid = exz_generate_client_uid($pdo);
        $pdo->prepare("UPDATE exz_clients SET client_uid=? WHERE id=?")->execute([$newUid, $mrow['id']]);
    }
    $master_clients = $pdo->query("SELECT * FROM exz_clients ORDER BY client_name ASC")->fetchAll();
}
catch(Exception $e){ $master_clients = []; }

// ── AUTO-GENERATED NEXT PROJECT ID (SID) — suggested default, e.g.
// EXR_260825_01 (EXR_YYMMDD_NN — NN resets to 01 automatically each day) ──
// This just pre-fills the "Project / Survey ID" field on the Add Project form
// with the next available ID for TODAY. The field stays editable, so a
// custom SID or an existing SID (to update that project) can still be typed.
$po_today  = date('ymd');            // e.g. "260825"
$po_prefix = "EXR_{$po_today}_";     // e.g. "EXR_260825_"
$po_prefix_len = strlen($po_prefix);
$next_po_sid = $po_prefix . '01';
try {
    $lastPoStmt = $pdo->prepare("SELECT survey_id FROM project_settings WHERE survey_id REGEXP ? ORDER BY CAST(SUBSTRING(survey_id, ?) AS UNSIGNED) DESC LIMIT 1");
    $lastPoStmt->execute(['^' . $po_prefix . '[0-9]+$', $po_prefix_len + 1]);
    $lastPo = $lastPoStmt->fetchColumn();
    if ($lastPo) {
        $nextNum = intval(substr($lastPo, $po_prefix_len)) + 1;
        $next_po_sid = $po_prefix . str_pad($nextNum, 2, '0', STR_PAD_LEFT);
    }
} catch(Exception $e){ /* fall back to {prefix}01 */ }

// Client lifetime-stats — total/active projects, total traffic, completes
// NOTE: project-counts and traffic-counts are computed as TWO SEPARATE
// queries, then merged by client_id in PHP. Combining them in one query
// via a JOIN would "fan out" — a client's project row gets duplicated
// once per matching survey_responses row, silently inflating the
// project-count aggregates (a real bug caught by testing: a client with
// 1 active + 1 inactive project, and 3 total responses on the active
// one, showed "Active Projects: 2" instead of the correct 1).
$client_stats = [];
try {
    $cp = $pdo->query("
        SELECT client_id, COUNT(*) AS total_projects, SUM(status='active') AS active_projects
        FROM project_settings WHERE client_id IS NOT NULL GROUP BY client_id
    ")->fetchAll();
    foreach ($cp as $row) $client_stats[$row['client_id']] = $row;

    $ct = $pdo->query("
        SELECT ps.client_id, COUNT(sr.id) AS total_traffic, SUM(sr.status='complete') AS total_completes
        FROM survey_responses sr
        JOIN project_settings ps ON ps.survey_id = sr.survey_id
        WHERE ps.client_id IS NOT NULL AND sr.no_entry_record=0
        GROUP BY ps.client_id
    ")->fetchAll();
    foreach ($ct as $row) {
        if (!isset($client_stats[$row['client_id']])) $client_stats[$row['client_id']] = ['total_projects'=>0,'active_projects'=>0];
        $client_stats[$row['client_id']]['total_traffic'] = $row['total_traffic'];
        $client_stats[$row['client_id']]['total_completes'] = $row['total_completes'];
    }
} catch (Exception $e) {}

// ── VENDOR × PROJECT MATRIX (grid: every vendor's clicks/completes per project) ──
// Instead of opening each Vendor or Project page separately to see "who's
// assigned to what", this shows every vendor-project combination with real
// traffic in one grid, with a paused-badge if that specific vendor-project
// mapping is paused.
$matrix_vendors = [];
$matrix_projects = [];
$matrix_cells = []; // keyed as "vendorId_sid" => ['clicks'=>x,'completes'=>y,'paused'=>bool]
try {
    $matrix_vendors = $pdo->query("SELECT id, vendor_name FROM exz_vendors ORDER BY vendor_name ASC LIMIT 50")->fetchAll();
    $matrix_projects = $pdo->query("SELECT survey_id, project_name FROM project_settings ORDER BY created_at DESC LIMIT 30")->fetchAll();

    // The survey_starts <-> survey_responses join below is by (sid,
    // respondent) — a Ghost Entry Detection completion (no matching
    // survey_starts row) can never match here, so this grid is already
    // ghost-safe without needing an explicit no_entry_record filter.
    $mc = $pdo->query("SELECT ss.vendor_id, ss.sid,
            COUNT(DISTINCT ss.id) AS clicks,
            SUM(CASE WHEN sr.status='complete' THEN 1 ELSE 0 END) AS completes
        FROM survey_starts ss
        LEFT JOIN survey_responses sr ON sr.survey_id = ss.sid AND sr.respondent = ss.uid
        WHERE ss.vendor_id IS NOT NULL
        GROUP BY ss.vendor_id, ss.sid");
    while ($row = $mc->fetch()) {
        $matrix_cells[$row['vendor_id'] . '_' . $row['sid']] = ['clicks' => $row['clicks'], 'completes' => $row['completes']];
    }

    $mp = $pdo->query("SELECT vendor_id, survey_id, status FROM exz_project_vendors");
    while ($row = $mp->fetch()) {
        $key = $row['vendor_id'] . '_' . $row['survey_id'];
        if (isset($matrix_cells[$key])) $matrix_cells[$key]['paused'] = ($row['status'] === 'inactive');
    }
} catch (Exception $e) {}

// ── Master Vendors ────────────────────────────────────────────
exz_ensure_vendor_extra_columns($pdo);
$master_vendors = [];
try { $master_vendors = $pdo->query("SELECT * FROM exz_vendors ORDER BY vendor_name ASC")->fetchAll(); }
catch(Exception $e){ $master_vendors = []; }

// ── Blocked IP List ──────────────────────────────────────────
exz_ensure_blocked_ips_table($pdo);
$blocked_ips = [];
try { $blocked_ips = $pdo->query("SELECT * FROM exz_blocked_ips ORDER BY created_at DESC")->fetchAll(); }
catch(Exception $e){ $blocked_ips = []; }

// ── Client Report ──────────────────────────────────────────────
$cr_client = intval($_GET['cr_client'] ?? 0);
$cr_from = trim($_GET['cr_from'] ?? '');
$cr_to = trim($_GET['cr_to'] ?? '');
$client_report_rows = [];
if ($cr_client) {
    try {
        $cr_where = "ps.client_id = ? AND sr.no_entry_record=0"; $cr_params = [$cr_client];
        if ($cr_from) { $cr_where .= " AND sr.created_at >= ?"; $cr_params[] = $cr_from . ' 00:00:00'; }
        if ($cr_to)   { $cr_where .= " AND sr.created_at <= ?"; $cr_params[] = $cr_to . ' 23:59:59'; }
        $crq = $pdo->prepare("
            SELECT ps.survey_id, ps.project_name, ps.parent_sid,
                SUM(sr.status='complete') AS completes,
                SUM(sr.status='terminate') AS terminates,
                SUM(sr.status='quotafull') AS overquota,
                SUM(sr.status='qc') AS qualityfail,
                COUNT(*) AS total
            FROM survey_responses sr
            JOIN project_settings ps ON ps.survey_id = sr.survey_id
            WHERE $cr_where
            GROUP BY ps.survey_id, ps.project_name, ps.parent_sid
            ORDER BY ps.project_name ASC
        ");
        $crq->execute($cr_params);
        $client_report_rows = $crq->fetchAll();
    } catch (Exception $e) {}
}
// Parent rollup for Client Report — same pattern as Billing's rollup.
$client_report_parent_rollup = [];
foreach ($client_report_rows as $crr) {
    if (!empty($crr['parent_sid'])) {
        $p = $crr['parent_sid'];
        if (!isset($client_report_parent_rollup[$p])) $client_report_parent_rollup[$p] = ['completes'=>0,'terminates'=>0,'overquota'=>0,'qualityfail'=>0,'total'=>0,'child_count'=>0];
        foreach (['completes','terminates','overquota','qualityfail','total'] as $f) $client_report_parent_rollup[$p][$f] += intval($crr[$f]);
        $client_report_parent_rollup[$p]['child_count']++;
    }
}

// ── Supplier Report ──────────────────────────────────────────────
$sr_vendor = intval($_GET['sr_vendor'] ?? 0);
$sr_from = trim($_GET['sr_from'] ?? '');
$sr_to = trim($_GET['sr_to'] ?? '');
$supplier_report_rows = [];
if ($sr_vendor) {
    try {
        $sr_where = "sr.vendor_id = ? AND sr.no_entry_record=0"; $sr_params = [$sr_vendor];
        if ($sr_from) { $sr_where .= " AND sr.created_at >= ?"; $sr_params[] = $sr_from . ' 00:00:00'; }
        if ($sr_to)   { $sr_where .= " AND sr.created_at <= ?"; $sr_params[] = $sr_to . ' 23:59:59'; }
        $srq = $pdo->prepare("
            SELECT sr.survey_id, ps.project_name, ps.parent_sid,
                COUNT(*) AS total,
                SUM(sr.status='complete') AS completes,
                SUM(sr.status='terminate') AS terminates
            FROM survey_responses sr
            LEFT JOIN project_settings ps ON ps.survey_id = sr.survey_id
            WHERE $sr_where
            GROUP BY sr.survey_id, ps.project_name, ps.parent_sid
            ORDER BY ps.project_name ASC
        ");
        $srq->execute($sr_params);
        $supplier_report_rows = $srq->fetchAll();
    } catch (Exception $e) {}
}
// Parent rollup for Supplier Report.
$supplier_report_parent_rollup = [];
foreach ($supplier_report_rows as $srr) {
    if (!empty($srr['parent_sid'])) {
        $p = $srr['parent_sid'];
        if (!isset($supplier_report_parent_rollup[$p])) $supplier_report_parent_rollup[$p] = ['total'=>0,'completes'=>0,'terminates'=>0,'child_count'=>0];
        foreach (['total','completes','terminates'] as $f) $supplier_report_parent_rollup[$p][$f] += intval($srr[$f]);
        $supplier_report_parent_rollup[$p]['child_count']++;
    }
}

// ── PM Time Report (system-wide, across ALL projects) ─────────
exz_ensure_pm_activity_table($pdo);
$pmt_from = trim($_GET['pmt_from'] ?? '');
$pmt_to = trim($_GET['pmt_to'] ?? '');
$pm_time_report = [];
try {
    $pmt_where = '1=1'; $pmt_params = [];
    if ($pmt_from) { $pmt_where .= " AND logged_at >= ?"; $pmt_params[] = $pmt_from . ' 00:00:00'; }
    if ($pmt_to)   { $pmt_where .= " AND logged_at <= ?"; $pmt_params[] = $pmt_to . ' 23:59:59'; }
    $pmtq = $pdo->prepare("
        SELECT user_name, SUM(duration_minutes) AS total_minutes, COUNT(*) AS total_activities,
            COUNT(DISTINCT survey_id) AS projects_touched
        FROM exz_project_activity_log WHERE $pmt_where
        GROUP BY user_name ORDER BY total_minutes DESC
    ");
    $pmtq->execute($pmt_params);
    $pm_time_report = $pmtq->fetchAll();
} catch (Exception $e) {}

// ── Question Library + PreScreen Templates ────────────────────
exz_ensure_question_library_tables($pdo);
exz_ensure_project_template_column($pdo);
$question_library = [];
try { $question_library = $pdo->query("SELECT * FROM exz_question_library ORDER BY created_at DESC")->fetchAll(); }
catch (Exception $e) {}

$prescreen_templates = [];
try { $prescreen_templates = $pdo->query("SELECT * FROM exz_prescreen_templates ORDER BY template_name ASC")->fetchAll(); }
catch (Exception $e) {}

// Question-count per template, for the template list view
$template_qcounts = [];
try {
    $tqc = $pdo->query("SELECT template_id, COUNT(*) AS cnt FROM exz_prescreen_template_questions GROUP BY template_id")->fetchAll();
    foreach ($tqc as $row) $template_qcounts[$row['template_id']] = $row['cnt'];
} catch (Exception $e) {}

// If editing a specific template, load its attached questions (in order)
$editing_template_id = intval($_GET['edit_template'] ?? 0);
$editing_template_questions = [];
if ($editing_template_id) {
    try {
        $etq = $pdo->prepare("SELECT ptq.id AS link_id, ql.* FROM exz_prescreen_template_questions ptq
            JOIN exz_question_library ql ON ql.id = ptq.question_id
            WHERE ptq.template_id=? ORDER BY ptq.sort_order ASC");
        $etq->execute([$editing_template_id]);
        $editing_template_questions = $etq->fetchAll();
    } catch (Exception $e) {}
}

// ── IP Tracker ────────────────────────────────────────────────
exz_ensure_browser_column($pdo);
$ipt_query = trim($_GET['ipt_query'] ?? '');
$ip_tracker_rows = [];
try {
    $ipt_where = '1=1'; $ipt_params = [];
    if ($ipt_query) {
        $ipt_where .= " AND (sr.ip LIKE ? OR sr.respondent LIKE ? OR ps.project_name LIKE ? OR sr.survey_id LIKE ? OR v.vendor_name LIKE ?)";
        $like = "%$ipt_query%";
        $ipt_params = [$like, $like, $like, $like, $like];
    }
    $ipt = $pdo->prepare("
        SELECT sr.*, ps.project_name, v.vendor_name
        FROM survey_responses sr
        LEFT JOIN project_settings ps ON ps.survey_id = sr.survey_id
        LEFT JOIN exz_vendors v ON v.id = sr.vendor_id
        WHERE $ipt_where
        ORDER BY sr.created_at DESC LIMIT 200
    ");
    $ipt->execute($ipt_params);
    $ip_tracker_rows = $ipt->fetchAll();
} catch (Exception $e) {}

// Per-vendor performance stats (from survey_responses.vendor_id)
$vendor_stats = [];
try {
    $vs = $pdo->query("SELECT vendor_id, COUNT(*) as clicks,
        SUM(status='complete') as completes, SUM(status='terminate') as terminates,
        COUNT(DISTINCT survey_id) as total_projects
        FROM survey_responses WHERE vendor_id IS NOT NULL GROUP BY vendor_id")->fetchAll();
    foreach ($vs as $row) $vendor_stats[$row['vendor_id']] = $row;
} catch(Exception $e){}
$vendor_total_clicks = array_sum(array_column($vendor_stats,'clicks'));
$vendor_total_completes = array_sum(array_column($vendor_stats,'completes'));

// ── Vendor assignments per project (survey_id => [vendor rows]) ─
$project_vendor_map = [];
try {
    exz_ensure_short_code_column($pdo);
    $missing_short = $pdo->query("SELECT id FROM exz_project_vendors WHERE short_code IS NULL OR short_code=''")->fetchAll();
    foreach ($missing_short as $mrow) {
        $newCode = exz_generate_short_code($pdo);
        $pdo->prepare("UPDATE exz_project_vendors SET short_code=? WHERE id=?")->execute([$newCode, $mrow['id']]);
    }
    $pv = $pdo->query("SELECT pv.survey_id, v.id, v.vendor_name, pv.short_code FROM exz_project_vendors pv
        JOIN exz_vendors v ON v.id = pv.vendor_id")->fetchAll();
    foreach ($pv as $row) $project_vendor_map[$row['survey_id']][] = $row;
} catch(Exception $e){}

// ── SESSION LOCK RELEASE ──────────────────────────────────────
// Everything from here down is the (expensive, many-query) dashboard
// render for a GET request — no further $_SESSION writes happen past
// this point. PHP's default session handler holds an exclusive file
// lock on the session for as long as it stays open, which otherwise
// means every OTHER request from the same browser (a second tab, a
// form submit fired while this render is still in flight, etc.) blocks
// waiting for this one slow render to finish before it can even start.
// On shared hosting with a low concurrent-process cap, a pile-up of
// blocked requests like that is exactly what produces "server busy" /
// 503 / 504 errors after sustained use. Grab what we still need from
// $_SESSION into plain variables first, then close it — reads still
// work fine after close, only further writes wouldn't persist.
$bulk_import_results_snapshot = $_SESSION['bulk_import_results'] ?? null;
if (isset($_GET['bulk_import_done']) && $bulk_import_results_snapshot !== null) {
    unset($_SESSION['bulk_import_results']);
}
session_write_close();

// ── Full projects list for Projects management tab (settings + live stats) ──
$projects_full = [];
try {
    $all_ps = $pdo->query("SELECT * FROM project_settings ORDER BY is_pinned DESC, updated_at DESC")->fetchAll();
    // response counts per survey_id (reuse $projects array already computed above)
    $resp_by_sid = [];
    foreach ($projects as $rp) $resp_by_sid[$rp['survey_id']] = $rp;
    // "Starts" — raw click/entry count per survey_id, from survey_starts
    // (written by vendor.php at entry time — always exists whether or not
    // the respondent ever reaches a final status).
    $starts_by_sid = [];
    try {
        $stq = $pdo->query("SELECT sid, COUNT(*) as cnt FROM survey_starts GROUP BY sid")->fetchAll();
        foreach ($stq as $srow) $starts_by_sid[$srow['sid']] = $srow['cnt'];
    } catch (Exception $e) {}
    foreach ($all_ps as $ps) {
        $rp = $resp_by_sid[$ps['survey_id']] ?? ['total'=>0,'completes'=>0,'terminates'=>0];
        $cl = null;
        if ($ps['client_id']) {
            foreach ($master_clients as $mc) if ($mc['id'] == $ps['client_id']) { $cl = $mc; break; }
        }
        $starts_count = $starts_by_sid[$ps['survey_id']] ?? 0;
        $all_outcomes = intval($rp['completes'] ?? 0) + intval($rp['terminates'] ?? 0) + intval($rp['quotafull'] ?? 0) + intval($rp['quality'] ?? 0);
        $projects_full[] = array_merge($ps, [
            'live_total'     => $rp['total'] ?? 0,
            'live_completes' => $rp['completes'] ?? 0,
            'live_terminates'=> $rp['terminates'] ?? 0,
            'live_quotafull' => $rp['quotafull'] ?? 0,
            'live_quality'   => $rp['quality'] ?? 0,
            'live_duplicates'=> $rp['duplicates'] ?? 0,
            'live_starts'    => $starts_count,
            'live_dropout'   => max(0, $starts_count - $all_outcomes),
            'client_row'     => $cl,
            'vendors'        => $project_vendor_map[$ps['survey_id']] ?? [],
        ]);
    }
} catch(Exception $e){}

// ── Parent/Child hierarchy + rollup, for Projects-list display only ──
// ($projects_full itself stays flat/unchanged — it's also used elsewhere,
// e.g. dropdown filters, where every SID should still be listed individually.)
$projects_by_sid = [];
foreach ($projects_full as $pf) $projects_by_sid[$pf['survey_id']] = $pf;
$children_by_parent = [];
foreach ($projects_full as $pf) {
    if (!empty($pf['parent_sid'])) $children_by_parent[$pf['parent_sid']][] = $pf['survey_id'];
}
$exz_rollup_fields = ['live_total','live_completes','live_terminates','live_quotafull','live_quality','live_duplicates','live_starts','live_dropout','target'];
function exz_derive_parent_status(array $childStatuses): string {
    if (empty($childStatuses)) return 'active';
    $allComplete = true; $anyActive = false;
    foreach ($childStatuses as $st) {
        if ($st !== 'complete') $allComplete = false;
        if ($st === 'active') $anyActive = true;
    }
    if ($allComplete) return 'complete';
    if ($anyActive) return 'active';
    return 'paused';
}
$projects_hierarchical = [];
$seen_as_child = [];
foreach ($projects_full as $pf) {
    if (!empty($pf['parent_sid'])) continue; // rendered under its parent below
    if (!empty($pf['is_parent'])) {
        $childSids = $children_by_parent[$pf['survey_id']] ?? [];
        $agg = $pf;
        foreach ($exz_rollup_fields as $f) $agg[$f] = intval($pf[$f] ?? 0);
        $childStatuses = [];
        foreach ($childSids as $csid) {
            $child = $projects_by_sid[$csid] ?? null;
            if (!$child) continue;
            foreach ($exz_rollup_fields as $f) $agg[$f] += intval($child[$f] ?? 0);
            $childStatuses[] = $child['status'] ?? 'active';
        }
        $agg['_derived_status']  = exz_derive_parent_status($childStatuses);
        $agg['_is_group_parent'] = true;
        $agg['_child_count']     = count($childSids);
        $projects_hierarchical[] = $agg;
        foreach ($childSids as $csid) {
            if (isset($projects_by_sid[$csid])) {
                $childRow = $projects_by_sid[$csid];
                $childRow['_is_child_row']   = true;
                $childRow['_parent_row_sid'] = $pf['survey_id'];
                $projects_hierarchical[] = $childRow;
                $seen_as_child[$csid] = true;
            }
        }
    } else {
        $projects_hierarchical[] = $pf;
    }
}
// Safety net: a child whose parent_sid points at a SID that no longer
// exists (e.g. deleted outside the normal delete-blocking flow, or a
// bulk-import edge case) must never just silently disappear from the
// list — surface it standalone with an "orphaned" flag instead.
foreach ($projects_full as $pf) {
    if (!empty($pf['parent_sid']) && empty($seen_as_child[$pf['survey_id']])) {
        $pf['_orphaned_parent_sid'] = $pf['parent_sid'];
        $projects_hierarchical[] = $pf;
    }
}

// ── Recently Added Projects (for Create Project tab) ────────────
// Sorted purely by creation time (not is_pinned/updated_at like the main
// table above) — genuinely "what got added recently", capped at 50 so a
// very large project list never has to load more than this in one go.
$recently_added_projects = [];
try {
    $recently_added_projects = $pdo->query("SELECT survey_id, project_name, project_type, status, created_at,
            (SELECT client_name FROM exz_clients WHERE id = project_settings.client_id) AS client_name
        FROM project_settings ORDER BY created_at DESC, id DESC LIMIT 50")->fetchAll();
} catch (Exception $e) {}

// ── Audit Log ─────────────────────────────────────────────────
$audit_log = [];
try { $audit_log = $pdo->query("SELECT * FROM exz_audit_log ORDER BY performed_at DESC LIMIT 100")->fetchAll(); }
catch(Exception $e){ $audit_log = []; }

// ── Team Members ──────────────────────────────────────────────
$team_members = [];
try { $team_members = $pdo->query("SELECT * FROM exz_team ORDER BY created_at ASC")->fetchAll(); }
catch(Exception $e){ $team_members = []; }

// ── Alert Settings (current saved values, for pre-filling the form) ────
// Falls back to the existing hardcoded constants (already working) so the
// form never looks empty — just editable now, and saved to DB going forward.
$alert_settings = ['telegram_bot_token'=>TG_TOKEN, 'telegram_chat_id'=>TG_CHAT_ID, 'alert_email'=>ALERT_EMAIL];
try {
    $rows_as = $pdo->query("SELECT setting_key,setting_value FROM exz_settings WHERE setting_key IN ('telegram_bot_token','telegram_chat_id','alert_email')")->fetchAll();
    foreach ($rows_as as $r) if ($r['setting_value'] !== '') $alert_settings[$r['setting_key']] = $r['setting_value'];
} catch(Exception $e){}

// ── Status Synonym Mapping (for admin management UI) ────────────
$status_synonyms = [];
try {
    exz_ensure_status_synonyms_table($pdo);
    exz_seed_default_status_synonyms($pdo);
    $status_synonyms = $pdo->query("SELECT * FROM exz_status_synonyms ORDER BY survey_id IS NULL DESC, synonym ASC")->fetchAll();
} catch (Exception $e) {}

// ── Bulk UID Checker — resolve raw/encrypted UID, check flags ───
$uid_bulk_results = [];
$uid_bulk_done = false;
if (isset($_POST['check_uids'])) {
    $uid_bulk_done = true;
    $bulk_sid = trim($_POST['ul_sid'] ?? '');
    $raw_uids = preg_split('/\r\n|\r|\n/', trim($_POST['ul_uids'] ?? ''));
    $raw_uids = array_slice(array_filter(array_map('trim', $raw_uids)), 0, 500);
    foreach ($raw_uids as $uid_chk) {
        try {
            $ids = [$uid_chk];
            $mm = $pdo->prepare("SELECT original_uid, encrypted_uid FROM exz_uid_mapping WHERE original_uid=? OR encrypted_uid=? LIMIT 1");
            $mm->execute([$uid_chk, $uid_chk]);
            $map_row = $mm->fetch();
            if ($map_row) { $ids[] = $map_row['original_uid']; $ids[] = $map_row['encrypted_uid']; }
            $ids = array_values(array_unique(array_filter($ids)));
            $in_ph = implode(',', array_fill(0, count($ids), '?'));

            $params = $ids;
            $where_sid = '';
            if ($bulk_sid !== '') { $where_sid = ' AND survey_id=?'; $params[] = $bulk_sid; }
            $q = $pdo->prepare("SELECT status,loi_seconds,is_duplicate,created_at,ip,device,country,source,survey_id
                FROM survey_responses WHERE respondent IN ($in_ph) $where_sid ORDER BY created_at DESC LIMIT 1");
            $q->execute($params);
            $r = $q->fetch();

            if (!$r) {
                $uid_bulk_results[] = ['uid'=>$uid_chk, 'tag'=>'not_found', 'flags'=>[], 'row'=>null, 'map'=>$map_row, 'qscore'=>null];
            } else {
                $flags = [];
                if (!empty($r['is_duplicate'])) $flags[] = 'DUP';
                if ($r['loi_seconds'] && $r['loi_seconds'] < SPEEDER_THRESHOLD) $flags[] = 'SPEEDER';
                if (in_array($r['status'], ['qc','quality'])) $flags[] = 'QC';
                $tag = empty($flags) ? 'clean' : (in_array('DUP',$flags) ? 'duplicate' : (in_array('SPEEDER',$flags) ? 'speeder' : 'flagged'));
                // Quick quality score (same formula as Quality Score module)
                $qscore = 100;
                if ($r['loi_seconds'] && $r['loi_seconds'] < SPEEDER_THRESHOLD) $qscore -= 40;
                elseif (empty($r['loi_seconds'])) $qscore -= 10;
                if (!empty($r['is_duplicate'])) $qscore -= 30;
                if (in_array($r['status'], ['qc','quality'])) $qscore -= 15;
                if (empty($r['device'])) $qscore -= 5;
                if (empty($r['country'])) $qscore -= 5;
                $qscore = max(0, min(100, $qscore));
                $uid_bulk_results[] = ['uid'=>$uid_chk, 'tag'=>$tag, 'flags'=>$flags, 'row'=>$r, 'map'=>$map_row, 'qscore'=>$qscore];
            }
        } catch (Exception $e) {
            $uid_bulk_results[] = ['uid'=>$uid_chk, 'tag'=>'error', 'flags'=>[], 'row'=>null, 'map'=>null, 'qscore'=>null];
        }
    }
}
$uid_bulk_summary = ['clean'=>0,'duplicate'=>0,'speeder'=>0,'flagged'=>0,'not_found'=>0,'error'=>0];
foreach ($uid_bulk_results as $ubr) { $uid_bulk_summary[$ubr['tag']] = ($uid_bulk_summary[$ubr['tag']] ?? 0) + 1; }

// ── Billing / Revenue Tracker ────────────────────────────────────
$billing_rows = [];
try {
    $bq = $pdo->query("SELECT ps.survey_id, ps.project_name, ps.cpi, ps.vendor_cost, ps.parent_sid, ps.is_parent, c.client_name AS cname,
        (SELECT COUNT(*) FROM survey_responses WHERE survey_id=ps.survey_id AND status='complete' AND no_entry_record=0) AS completes,
        COALESCE(iv.status,'unpaid') AS invoice_status, COALESCE(iv.invoice_no,'') AS invoice_no, COALESCE(iv.notes,'') AS invoice_notes
        FROM project_settings ps
        LEFT JOIN exz_clients c ON c.id = ps.client_id
        LEFT JOIN exz_invoice_status iv ON iv.survey_id = ps.survey_id
        ORDER BY ps.created_at DESC");
    $billing_rows = $bq->fetchAll();
} catch (Exception $e) {}

// Parent rollup summary for Billing — a non-selectable combined view of a
// parent's children's revenue/cost. Vendor assignment and Auto-Invoice
// generation stay attached to each CHILD SID exactly as before (each child
// keeps its own CPI, its own checkbox); this only adds a summary line so a
// parent study's total billing picture is visible at a glance.
$billing_parent_rollup = [];
foreach ($billing_rows as $br) {
    if (!empty($br['parent_sid'])) {
        $p = $br['parent_sid'];
        if (!isset($billing_parent_rollup[$p])) $billing_parent_rollup[$p] = ['completes' => 0, 'revenue' => 0.0, 'cost' => 0.0, 'child_count' => 0];
        $billing_parent_rollup[$p]['completes']   += intval($br['completes']);
        $billing_parent_rollup[$p]['revenue']     += intval($br['completes']) * floatval($br['cpi']);
        $billing_parent_rollup[$p]['cost']        += intval($br['completes']) * floatval($br['vendor_cost']);
        $billing_parent_rollup[$p]['child_count']++;
    }
}

// ── Global Search — cross-project by UID/SID/IP/Country ────────
$gs_query = trim($_GET['gs_query'] ?? '');
$gs_results = [];
if ($gs_query !== '') {
    try {
        $like = '%' . $gs_query . '%';
        // Search across both the stored (possibly encrypted) respondent value
        // AND the original pre-encryption UID via the mapping table, so a
        // search by either the raw or encrypted UID finds the record.
        $gsq = $pdo->prepare("SELECT sr.*, um.original_uid AS original_uid FROM survey_responses sr
            LEFT JOIN exz_uid_mapping um ON um.encrypted_uid = sr.respondent AND um.survey_id = sr.survey_id
            WHERE sr.respondent LIKE ? OR um.original_uid LIKE ? OR sr.survey_id LIKE ? OR sr.ip LIKE ? OR sr.country LIKE ? OR sr.city LIKE ?
            ORDER BY sr.created_at DESC LIMIT 200");
        $gsq->execute([$like, $like, $like, $like, $like, $like]);
        $gs_raw = $gsq->fetchAll();
        foreach ($gs_raw as $r) {
            $flags = [];
            if (!empty($r['is_duplicate'])) $flags[] = 'DUP';
            if ($r['loi_seconds'] && $r['loi_seconds'] < SPEEDER_THRESHOLD) $flags[] = 'SPEEDER';
            if (in_array($r['status'], ['qc','quality'])) $flags[] = 'QC';
            $tag = empty($flags) ? 'clean' : (in_array('DUP',$flags) ? 'duplicate' : (in_array('SPEEDER',$flags) ? 'speeder' : 'flagged'));
            $qscore = 100;
            if ($r['loi_seconds'] && $r['loi_seconds'] < SPEEDER_THRESHOLD) $qscore -= 40;
            elseif (empty($r['loi_seconds'])) $qscore -= 10;
            if (!empty($r['is_duplicate'])) $qscore -= 30;
            if (in_array($r['status'], ['qc','quality'])) $qscore -= 15;
            if (empty($r['device'])) $qscore -= 5;
            if (empty($r['country'])) $qscore -= 5;
            $qscore = max(0, min(100, $qscore));
            $map_row = !empty($r['original_uid']) ? ['original_uid'=>$r['original_uid'], 'encrypted_uid'=>$r['respondent']] : null;
            $display_uid = !empty($r['original_uid']) ? $r['original_uid'] : $r['respondent'];
            $gs_results[] = ['uid'=>$display_uid, 'tag'=>$tag, 'flags'=>$flags, 'row'=>$r, 'map'=>$map_row, 'qscore'=>$qscore];
        }
    } catch (Exception $e) {}
}

// ── Screener Data ───────────────────────────────────────────────
$scr_filter_sid = trim($_GET['scr_sid'] ?? '');
$screener_data = [];
try {
    if ($scr_filter_sid) {
        $sq = $pdo->prepare("SELECT * FROM exz_screener_answers WHERE survey_id=? ORDER BY created_at DESC LIMIT 2000");
        $sq->execute([$scr_filter_sid]);
    } else {
        $sq = $pdo->query("SELECT * FROM exz_screener_answers ORDER BY created_at DESC LIMIT 2000");
    }
    $screener_data = $sq->fetchAll();
} catch(Exception $e){ $screener_data = []; }

// Pivot: group all answers per respondent+project into one row
// (Gender/Age/Education/Income/Device as columns, matching Azilytics layout)
$screener_pivot = [];
foreach ($screener_data as $sd) {
    $key = $sd['respondent'].'|'.$sd['survey_id'];
    if (!isset($screener_pivot[$key])) {
        $screener_pivot[$key] = [
            'respondent' => $sd['respondent'], 'survey_id' => $sd['survey_id'],
            'gender'=>'—','age_group'=>'—','education'=>'—','income'=>'—','device_self'=>'—',
            'created_at' => $sd['created_at'],
        ];
    }
    if (isset($screener_pivot[$key][$sd['question_key']])) {
        $screener_pivot[$key][$sd['question_key']] = $sd['answer_value'];
    }
    // keep earliest timestamp for the group
    if ($sd['created_at'] < $screener_pivot[$key]['created_at']) $screener_pivot[$key]['created_at'] = $sd['created_at'];
}
$screener_pivot = array_values($screener_pivot);
usort($screener_pivot, fn($a,$b) => strtotime($b['created_at'].' UTC') <=> strtotime($a['created_at'].' UTC'));
$screener_pivot = array_slice($screener_pivot, 0, 300);

$screener_total = 0;
try { $screener_total = $pdo->query("SELECT COUNT(DISTINCT CONCAT(respondent,'|',survey_id)) FROM exz_screener_answers")->fetchColumn(); } catch(Exception $e){}

// JSON for charts
$trendJson   = json_encode($trend);
$hourlyJson  = json_encode($hourly);
$deviceJson  = json_encode($devices);
$countryJson = json_encode($countries);

// ── HELPERS ───────────────────────────────────────────────────
function fmt_loi($s) {
    if ($s === null || $s === '' || intval($s) === 0) return '—';
    $s = intval($s);
    return intdiv($s,60).'m '.($s%60).'s';
}
function loi_cls($s) {
    if ($s === null || intval($s) === 0) return '';
    $s = intval($s);
    if ($s < SPEEDER_THRESHOLD) return 'loi-red';
    if ($s < 480) return 'loi-yellow';
    return 'loi-green';
}
function pct($a,$b) { return $b>0 ? round(($a/$b)*100,1).'%' : '—'; }
function money($n)  { return $n>0 ? '$'.number_format($n,0) : '—'; }

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="viewport" content="width=device-width,initial-scale=1"><!-- smart refresh via JS -->
<title>Exazon Research — Survey Dashboard v5</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --navy:#0a1628;--navy2:#112040;--blue:#1b4fd8;--blue2:#3b82f6;
  --gold:#c8a84b;--gold2:#e6c96a;--off:#f0f4ff;--muted:#94a3b8;
  --green:#22c55e;--red:#ef4444;--yellow:#f59e0b;
  --purple:#8b5cf6;--teal:#14b8a6;--orange:#f97316;
}
body{font-family:'DM Sans',sans-serif;background:var(--off);color:#1e293b;min-height:100vh}

/* NAV */
/* SIDEBAR LAYOUT (Azilytics-style) */
.app-layout{display:flex;min-height:100vh}
.sidebar{width:250px;flex-shrink:0;background:var(--navy);border-right:1px solid rgba(59,130,246,0.15);
         position:fixed;top:0;left:0;bottom:0;overflow-y:auto;overflow-x:hidden;z-index:200;padding:20px 14px;
         transition:width .2s ease}
.sidebar.collapsed{width:60px}
.sidebar.collapsed:hover{width:250px}
.sidebar-toggle{position:absolute;top:18px;right:10px;background:rgba(255,255,255,0.08);border:none;color:var(--muted);
                 width:22px;height:22px;border-radius:6px;cursor:pointer;font-size:12px;line-height:1;z-index:5}
.sidebar.collapsed .sidebar-brand,.sidebar.collapsed .sidebar-user,.sidebar.collapsed .sidebar-section-lbl{opacity:0;transition:opacity .1s}
.sidebar.collapsed:hover .sidebar-brand,.sidebar.collapsed:hover .sidebar-user,
.sidebar.collapsed:hover .sidebar-section-lbl{opacity:1}
.sidebar.collapsed .tab-btn{overflow:hidden}
.sidebar.collapsed:hover .tab-btn{overflow:visible}
.app-content{transition:margin-left .2s ease}
.sidebar-brand{display:flex;align-items:center;gap:10px;padding:0 6px 18px;border-bottom:1px solid rgba(255,255,255,0.08);margin-bottom:16px;white-space:nowrap}
.nav-logo{width:34px;height:34px;border-radius:50%;border:2px solid rgba(59,130,246,0.3);background:#fff;flex-shrink:0}
.nav-name{font-family:'Bebas Neue',sans-serif;font-size:15px;letter-spacing:2px;color:#fff;line-height:1.2}
.nav-tag{font-size:8px;letter-spacing:2px;text-transform:uppercase;color:var(--gold)}
.sidebar-user{padding:0 6px 16px;margin-bottom:10px;white-space:nowrap}
.sidebar-user-name{font-size:12px;font-weight:700;color:#fff}
.sidebar-user-role{font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--gold)}
.sidebar-actions{display:flex;flex-wrap:wrap;gap:6px;padding:0 6px 16px;margin-bottom:6px;border-bottom:1px solid rgba(255,255,255,0.08)}
.sidebar-section-lbl{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:rgba(255,255,255,0.25);padding:14px 6px 6px;white-space:nowrap}
.tab-btn{display:flex;align-items:center;gap:8px;width:100%;text-align:left;padding:9px 10px;font-size:12px;font-weight:600;
         color:var(--muted);background:none;border:none;border-radius:8px;cursor:pointer;white-space:nowrap;transition:all .15s}
.tab-btn.active,.tab-btn:hover{color:#fff;background:rgba(59,130,246,0.15)}
.tab-pane{display:none}.tab-pane.active{display:block}
.btn-sm{padding:5px 12px;border-radius:6px;font-size:10px;font-weight:600;
        letter-spacing:1px;text-transform:uppercase;cursor:pointer;
        border:none;text-decoration:none;display:inline-block;white-space:nowrap}
.btn-green{background:linear-gradient(135deg,var(--green),#16a34a);color:#fff}
.btn-blue{background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff}
.btn-wa{background:linear-gradient(135deg,#25d366,#128c7e);color:#fff}
.btn-logout{background:rgba(255,255,255,0.08);color:var(--muted);border:1px solid rgba(255,255,255,0.1)}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);
          animation:pulse 2s infinite;display:inline-block;margin-right:5px}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.3)}}

/* LAYOUT */
.app-content{flex:1;margin-left:250px;min-width:0}
.app-content.sidebar-collapsed{margin-left:60px}
.topbar-slim{background:var(--navy);padding:10px 24px;display:flex;justify-content:flex-end;align-items:center;gap:8px;
             border-bottom:1px solid rgba(59,130,246,0.15);position:sticky;top:0;z-index:150;flex-wrap:wrap}
.main{max-width:1340px;margin:0 auto;padding:20px 18px}
@media(max-width:900px){
  .sidebar{position:static;width:100%;height:auto;display:flex;flex-wrap:wrap}
  .app-content{margin-left:0}
}

/* STAT GRIDS */
.sg8{display:grid;grid-template-columns:repeat(8,1fr);gap:10px;margin-bottom:12px}
.sg4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}
.sg3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px}
.stat-card{background:#fff;border-radius:12px;padding:13px 10px;border:1px solid #e2e8f0;
           box-shadow:0 1px 4px rgba(10,22,40,0.05);text-align:center}
.stat-num{font-family:'Bebas Neue',sans-serif;font-size:24px;letter-spacing:1px}
.stat-num.green{color:var(--green)}.stat-num.red{color:var(--red)}
.stat-num.yellow{color:var(--yellow)}.stat-num.purple{color:var(--purple)}
.stat-num.blue{color:var(--blue)}.stat-num.navy{color:var(--navy)}
.stat-num.teal{color:var(--teal)}.stat-num.orange{color:var(--orange)}
.stat-num.gold{color:var(--gold)}.stat-num.pink{color:#ec4899}
.stat-lbl{font-size:8px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-top:2px}
.stat-sub{font-size:10px;color:#94a3b8;margin-top:2px}

/* MINI ROW */
.mini-row{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px}
.mini-card{background:#fff;border-radius:12px;padding:13px 16px;border:1px solid #e2e8f0;
           box-shadow:0 1px 4px rgba(10,22,40,0.04);display:flex;align-items:center;gap:12px}
.mini-icon{font-size:22px}
.mini-val{font-family:'Bebas Neue',sans-serif;font-size:18px;color:var(--navy)}
.mini-lbl{font-size:8px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}

/* CHARTS */
.charts-row{display:grid;grid-template-columns:2fr 1fr 1fr;gap:14px;margin-bottom:18px}
.charts-row2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
.chart-card{background:#fff;border-radius:12px;padding:16px;
            border:1px solid #e2e8f0;box-shadow:0 1px 4px rgba(10,22,40,0.04)}
.chart-title{font-family:'Bebas Neue',sans-serif;font-size:12px;letter-spacing:2px;
             color:var(--navy);margin-bottom:12px}

/* SECTION TITLE */
.sec-title{font-family:'Bebas Neue',sans-serif;font-size:15px;
           letter-spacing:2px;color:var(--navy);margin-bottom:10px}

/* PROJECT CARDS */
.proj-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
           gap:12px;margin-bottom:18px}
.proj-card{background:#fff;border-radius:12px;padding:15px;border:1px solid #e2e8f0;
           box-shadow:0 1px 4px rgba(10,22,40,0.04)}
.proj-id{font-family:'Bebas Neue',sans-serif;font-size:17px;letter-spacing:2px;color:var(--blue)}
.proj-client{font-size:9px;color:var(--gold);font-weight:600;
             margin-bottom:8px;letter-spacing:.5px;text-transform:uppercase}
.proj-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.proj-stat{font-size:11px;color:#64748b} .proj-stat b{color:#1e293b}
.proj-cr{font-size:11px;font-weight:600;color:var(--green);margin-bottom:4px}
.proj-target{font-size:10px;color:#64748b;margin-bottom:5px}
.proj-rev{font-size:12px;font-weight:700;color:var(--green);margin-bottom:4px}
.proj-margin{font-size:11px;color:var(--teal);margin-bottom:4px}
.pbar{height:5px;background:#e2e8f0;border-radius:3px;overflow:hidden;margin-bottom:6px}
.pbar-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--blue),var(--blue2))}
.pbar-fill.near{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.pbar-fill.done{background:linear-gradient(90deg,#22c55e,#4ade80)}
.proj-badges{display:flex;gap:4px;flex-wrap:wrap;margin-top:4px}
.badge{font-size:9px;padding:2px 7px;border-radius:10px;font-weight:600}
.badge-spd{background:rgba(239,68,68,.1);color:#dc2626;border:1px solid rgba(239,68,68,.3)}
.badge-dup{background:rgba(245,158,11,.1);color:#b45309;border:1px solid rgba(245,158,11,.3)}
.badge-loi{background:rgba(20,184,166,.1);color:#0f766e;border:1px solid rgba(20,184,166,.3)}
.badge-rev{background:rgba(34,197,94,.1);color:#15803d;border:1px solid rgba(34,197,94,.3)}
.proj-dates{font-size:9px;color:var(--muted);margin-top:6px}

/* FILTERS */
.filters-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.fsel{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:7px 11px;
      font-family:'DM Sans',sans-serif;font-size:12px;color:#1e293b;outline:none;cursor:pointer}
.fsel:focus{border-color:var(--blue2)}
.fsrch{flex:1;min-width:180px;background:#fff;border:1px solid #e2e8f0;border-radius:8px;
       padding:7px 12px;font-family:'DM Sans',sans-serif;font-size:12px;outline:none}
.fsrch:focus{border-color:var(--blue2)}

/* TABLE */
.tbl-card{background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e2e8f0;
          box-shadow:0 1px 4px rgba(10,22,40,0.04);margin-bottom:18px}
.tbl-head{background:var(--navy);padding:11px 16px;display:flex;
          align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.tbl-title{font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:2px;color:var(--gold)}
.tbl-count{font-size:10px;color:var(--muted)}
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
thead{background:#f8faff}
th{padding:9px 12px;text-align:left;font-size:8px;letter-spacing:2px;
   text-transform:uppercase;color:#64748b;font-weight:600;
   border-bottom:1px solid #e2e8f0;white-space:nowrap}
tbody tr{border-bottom:1px solid #f1f5f9;transition:background .12s}
tbody tr:hover{background:#f8faff}
tbody tr.spd-row{background:rgba(239,68,68,.03)}
td{padding:9px 12px;font-size:12px;color:#374151;vertical-align:middle;white-space:nowrap}
td.mono{font-family:'Courier New',monospace;font-size:11px}

/* PILLS — FIX: qc added */
.pill{display:inline-flex;align-items:center;gap:3px;border-radius:20px;
      padding:2px 9px;font-size:10px;font-weight:600}
.pill::before{content:'';width:5px;height:5px;border-radius:50%;flex-shrink:0}
.pill.complete  {background:rgba(34,197,94,.1);color:#16a34a;border:1px solid rgba(34,197,94,.3)}  .pill.complete::before{background:var(--green)}
.pill.terminate {background:rgba(100,116,139,.1);color:#475569;border:1px solid rgba(100,116,139,.3)} .pill.terminate::before{background:#64748b}
.pill.quotafull {background:rgba(245,158,11,.1);color:#b45309;border:1px solid rgba(245,158,11,.3)}  .pill.quotafull::before{background:var(--yellow)}
.pill.quality,
.pill.qc        {background:rgba(139,92,246,.1);color:#7c3aed;border:1px solid rgba(139,92,246,.3)} .pill.quality::before,.pill.qc::before{background:var(--purple)}
.pill.unmatched {background:rgba(239,68,68,.1);color:#dc2626;border:1px solid rgba(239,68,68,.3)} .pill.unmatched::before{background:#ef4444}
.pill.pending   {background:rgba(59,130,246,.1);color:#1b4fd8;border:1px solid rgba(59,130,246,.3)} .pill.pending::before{background:#3b82f6}
.pill.click_only{background:rgba(148,163,184,.15);color:#64748b;border:1px solid rgba(148,163,184,.3)} .pill.click_only::before{background:#94a3b8}
.tag{border-radius:4px;padding:1px 5px;font-size:9px;font-weight:700;margin-left:3px}
.tag-dup{background:rgba(239,68,68,.1);color:#dc2626;border:1px solid rgba(239,68,68,.3)}
.tag-spd{background:rgba(249,115,22,.1);color:#c2410c;border:1px solid rgba(249,115,22,.3)}

/* LOI */
.loi-red   {color:#dc2626;font-weight:700}
.loi-yellow{color:#b45309;font-weight:600}
.loi-green {color:#16a34a;font-weight:600}

/* ALERTS */
.alert{background:#fff;border-radius:10px;padding:11px 15px;
       border-left:4px solid var(--red);margin-bottom:10px;
       font-size:12px;color:#7f1d1d;display:flex;align-items:center;gap:8px}
.alert.warn{border-left-color:var(--yellow);color:#78350f}
.alert.info{border-left-color:var(--blue2);color:#1e3a5f}
.alert.ok  {border-left-color:var(--green);color:#14532d}
.alert.orange{border-left-color:var(--orange);color:#7c2d12}

/* CLOCK */
.clock-bar{background:#fff;border-radius:12px;padding:12px 18px;
           border:1px solid #e2e8f0;box-shadow:0 1px 4px rgba(10,22,40,.04);
           margin-bottom:18px;display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.ck-item{display:flex;align-items:center;gap:8px}
.ck-flag{font-size:18px}
.ck-lbl{font-size:8px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}
.ck-time{font-family:'Bebas Neue',sans-serif;font-size:20px;letter-spacing:2px;color:var(--navy)}
.ck-sep{color:#e2e8f0;font-size:18px}

/* MODAL */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);
               z-index:999;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:#fff;border-radius:16px;padding:26px;max-width:460px;
       width:90%;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.modal h3{font-family:'Bebas Neue',sans-serif;font-size:17px;letter-spacing:2px;
          color:var(--navy);margin-bottom:14px}
.form-row{margin-bottom:11px}
.form-lbl{font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;
          text-transform:uppercase;margin-bottom:4px;display:block}
.form-inp{width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;
          padding:9px 13px;font-family:'DM Sans',sans-serif;font-size:13px;
          color:#1e293b;outline:none}
.form-inp:focus{border-color:var(--blue2)}
.modal-foot{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.btn-cancel{background:#f1f5f9;color:#64748b;border:none;border-radius:8px;
            padding:8px 16px;font-size:12px;font-weight:600;cursor:pointer}
.btn-save{background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;
          border:none;border-radius:8px;padding:8px 16px;
          font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer}

/* NOTES */
.notes-card{background:#fff;border-radius:12px;padding:16px;
            border:1px solid #e2e8f0;box-shadow:0 1px 4px rgba(10,22,40,.04);margin-bottom:18px}
.notes-row{display:flex;gap:8px;margin-bottom:12px}
.notes-ta{flex:1;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;
          padding:9px 13px;font-family:'DM Sans',sans-serif;font-size:13px;
          color:#1e293b;outline:none;resize:none;height:54px}
.notes-ta:focus{border-color:var(--blue2)}
.btn-note{background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;
          border:none;border-radius:8px;padding:0 16px;
          font-family:'Bebas Neue',sans-serif;font-size:13px;cursor:pointer;
          height:54px;white-space:nowrap}
.note-item{background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;
           padding:9px 13px;margin-bottom:7px;display:flex;
           align-items:flex-start;justify-content:space-between;gap:8px}
.note-text{font-size:13px;color:#1e293b;flex:1;line-height:1.5}
.note-meta{font-size:10px;color:var(--muted);margin-top:2px}
.note-del{background:none;border:none;color:#94a3b8;cursor:pointer;
          font-size:13px;padding:2px 5px;border-radius:4px}
.note-del:hover{color:var(--red)}

/* VENDOR SCORECARD */
.score-bar{height:5px;background:#e2e8f0;border-radius:3px;overflow:hidden;margin-top:3px}
.score-fill{height:100%;border-radius:3px}

/* CALLMEBOT SETUP */
.setup-box{border-radius:10px;padding:13px 16px;font-size:12px;line-height:1.8;margin-bottom:14px}
.setup-box code{background:rgba(0,0,0,.06);border-radius:4px;padding:1px 5px;font-family:monospace}

/* RESPONSIVE */
@media(max-width:1100px){.sg8{grid-template-columns:repeat(4,1fr)}.charts-row{grid-template-columns:1fr 1fr}.mini-row{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.sg8{grid-template-columns:repeat(2,1fr)}.sg4{grid-template-columns:repeat(2,1fr)}.sg3{grid-template-columns:1fr}.charts-row{grid-template-columns:1fr}.charts-row2{grid-template-columns:1fr}.mini-row{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- SETTINGS MODAL -->
<div class="modal-overlay" id="settingsModal">
  <div class="modal">
    <h3>⚙️ Project Settings</h3>
    <form method="POST">
      <input type="hidden" name="save_settings" value="1">
      <div class="form-row">
        <label class="form-lbl">Project ID</label>
        <input class="form-inp" type="text" name="ps_sid" id="modal_sid" readonly style="background:#f1f5f9;color:#64748b">
      </div>
      <div class="form-row">
        <label class="form-lbl">Target Completes</label>
        <input class="form-inp" type="number" name="ps_target" id="modal_target" placeholder="e.g. 200" min="0">
      </div>
      <div class="form-row">
        <label class="form-lbl">Client CPI — Cost Per Interview ($)</label>
        <input class="form-inp" type="number" step="0.01" name="ps_cpi" id="modal_cpi" placeholder="e.g. 250.00" min="0">
      </div>
      <div class="form-row">
        <label class="form-lbl">Vendor Cost Per Complete ($)</label>
        <input class="form-inp" type="number" step="0.01" name="ps_vcost" id="modal_vcost" placeholder="e.g. 150.00" min="0">
      </div>
      <div class="modal-foot">
        <button type="button" class="btn-cancel" onclick="closeModal()">Cancel</button>
        <button type="submit" class="btn-save">Save Settings</button>
      </div>
    </form>
  </div>
</div>

<!-- SIDEBAR + APP LAYOUT -->
<div class="app-layout">
<aside class="sidebar" id="appSidebar">
  <button class="sidebar-toggle" onclick="toggleSidebar()" id="sidebarToggleBtn" title="Collapse/Expand sidebar">☰</button>
  <div class="sidebar-brand">
    <img src="logo.php" class="nav-logo" alt="ExaVerify">
    <div>
      <div class="nav-name">Exazon Research</div>
      <div class="nav-tag">Survey Dashboard v5</div>
    </div>
  </div>
  <div class="sidebar-user">
    <div class="sidebar-user-name"><?= htmlspecialchars($_SESSION['ex_team_name'] ?? '') ?></div>
    <div class="sidebar-user-role"><?= htmlspecialchars(exz_current_team_role()) ?></div>
  </div>

  <div class="sidebar-section-lbl">Main</div>
  <button class="tab-btn active" onclick="sw('overview',this)">📊 Dashboard</button>
  <button class="tab-btn" onclick="sw('createproject',this)">➕ Create Project</button>
  <button class="tab-btn" onclick="sw('projects',this)">📁 All Projects</button>
  <button class="tab-btn" onclick="sw('responses',this)">📋 Leads</button>
  <button class="tab-btn" onclick="sw('fraud',this)">🚨 Fraud Detection <?php $ft=intval($stats['speeders']??0)+intval($stats['duplicates']??0)+count($ghost_entries); if($ft>0): ?><span style="background:#ef4444;color:#fff;border-radius:10px;padding:1px 5px;font-size:9px;margin-left:3px"><?= $ft ?></span><?php endif; ?></button>
  <button class="tab-btn" onclick="sw('screener',this)">📄 Screener Data</button>
  <button class="tab-btn" onclick="sw('searchlookup',this)">🔍 Search &amp; Lookup</button>
  <button class="tab-btn" onclick="sw('notes',this)">📝 Notes <?php if(count($notes)): ?><span style="background:var(--blue2);color:#fff;border-radius:10px;padding:1px 5px;font-size:9px;margin-left:3px"><?= count($notes) ?></span><?php endif; ?></button>
  <button class="tab-btn" onclick="sw('billing',this)">🧾 Billing</button>
  <button class="tab-btn" onclick="sw('qualityscore',this)">⭐ Quality Score</button>
  <button class="tab-btn" onclick="sw('reconciletab',this)">⚖️ Reconcile</button>
  <button class="tab-btn" onclick="sw('charts',this)">📈 Analytics</button>
  <button class="tab-btn" onclick="sw('feasibility',this)">📐 Feasibility Calc</button>

  <div class="sidebar-section-lbl">Management</div>
  <button class="tab-btn" onclick="sw('clientsmaster',this)">🏢 Clients</button>
  <button class="tab-btn" onclick="sw('vendors',this)">👥 Vendors</button>
  <button class="tab-btn" onclick="sw('matrix',this)">🔲 Vendor × Project</button>
  <button class="tab-btn" onclick="sw('clients',this)">👤 Client Accounts <?php if(count($clients_list)>0): ?><span style="background:var(--blue2);color:#fff;border-radius:10px;padding:1px 5px;font-size:9px;margin-left:3px"><?= count($clients_list) ?></span><?php endif; ?></button>

  <div class="sidebar-section-lbl">Reports</div>
  <button class="tab-btn" onclick="sw('pmtimereport',this)">🕒 PM Time Report</button>
  <button class="tab-btn" onclick="sw('clientreport',this)">📊 Client Report</button>
  <button class="tab-btn" onclick="sw('supplierreport',this)">📊 Supplier Report</button>

  <div class="sidebar-section-lbl">Tools</div>
  <button class="tab-btn" onclick="sw('questionlibrary',this)">📚 Question Library</button>
  <button class="tab-btn" onclick="sw('prescreentemplates',this)">📋 PreScreen Templates</button>
  <button class="tab-btn" onclick="sw('iptracker',this)">📍 IP Tracker</button>
  <button class="tab-btn" onclick="sw('blockedips',this)">⛔ Blocked IPs <?php if(count($blocked_ips)>0): ?><span style="background:#ef4444;color:#fff;border-radius:10px;padding:1px 5px;font-size:9px;margin-left:3px"><?= count($blocked_ips) ?></span><?php endif; ?></button>

  <div class="sidebar-section-lbl">Admin</div>
  <button class="tab-btn" onclick="sw('alerts',this)">🔔 Alert Settings</button>
  <button class="tab-btn" onclick="sw('auditlog',this)">📜 Audit Log</button>
  <?php if (exz_is_superadmin()): ?>
  <button class="tab-btn" onclick="sw('team',this)">👥 Team</button>
  <?php endif; ?>

  <div class="sidebar-section-lbl">Account</div>
  <button class="tab-btn" onclick="sw('changepass',this)">⚙️ Account Settings</button>
  <a class="tab-btn" href="https://exaconnect.exazonresearch.com" target="_blank" style="text-decoration:none;color:inherit">🔗 ExaConnect (Panel Portal)</a>
  <a class="tab-btn" href="?logout=1" style="text-decoration:none;color:#f87171">⏻ Logout</a>
</aside>

<div class="app-content" id="appContent">
  <div class="topbar-slim">
    <span style="font-size:10px;color:var(--muted)"><span class="live-dot"></span>60s</span>
    <?php if(isset($_GET['report_sent'])): ?>
    <span style="font-size:10px;color:var(--green);font-weight:600">✅ Sent!</span>
    <?php endif; ?>
    <a href="?send_report=1" onclick="this.href='?send_report=1&ret='+(activeTabName||'overview');" class="btn-sm btn-wa">📲 Report</a>
    <a href="?export=csv"    class="btn-sm btn-green">⬇ CSV</a>
    <a href="?export=json"   class="btn-sm btn-blue">⬇ JSON</a>
    <a href="?export=xlsx"   class="btn-sm" style="background:#16a34a;color:#fff">⬇ Excel</a>
  </div>

<div class="main">

<!-- ════════ OVERVIEW TAB ════════ -->
<div class="tab-pane active" id="tab-overview">
<?php if (isset($_GET['err']) && $_GET['err']==='noperm'): ?>
<div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#b91c1c;border-radius:8px;padding:12px 16px;font-size:13px;margin-bottom:14px">🔒 Your role (<?= htmlspecialchars(ucfirst(exz_current_team_role())) ?>) does not have permission to perform this action. Contact a Superadmin.</div>
<?php endif; ?>

<?php if($ir_drift_alert): ?>
<div class="alert orange">🚨 <strong>IR Drift Alert!</strong> IR in the last 50 responses is only <?= $ir_drift ?>% — below the 20% threshold. Check immediately!</div>
<?php endif; ?>
<?php if(($stats['speeders']??0)>0): ?>
<div class="alert">⚡ <strong><?= $stats['speeders'] ?> speeder<?= $stats['speeders']>1?'s':'' ?></strong> detected — LOI under 3 min. <a href="#" onclick="sw('fraud',document.querySelectorAll('.tab-btn')[2]);return false" style="color:#dc2626;text-decoration:underline">View →</a></div>
<?php endif; ?>
<?php if(($stats['duplicates']??0)>0): ?>
<div class="alert warn">⚠️ <strong><?= $stats['duplicates'] ?> duplicate<?= $stats['duplicates']>1?'s':'' ?></strong> detected. <a href="#" onclick="sw('fraud',document.querySelectorAll('.tab-btn')[2]);return false" style="color:#b45309;text-decoration:underline">View →</a></div>
<?php endif; ?>
<?php if($gross_margin > 0): ?>
<div class="alert ok">💰 Gross Margin: <strong><?= money($gross_margin) ?></strong> &nbsp;|&nbsp; Revenue: <strong><?= money($total_revenue) ?></strong> &nbsp;|&nbsp; Cost: <strong><?= money($total_cost) ?></strong></div>
<?php endif; ?>
<?php if(isset($_GET['report_sent'])): ?>
<div class="alert info">✅ Daily report sent via WhatsApp + Email!</div>
<?php endif; ?>

<!-- CLOCKS -->
<div class="clock-bar">
  <div class="ck-item"><span class="ck-flag">🇮🇳</span><div><div class="ck-lbl">India IST</div><div class="ck-time" id="istClock">--:--:--</div></div></div>
  <span class="ck-sep">|</span>
  <div class="ck-item"><span class="ck-flag">🇺🇸</span><div><div class="ck-lbl">New York ET</div><div class="ck-time" id="etClock">--:--:--</div></div></div>
  <span class="ck-sep">|</span>
  <div class="ck-item"><span class="ck-flag">🌐</span><div><div class="ck-lbl">UTC</div><div class="ck-time" id="utcClock">--:--:--</div></div></div>
  <div style="margin-left:auto;font-size:10px;color:var(--muted)">Updated: <?= date('d M H:i:s') ?></div>
</div>

<!-- ROW 1: 8 Main Stats -->
<div class="sg8">
  <div class="stat-card"><div class="stat-num navy"><?= $stats['total']??0 ?></div><div class="stat-lbl">Total</div></div>
  <div class="stat-card"><div class="stat-num green"><?= $stats['completes']??0 ?></div><div class="stat-lbl">Completes</div><div class="stat-sub">CR: <?= pct($stats['completes']??0,$stats['total']??0) ?></div></div>
  <div class="stat-card"><div class="stat-num red"><?= $stats['terminates']??0 ?></div><div class="stat-lbl">Terminates</div></div>
  <div class="stat-card"><div class="stat-num yellow"><?= $stats['quotafull']??0 ?></div><div class="stat-lbl">Quota Full</div></div>
  <div class="stat-card"><div class="stat-num purple"><?= $stats['quality']??0 ?></div><div class="stat-lbl">Quality Fail</div></div>
  <div class="stat-card"><div class="stat-num pink"><?= $partials ?></div><div class="stat-lbl">Partials</div><div class="stat-sub">Drop-outs</div></div>
  <div class="stat-card"><div class="stat-num orange"><?= $stats['speeders']??0 ?></div><div class="stat-lbl">Speeders</div><div class="stat-sub">&lt;3 min</div></div>
  <div class="stat-card"><div class="stat-num blue"><?= $stats['projects']??0 ?></div><div class="stat-lbl">Projects</div></div>
</div>

<!-- ROW 2: LOI + Revenue + IR -->
<div class="sg4">
  <div class="stat-card"><div class="stat-num teal"><?= fmt_loi($stats['avg_loi']??0) ?></div><div class="stat-lbl">Avg LOI</div><div class="stat-sub">Completes only</div></div>
  <div class="stat-card"><div class="stat-num blue"><?= fmt_loi($stats['median_loi']??0) ?></div><div class="stat-lbl">Median LOI</div><div class="stat-sub">Middle value</div></div>
  <div class="stat-card"><div class="stat-num <?= ($stats['min_loi']??0)>0&&($stats['min_loi']??0)<SPEEDER_THRESHOLD?'red':'teal' ?>"><?= fmt_loi($stats['min_loi']??0) ?></div><div class="stat-lbl">Min LOI</div><div class="stat-sub">Fastest complete</div></div>
  <div class="stat-card"><div class="stat-num teal"><?= $ir ?>%</div><div class="stat-lbl">IR Overall</div><div class="stat-sub">Drift: <?= $ir_drift!==null?$ir_drift.'%':'—' ?></div></div>
</div>

<!-- ROW 3: Financial + Today -->
<div class="sg4">
  <div class="stat-card"><div class="stat-num gold"><?= money($total_revenue) ?></div><div class="stat-lbl">Total Revenue</div><div class="stat-sub">Client CPI based</div></div>
  <div class="stat-card"><div class="stat-num <?= $gross_margin>=0?'green':'red' ?>"><?= money($gross_margin) ?></div><div class="stat-lbl">Gross Margin</div><div class="stat-sub">Rev - Vendor Cost</div></div>
  <div class="stat-card"><div class="stat-num teal"><?= $epc>0?'$'.$epc:'—' ?></div><div class="stat-lbl">EPC</div><div class="stat-sub">Earnings/Click</div></div>
  <div class="stat-card"><div class="stat-num green"><?= $today['completes']??0 ?></div><div class="stat-lbl">Today Completes</div><div class="stat-sub">IR: <?= pct($today['completes']??0,($today['completes']??0)+($today['terminates']??0)) ?></div></div>
</div>

<!-- MINI ROW -->
<div class="mini-row">
  <div class="mini-card"><div class="mini-icon">🎯</div><div><div class="mini-val"><?= $stats['direct_count']??0 ?> Direct &nbsp;|&nbsp; <?= $stats['tp_count']??0 ?> TP</div><div class="mini-lbl">Direct vs Third Party</div></div></div>
  <div class="mini-card"><div class="mini-icon">📡</div><div><div class="mini-val"><?= $stats['duplicates']??0 ?> Flagged</div><div class="mini-lbl">Duplicate UIDs</div></div></div>
  <div class="mini-card"><div class="mini-icon">📋</div><div><div class="mini-val">Today: <?= ($today['quotafull']??0) ?> QF &nbsp;·&nbsp; <?= ($today['quality']??0) ?> QC</div><div class="mini-lbl">Today's Quota Full & QC</div></div></div>
</div>

<!-- CHARTS -->
<div class="charts-row">
  <div class="chart-card">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:12px">
      <div class="chart-title" style="margin-bottom:0"><?= ($trend_from && $trend_to) ? 'Daily Trend — Custom Range' : 'Daily Trend — Last 7 Days' ?></div>
      <form method="GET" action="index.php#overview" style="display:flex;align-items:center;gap:6px" onsubmit="var t=this.querySelectorAll('input,button,select'); return true;">
        <input type="hidden" name="page" value="<?= htmlspecialchars($_GET['page'] ?? '') ?>">
        <input type="date" name="trend_from" value="<?= htmlspecialchars($trend_from) ?>" style="font-size:11px;padding:4px 6px;border:1px solid #e2e8f0;border-radius:6px;background:#f8faff">
        <span style="font-size:11px;color:#94a3b8">to</span>
        <input type="date" name="trend_to" value="<?= htmlspecialchars($trend_to) ?>" style="font-size:11px;padding:4px 6px;border:1px solid #e2e8f0;border-radius:6px;background:#f8faff">
        <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:6px;padding:5px 12px;font-size:11px;font-weight:600;cursor:pointer">Go</button>
        <?php if ($trend_from || $trend_to): ?>
        <a href="?<?= http_build_query(array_diff_key($_GET, ['trend_from'=>1,'trend_to'=>1])) ?>#overview" style="background:#f1f3f9;color:#475569;border-radius:6px;padding:5px 12px;font-size:11px;font-weight:600;text-decoration:none">Reset</a>
        <?php endif; ?>
      </form>
    </div>
    <canvas id="trendChart" height="110"></canvas>
  </div>
  <div class="chart-card"><div class="chart-title">Status Breakdown</div><canvas id="doughChart" height="160"></canvas></div>
  <div class="chart-card"><div class="chart-title">Device Split</div><canvas id="devChart" height="160"></canvas></div>
</div>
<div class="chart-card" style="margin-bottom:18px"><div class="chart-title">Hourly — Today</div><canvas id="hrChart" height="70"></canvas></div>

<!-- PROJECTS -->
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap;gap:8px">
  <div class="sec-title" style="margin:0">Projects Overview</div>
  <?php if(count($projects)>4): ?>
  <button onclick="toggleProj(this)" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:7px 14px;font-size:12px;font-weight:600;cursor:pointer">▼ Show All (<?= count($projects)-4 ?> more)</button>
  <?php endif; ?>
</div>

<?php
function renderProjCard($p, $proj_settings) {
    $ps     = $proj_settings[$p['survey_id']] ?? null;
    $target = $ps['target']      ?? 0;
    $cpi    = $ps['cpi']         ?? 0;
    $vcost  = $ps['vendor_cost'] ?? 0;
    $rev    = $p['completes'] * $cpi;
    $cost   = $p['completes'] * $vcost;
    $margin = $rev - $cost;
    $cr     = $p['total']>0 ? round($p['completes']/$p['total']*100) : 0;
    $ir_p   = ($p['completes']+$p['terminates'])>0 ? round($p['completes']/($p['completes']+$p['terminates'])*100,1) : 0;
    $tpct   = $target>0 ? min(100,round($p['completes']/$target*100)) : 0;
    $bcls   = $tpct>=100?'done':($tpct>=80?'near':'');
    echo '<div class="proj-card">';
    echo '<div style="display:flex;align-items:flex-start;justify-content:space-between">';
    echo '<div class="proj-id">'.htmlspecialchars($p['survey_id']).'</div>';
    echo '<button onclick="openModal(\''.htmlspecialchars($p['survey_id']).'\',\''.$target.'\',\''.$cpi.'\',\''.$vcost.'\')" style="background:none;border:1px solid #e2e8f0;border-radius:6px;padding:3px 7px;font-size:10px;color:#64748b;cursor:pointer">⚙️</button>';
    echo '</div>';
    if($p['client_name']) echo '<div class="proj-client">🏢 '.htmlspecialchars($p['client_name']).'</div>';
    echo '<div class="proj-row">';
    echo '<div class="proj-stat">Total: <b>'.$p['total'].'</b></div>';
    echo '<div class="proj-stat" style="color:#22c55e">✓ <b>'.$p['completes'].'</b></div>';
    echo '<div class="proj-stat" style="color:#ef4444">✗ <b>'.$p['terminates'].'</b></div>';
    echo '<div class="proj-stat" style="color:#f59e0b">⚠ <b>'.$p['quotafull'].'</b></div>';
    echo '<div class="proj-stat" style="color:#8b5cf6">⚑ <b>'.$p['quality'].'</b></div>';
    echo '</div>';
    echo '<div class="proj-cr">CR: '.$cr.'% &nbsp;·&nbsp; <span style="color:var(--teal)">IR: '.$ir_p.'%</span> &nbsp;·&nbsp; <span style="color:var(--muted)">'.fmt_loi($p['avg_loi']).'</span></div>';
    if($target>0) {
        echo '<div class="proj-target">🎯 Target: <strong>'.$p['completes'].'/'.$target.'</strong> ('.$tpct.'%)</div>';
        echo '<div class="pbar"><div class="pbar-fill '.$bcls.'" style="width:'.$tpct.'%"></div></div>';
    } else {
        echo '<div class="pbar"><div class="pbar-fill" style="width:'.$cr.'%"></div></div>';
    }
    if($rev>0) echo '<div class="proj-rev">💰 Rev: $'.number_format($rev,0).'</div>';
    if($margin>0) echo '<div class="proj-margin">📈 Margin: $'.number_format($margin,0).'</div>';
    echo '<div class="proj-badges">';
    if($p['speeders']>0)   echo '<span class="badge badge-spd">⚡ '.$p['speeders'].' SPD</span>';
    if($p['duplicates']>0) echo '<span class="badge badge-dup">⚠ '.$p['duplicates'].' DUP</span>';
    if($p['avg_loi']>0)    echo '<span class="badge badge-loi">⏱ '.fmt_loi($p['avg_loi']).'</span>';
    if($cpi>0)             echo '<span class="badge badge-rev">CPI $'.$cpi.'</span>';
    echo '</div>';
    echo '<div class="proj-dates">First: '.date('d M Y',strtotime($p['first_response'].' UTC')).' · Last: '.date('d M H:i',strtotime($p['last_response'].' UTC')).'</div>';
    echo '</div>';
}
?>
<div class="proj-grid" id="topProj">
<?php foreach(array_slice($projects,0,4) as $p) renderProjCard($p,$proj_settings); ?>
<?php if(empty($projects)): ?><div class="proj-card" style="color:#94a3b8;font-size:13px">No projects yet.</div><?php endif; ?>
</div>
<?php if(count($projects)>4): ?>
<div id="extraProj" style="overflow:hidden;max-height:0;transition:max-height .45s ease,opacity .3s;opacity:0">
  <div class="proj-grid" style="margin-top:10px">
  <?php foreach(array_slice($projects,4) as $p) renderProjCard($p,$proj_settings); ?>
  </div>
</div>
<?php endif; ?>

<div class="chart-card" style="margin-top:16px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
    <div class="chart-title" style="margin-bottom:0">📁 Recent Projects</div>
    <a href="#" onclick="sw('projects');return false;" style="font-size:11px;color:var(--blue2);text-decoration:none;font-weight:600">View All Projects →</a>
  </div>
  <?php if (empty($projects_full)): ?>
  <div style="text-align:center;padding:20px;color:#94a3b8;font-size:12px">No projects yet.</div>
  <?php else: ?>
  <table style="width:100%">
    <?php foreach (array_slice($projects_full, 0, 5) as $rp): ?>
    <tr>
      <td style="padding:6px 8px;font-size:12px;font-weight:600;color:#1e293b"><?= htmlspecialchars($rp['project_name'] ?: $rp['survey_id']) ?></td>
      <td style="padding:6px 8px;font-size:11px;font-family:monospace;color:#94a3b8"><?= htmlspecialchars($rp['survey_id']) ?></td>
      <td style="padding:6px 8px;font-size:11px;text-align:right"><span class="pill <?= ($rp['status']??'')==='active' ? 'complete' : 'terminate' ?>"><?= ucfirst($rp['status'] ?? 'unknown') ?></span></td>
    </tr>
    <?php endforeach; ?>
  </table>
  <?php endif; ?>
</div>

<div class="chart-card" style="margin-top:16px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
    <div class="chart-title" style="margin-bottom:0">📜 Recent Activity</div>
    <a href="#" onclick="sw('auditlog');return false;" style="font-size:11px;color:var(--blue2);text-decoration:none;font-weight:600">View All Audit Log →</a>
  </div>
  <?php if (empty($audit_log)): ?>
  <div style="text-align:center;padding:20px;color:#94a3b8;font-size:12px">No activity logged yet.</div>
  <?php else: ?>
  <table style="width:100%">
    <?php foreach (array_slice($audit_log, 0, 5) as $al): ?>
    <tr>
      <td style="padding:6px 8px;font-size:11px"><span class="pill terminate"><?= htmlspecialchars($al['action']) ?></span></td>
      <td style="padding:6px 8px;font-size:12px;color:#475569"><?= htmlspecialchars($al['detail']) ?></td>
      <td style="padding:6px 8px;font-size:11px;color:#64748b;white-space:nowrap">👤 <?= htmlspecialchars($al['performed_by'] ?? 'Unknown') ?></td>
      <td style="padding:6px 8px;font-size:11px;color:#94a3b8;text-align:right;white-space:nowrap"><?= date('d M H:i', strtotime($al['performed_at'].' UTC')) ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
  <?php endif; ?>
</div>
</div><!-- /overview -->

<!-- ════════ PROJECTS TAB (full CRUD — Direct + TP) ════════ -->
<?php
// Valid "Child of..." dropdown options — only real top-level parents
// (flagged is_parent=1, and not themselves a child of anything).
$parent_project_options = array_values(array_filter($projects_full, fn($pf) => !empty($pf['is_parent']) && empty($pf['parent_sid'])));
?>
<div class="tab-pane" id="tab-createproject">
<div style="margin-top:16px">

<?php if (isset($_GET['msg'])): ?>
<div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#dc2626;border-radius:8px;padding:10px 16px;font-size:13px;margin-bottom:14px">⚠ <?= htmlspecialchars($_GET['msg']) ?></div>
<?php endif; ?>

  <div class="sec-title">➕ Add / Update Project</div>
  <div class="tbl-card" style="padding:18px;margin-bottom:18px">
    <form method="POST">
      <input type="hidden" name="save_project" value="1">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;margin-bottom:12px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Project / Survey ID (SID) *</div>
          <div style="display:flex;gap:6px">
            <input id="pr_sid_input" style="flex:1;width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="pr_sid" value="<?= htmlspecialchars($next_po_sid) ?>" placeholder="e.g. EXR_260825_01 or KANTAR_UK_2026" required onblur="prLoadExistingStructure()" onchange="prLoadExistingStructure()">
            <button type="button" onclick="document.getElementById('pr_sid_input').value='<?= htmlspecialchars($next_po_sid) ?>'; prLoadExistingStructure();" title="Reset to auto-generated ID" style="background:#f1f3f9;border:1px solid #e2e8f0;border-radius:8px;padding:0 10px;font-size:13px;cursor:pointer;color:#475569">🔄</button>
          </div>
          <div style="font-size:9px;color:#94a3b8;margin-top:3px">Auto-filled with the next PO number — edit this to set a custom ID, or type an existing SID to update that project.</div>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Project Name</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="pr_name" placeholder="e.g. UK Healthcare B2B">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Client</div>
          <select name="pr_client" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
            <option value="">— Select client —</option>
            <?php foreach($master_clients as $mc): ?>
            <option value="<?= $mc['id'] ?>"><?= htmlspecialchars($mc['client_name']) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Type</div>
          <select name="pr_type" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
            <option value="direct">Direct — our redirect is on the client's survey (completion tracked)</option>
            <option value="tp">Third Party — client's own end page, no redirect to us (entries only)</option>
          </select>
          <div style="font-size:9px;color:#94a3b8;margin-top:3px">Controls how orphaned entries (no completion signal received) are labelled: Direct → "Pending", Third Party → "Click Only".</div>
        </div>
      </div>
      <!-- Structure — parent/child grouping, unrelated to the "Type" field above -->
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:12px;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:12px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Structure</div>
          <select name="pr_structure" id="prStructureSelect" style="width:100%;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" onchange="prStructureChanged()">
            <option value="standalone">Standalone (default)</option>
            <option value="parent">Parent project</option>
            <option value="child">Child of...</option>
          </select>
          <div style="font-size:9px;color:#94a3b8;margin-top:3px">Groups multi-country/multi-vendor studies under one parent for rollup reporting. Doesn't affect Live URL, CPI, target, or vendor — those stay per-project either way.</div>
        </div>
        <div id="prParentSidWrap" style="display:none">
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Parent Project</div>
          <select name="pr_parent_sid" id="prParentSidSelect" style="width:100%;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" onchange="prSuggestChildSid()">
            <option value="">— Select parent —</option>
            <?php foreach ($parent_project_options as $ppo): ?>
            <option value="<?= htmlspecialchars($ppo['survey_id']) ?>"><?= htmlspecialchars($ppo['survey_id']) ?><?= $ppo['project_name'] ? ' — '.htmlspecialchars($ppo['project_name']) : '' ?></option>
            <?php endforeach; ?>
          </select>
          <?php if (empty($parent_project_options)): ?>
          <div style="font-size:9px;color:#94a3b8;margin-top:3px">No parent projects yet — mark one as "Parent project" first.</div>
          <?php endif; ?>
        </div>
        <div id="prCountryCodeWrap" style="display:none">
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Country Code (for child SID)</div>
          <div style="position:relative">
            <input id="prCountryCodeInput" style="width:100%;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" placeholder="e.g. IN, BD, PH" maxlength="60" autocomplete="off" oninput="prSuggestChildSid(); prCountryAutocomplete(this,'prCountryCodeDropdown',false)" onfocus="prCountryAutocomplete(this,'prCountryCodeDropdown',false)" onblur="setTimeout(()=>document.getElementById('prCountryCodeDropdown').style.display='none',150)">
            <div id="prCountryCodeDropdown" class="pr-country-dropdown" style="display:none"></div>
          </div>
          <div style="font-size:9px;color:#94a3b8;margin-top:3px">Auto-fills the SID above as parent-CODE — still fully editable.</div>
        </div>
      </div>
      <script>
      // Existing SID -> Structure lookup, so editing an existing project
      // (by retyping its SID) doesn't silently reset it to Standalone and
      // detach it from its parent — the #1 edge case this feature has to
      // avoid (see save_project's own server-side guard for the same thing).
      var prExistingStructure = {
        <?php foreach ($projects_full as $pf):
          $st = !empty($pf['is_parent']) ? 'parent' : (!empty($pf['parent_sid']) ? 'child' : 'standalone');
        ?>
        <?= json_encode($pf['survey_id']) ?>: {structure: <?= json_encode($st) ?>, parent_sid: <?= json_encode($pf['parent_sid'] ?? '') ?>},
        <?php endforeach; ?>
      };
      function prLoadExistingStructure(){
        var sid = document.getElementById('pr_sid_input').value.trim();
        var info = prExistingStructure[sid];
        var sel = document.getElementById('prStructureSelect');
        if (info) {
          sel.value = info.structure;
          if (info.structure === 'child') document.getElementById('prParentSidSelect').value = info.parent_sid;
        } else {
          sel.value = 'standalone'; // brand-new SID — safe default
        }
        prStructureChanged();
      }
      function prStructureChanged(){
        var v = document.getElementById('prStructureSelect').value;
        document.getElementById('prParentSidWrap').style.display   = (v === 'child') ? '' : 'none';
        document.getElementById('prCountryCodeWrap').style.display = (v === 'child') ? '' : 'none';
      }
      function prSuggestChildSid(){
        var parent = document.getElementById('prParentSidSelect').value;
        var code   = document.getElementById('prCountryCodeInput').value.trim().toUpperCase().replace(/[^A-Z0-9]/g,'');
        if (parent && code) {
          document.getElementById('pr_sid_input').value = parent + '-' + code;
        }
      }

      // ── Country autocomplete (Target Countries + Country Code fields) ──
      // Genuinely-editable — typing anything freely always works exactly
      // as before; the dropdown is purely an optional shortcut on top.
      var prCountryList = [
        ["Afghanistan","AF"],["Albania","AL"],["Algeria","DZ"],["Andorra","AD"],["Angola","AO"],
        ["Argentina","AR"],["Armenia","AM"],["Australia","AU"],["Austria","AT"],["Azerbaijan","AZ"],
        ["Bahamas","BS"],["Bahrain","BH"],["Bangladesh","BD"],["Barbados","BB"],["Belarus","BY"],
        ["Belgium","BE"],["Belize","BZ"],["Benin","BJ"],["Bhutan","BT"],["Bolivia","BO"],
        ["Bosnia and Herzegovina","BA"],["Botswana","BW"],["Brazil","BR"],["Brunei","BN"],["Bulgaria","BG"],
        ["Burkina Faso","BF"],["Burundi","BI"],["Cambodia","KH"],["Cameroon","CM"],["Canada","CA"],
        ["Chad","TD"],["Chile","CL"],["China","CN"],["Colombia","CO"],["Costa Rica","CR"],
        ["Croatia","HR"],["Cuba","CU"],["Cyprus","CY"],["Czech Republic","CZ"],["Denmark","DK"],
        ["Dominican Republic","DO"],["Ecuador","EC"],["Egypt","EG"],["El Salvador","SV"],["Estonia","EE"],
        ["Ethiopia","ET"],["Fiji","FJ"],["Finland","FI"],["France","FR"],["Georgia","GE"],
        ["Germany","DE"],["Ghana","GH"],["Greece","GR"],["Guatemala","GT"],["Haiti","HT"],
        ["Honduras","HN"],["Hong Kong","HK"],["Hungary","HU"],["Iceland","IS"],["India","IN"],
        ["Indonesia","ID"],["Iran","IR"],["Iraq","IQ"],["Ireland","IE"],["Israel","IL"],
        ["Italy","IT"],["Ivory Coast","CI"],["Jamaica","JM"],["Japan","JP"],["Jordan","JO"],
        ["Kazakhstan","KZ"],["Kenya","KE"],["Kuwait","KW"],["Kyrgyzstan","KG"],["Laos","LA"],
        ["Latvia","LV"],["Lebanon","LB"],["Libya","LY"],["Lithuania","LT"],["Luxembourg","LU"],
        ["Madagascar","MG"],["Malawi","MW"],["Malaysia","MY"],["Maldives","MV"],["Mali","ML"],
        ["Malta","MT"],["Mauritius","MU"],["Mexico","MX"],["Moldova","MD"],["Monaco","MC"],
        ["Mongolia","MN"],["Montenegro","ME"],["Morocco","MA"],["Mozambique","MZ"],["Myanmar","MM"],
        ["Namibia","NA"],["Nepal","NP"],["Netherlands","NL"],["New Zealand","NZ"],["Nicaragua","NI"],
        ["Niger","NE"],["Nigeria","NG"],["North Korea","KP"],["North Macedonia","MK"],["Norway","NO"],
        ["Oman","OM"],["Pakistan","PK"],["Panama","PA"],["Papua New Guinea","PG"],["Paraguay","PY"],
        ["Peru","PE"],["Philippines","PH"],["Poland","PL"],["Portugal","PT"],["Qatar","QA"],
        ["Romania","RO"],["Russia","RU"],["Rwanda","RW"],["Saudi Arabia","SA"],["Senegal","SN"],
        ["Serbia","RS"],["Singapore","SG"],["Slovakia","SK"],["Slovenia","SI"],["Somalia","SO"],
        ["South Africa","ZA"],["South Korea","KR"],["South Sudan","SS"],["Spain","ES"],["Sri Lanka","LK"],
        ["Sudan","SD"],["Sweden","SE"],["Switzerland","CH"],["Syria","SY"],["Taiwan","TW"],
        ["Tajikistan","TJ"],["Tanzania","TZ"],["Thailand","TH"],["Togo","TG"],["Trinidad and Tobago","TT"],
        ["Tunisia","TN"],["Turkey","TR"],["Turkmenistan","TM"],["Uganda","UG"],["Ukraine","UA"],
        ["United Arab Emirates","AE"],["United Kingdom","GB"],["United States","US"],["Uruguay","UY"],
        ["Uzbekistan","UZ"],["Venezuela","VE"],["Vietnam","VN"],["Yemen","YE"],["Zambia","ZM"],["Zimbabwe","ZW"]
      ];

      function prCountryAutocomplete(inputEl, dropdownId, isMultiValue){
        var dropdown = document.getElementById(dropdownId);
        var raw = inputEl.value;
        // For the comma-separated Target Countries field, only match against
        // whatever's being typed after the last comma — earlier entries stay
        // untouched. For the single-value Country Code field, match the whole thing.
        var query = isMultiValue ? raw.split(',').pop().trim().toLowerCase() : raw.trim().toLowerCase();
        if (query === '') { dropdown.style.display = 'none'; return; }
        var matches = prCountryList.filter(function(c){
          return c[0].toLowerCase().indexOf(query) === 0 || c[1].toLowerCase() === query;
        }).slice(0, 8);
        if (matches.length === 0) { dropdown.style.display = 'none'; return; }
        dropdown.innerHTML = matches.map(function(c){
          return '<div class="pr-country-option" onmousedown="prSelectCountry(\'' + inputEl.id + '\',\'' + dropdownId + '\',' + isMultiValue + ',\'' + c[0].replace(/'/g,"\\'") + '\',\'' + c[1] + '\')">' + c[0] + ' <span style="color:#94a3b8;font-size:10px">(' + c[1] + ')</span></div>';
        }).join('');
        dropdown.style.display = 'block';
      }

      function prSelectCountry(inputId, dropdownId, isMultiValue, name, code){
        var inputEl = document.getElementById(inputId);
        if (isMultiValue) {
          // Target Countries: append the full NAME, preserving any earlier
          // comma-separated entries already typed.
          var parts = inputEl.value.split(',').map(function(s){ return s.trim(); }).filter(Boolean);
          parts.pop(); // drop the partial query being typed
          parts.push(name);
          inputEl.value = parts.join(', ') + ', ';
        } else {
          // Country Code field: insert the short CODE, then re-run the
          // existing SID-suggestion logic exactly as if it were typed.
          inputEl.value = code;
          prSuggestChildSid();
        }
        document.getElementById(dropdownId).style.display = 'none';
        inputEl.focus();
        // Genuinely move the cursor to the END after selecting — without
        // this, focus() alone leaves the cursor at position 0, so typing
        // the next country would insert it at the START instead of
        // appending after what was just selected.
        var len = inputEl.value.length;
        inputEl.setSelectionRange(len, len);
      }
      </script>
      <style>
      .pr-country-dropdown{position:absolute;top:100%;left:0;right:0;background:#fff;border:1px solid #e2e8f0;border-radius:8px;margin-top:4px;max-height:220px;overflow-y:auto;z-index:50;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
      .pr-country-option{padding:8px 12px;font-size:12px;color:#1e293b;cursor:pointer}
      .pr-country-option:hover{background:#f1f5f9}
      </style>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:12px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">CPI — Client Pays You ($)</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="number" step="0.01" name="pr_cpi" placeholder="e.g. 500">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">CPI — You Pay Vendor ($)</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="number" step="0.01" name="pr_vcost" placeholder="e.g. 300">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Target Completes</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="number" name="pr_target" placeholder="e.g. 300">
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Start Date</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="date" name="pr_start_date">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">End Date</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="date" name="pr_end_date">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Project Manager</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="pr_manager" placeholder="e.g. Rahul Sharma">
        </div>
      </div>
      <div style="margin-bottom:12px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">PreScreen Template (optional — leave blank for default 6 questions)</div>
        <select name="pr_template" id="prTemplateSelect" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
          <option value="">— Default (fixed 6 questions) —</option>
          <?php foreach ($prescreen_templates as $pt): ?>
          <option value="<?= $pt['id'] ?>"><?= htmlspecialchars($pt['template_name']) ?> (<?= $template_qcounts[$pt['id']] ?? 0 ?> questions)</option>
          <?php endforeach; ?>
        </select>
      </div>
      <div style="margin-bottom:12px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Target Countries (comma-separated — for reference only, e.g. one live URL/SID shared across multiple markets)</div>
        <div style="position:relative">
          <input id="prTargetCountriesInput" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="pr_countries" placeholder="e.g. United States, United Kingdom, Germany" autocomplete="off" oninput="prCountryAutocomplete(this,'prTargetCountriesDropdown',true)" onfocus="prCountryAutocomplete(this,'prTargetCountriesDropdown',true)" onblur="setTimeout(()=>document.getElementById('prTargetCountriesDropdown').style.display='none',150)">
          <div id="prTargetCountriesDropdown" class="pr-country-dropdown" style="display:none"></div>
        </div>

      </div>
      <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">+ Add / Update Project</button>
      <span style="font-size:11px;color:#94a3b8;margin-left:10px">Same SID = update existing</span>
    </form>
  </div>

  <!-- Bulk Project Import -->
  <div class="sec-title">📥 Bulk Import Projects (CSV)</div>
  <div class="tbl-card" style="padding:18px;margin-bottom:18px">
    <?php if (isset($_GET['bulk_import_done']) && $bulk_import_results_snapshot !== null):
        $bir = $bulk_import_results_snapshot; ?>
    <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 16px;margin-bottom:14px;font-size:12px">
      <b style="color:#16a34a">Import complete:</b> <?= $bir['created'] ?> created, <?= $bir['updated'] ?> updated<?= count($bir['errors']) ? ', <span style="color:#dc2626">'.count($bir['errors']).' error(s)</span>' : '' ?>.
      <?php if (count($bir['errors'])): ?>
      <ul style="margin:8px 0 0 18px;color:#dc2626">
        <?php foreach ($bir['errors'] as $err): ?>
        <li><?= htmlspecialchars($err) ?></li>
        <?php endforeach; ?>
      </ul>
      <?php endif; ?>
    </div>
    <?php endif; ?>
    <div style="font-size:11px;color:#94a3b8;margin-bottom:12px">
      Upload a CSV with columns: <b>sid, project_name, client_name, cpi, target, live_url, parent_sid</b> (only <b>sid</b> is required; existing SIDs get updated, same as the single-project form above). <b>parent_sid</b> is optional — leave blank for a standalone project, or set it to another row's <b>sid</b> (in this file or already in the system) to make this row its child; that other SID is automatically flagged as a parent. Parent and child rows can be in any order in the file.
      <a href="data:text/csv;charset=utf-8,sid%2Cproject_name%2Cclient_name%2Ccpi%2Ctarget%2Clive_url%2Cparent_sid%0AEXR_260825_01%2CGlobal%20Study%2CKantar%2C0%2C0%2C%2C%0AEXR_260825_01-UK%2CUK%20B2B%20Study%2CKantar%2C4.50%2C500%2Chttps%3A//example.com/s%3Fuid%3D%5BUID%5D%2CEXR_260825_01" download="project_import_template.csv" style="color:var(--blue2);margin-left:6px">⬇ Download template CSV</a>
    </div>
    <form method="POST" enctype="multipart/form-data" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <input type="hidden" name="bulk_import_projects" value="1">
      <input type="file" name="bulk_csv" accept=".csv" required style="font-size:12px">
      <button type="submit" style="background:linear-gradient(135deg,#16a34a,#22c55e);color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">📥 Import Projects</button>
    </form>
  </div>

  <div class="tbl-card" style="padding:18px;margin-bottom:18px">
    <div style="font-size:11px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Live Survey URL — set separately per project (SID must already exist above)</div>
    <form method="POST">
      <input type="hidden" name="save_project" value="1">
      <div style="display:grid;grid-template-columns:1fr 2fr auto;gap:10px;align-items:end">
        <div>
          <div style="font-size:10px;color:#64748b;margin-bottom:4px">SID</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;outline:none" type="text" name="pr_sid" placeholder="existing SID" required>
        </div>
        <div>
          <div style="font-size:10px;color:#64748b;margin-bottom:4px">Live URL — [UID]/[SID]/[VID] placeholders supported</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:11px;outline:none" type="text" name="pr_liveurl" placeholder="https://client-survey.com/s?r=[UID]">
        </div>
        <div style="display:flex;align-items:center;gap:6px;padding-bottom:9px">
          <input type="checkbox" name="pr_encrypt" value="1" checked id="encchk">
          <label for="encchk" style="font-size:11px;color:#64748b">Encrypt UID</label>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr;gap:10px;margin-top:10px">
        <div>
          <div style="font-size:10px;color:#64748b;margin-bottom:4px">Test Survey URL (optional)</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:11px;outline:none" type="text" name="pr_testurl" placeholder="https://client-survey.com/test?r=[UID]">
        </div>
        <div>
          <div style="font-size:10px;color:#64748b;margin-bottom:4px">Description / Study Parameters (optional)</div>
          <textarea name="pr_description" rows="3" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;outline:none;resize:vertical;font-family:'DM Sans',sans-serif" placeholder="e.g. US 18+ Gen Pop, M/F, healthcare decision-makers..."></textarea>
        </div>
      </div>
      <button type="submit" style="margin-top:10px;background:rgba(59,130,246,.1);color:#1b4fd8;border:1px solid rgba(59,130,246,.25);border-radius:8px;padding:8px 18px;font-size:12px;font-weight:600;cursor:pointer">Save Live URL</button>
    </form>
  </div>

  <div class="tbl-card" style="padding:0;overflow:hidden">
    <div class="tbl-head" style="padding:14px 18px">
      <div class="tbl-title">📁 Recently Added Projects</div>
      <div style="display:flex;align-items:center;gap:10px">
        <div class="tbl-count" id="rapCount"><?= count($recently_added_projects) ?> shown</div>
        <select id="rapPageSize" onchange="rapRender()" style="font-size:11px;padding:4px 8px;border:1px solid #e2e8f0;border-radius:6px;background:#f8faff;color:#475569">
          <option value="10">10 / page</option>
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
        </select>
      </div>
    </div>
    <div class="tbl-wrap">
      <table style="width:100%" id="rapTable">
        <thead><tr>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">SID</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Client</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Type</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Status</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Added</th>
        </tr></thead>
        <tbody>
        <?php if (empty($recently_added_projects)): ?>
        <tr><td colspan="6" style="text-align:center;padding:24px;color:#94a3b8">No projects yet. Add one above.</td></tr>
        <?php else: foreach ($recently_added_projects as $rap): ?>
        <tr class="rap-row">
          <td style="padding:8px 10px"><span style="background:rgba(59,130,246,.1);color:#1b4fd8;font-family:monospace;font-size:11px;padding:2px 7px;border-radius:5px;font-weight:600"><?= htmlspecialchars($rap['survey_id']) ?></span></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:600"><?= htmlspecialchars($rap['project_name'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($rap['client_name'] ?? '—') ?></td>
          <td style="padding:8px 10px;font-size:11px;color:#64748b"><?= $rap['project_type']==='tp' ? 'Third Party' : 'Direct' ?></td>
          <td style="padding:8px 10px"><span class="pill <?= $rap['status']==='active' ? 'complete' : 'terminate' ?>"><?= ucfirst($rap['status'] ?? 'unknown') ?></span></td>
          <td style="padding:8px 10px;font-size:11px;color:#94a3b8;white-space:nowrap"><?= date('d M Y, H:i', strtotime($rap['created_at'].' UTC')) ?></td>
        </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
    <?php if (!empty($recently_added_projects)): ?>
    <div id="rapPagination" style="display:flex;justify-content:center;align-items:center;gap:6px;padding:14px;border-top:1px solid #eef1f6"></div>
    <?php endif; ?>
  </div>

</div>
</div><!-- /createproject -->

<!-- ════════ ALL PROJECTS TAB ════════ -->
<div class="tab-pane" id="tab-projects">
<div style="margin-top:16px">

  <div style="display:flex;gap:10px;margin-bottom:14px">
    <input type="text" id="projectSearchBox" placeholder="Search by project name, SID, or client.." style="flex:1;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;color:#1e293b;outline:none" oninput="filterProjectsTable()">
  </div>

  <div style="display:flex;justify-content:flex-end;margin-bottom:8px">
    <?php if (exz_is_superadmin()): ?><button type="button" onclick="bulkDeleteProjects()" style="background:rgba(239,68,68,.15);color:#dc2626;border:none;border-radius:8px;padding:10px 18px;font-size:12px;font-weight:600;cursor:pointer">🗑 Delete Selected</button><?php endif; ?>
  </div>
  <form id="projectBulkForm" method="POST">
    <input type="hidden" name="bulk_delete_projects" value="1">
    <input type="hidden" name="project_sids" id="projectSidsInput">
  </form>

  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">All Projects</div><div class="tbl-count"><?= count($projects_full) ?> projects</div></div>
    <div class="tbl-wrap">
      <table style="width:100%">
        <thead><tr>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left"><input type="checkbox" onclick="toggleAllProjects(this)"></th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">📌</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">SID</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Parent SID</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Client</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">CPI / Vendor Cost</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Completes / Target</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left" title="Total clicks/entries, and how many started but have no final status yet">Starts / Dropout</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left" title="Incomplete/Terminate, Quota-full, Duplicate, Quality-fail">IC / Q / D / QC</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Vendors Assigned</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Status</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Actions</th>
        </tr></thead>
        <tbody>
        <?php $color_opts=['red'=>'#ef4444','orange'=>'#f97316','yellow'=>'#f59e0b','green'=>'#22c55e','blue'=>'#3b82f6','purple'=>'#8b5cf6']; ?>
        <?php foreach($projects_hierarchical as $p):
            $border = !empty($p['color_tag']) && isset($color_opts[$p['color_tag']]) ? 'border-left:4px solid '.$color_opts[$p['color_tag']] : '';
            $is_group_parent = !empty($p['_is_group_parent']);
            $is_child_row    = !empty($p['_is_child_row']);
            $row_style = $border;
            if ($is_group_parent) $row_style .= ';background:#f8faff';
            if ($is_child_row)    $row_style .= ';background:#fcfdff';
        ?>
        <tr style="<?= $row_style ?>" class="project-row<?= $is_child_row ? ' project-child-row' : '' ?>"
            <?= $is_child_row ? 'data-parent-group="'.htmlspecialchars($p['_parent_row_sid']).'"' : '' ?>
            data-search="<?= htmlspecialchars(strtolower(($p['project_name'] ?? '').' '.$p['survey_id'].' '.($p['client_row']['client_name'] ?? ''))) ?>">
          <td style="padding:8px 10px"><input type="checkbox" class="project-chk" value="<?= htmlspecialchars($p['survey_id']) ?>"></td>
          <td style="padding:8px 10px">
            <a href="?pin_project=<?= urlencode($p['survey_id']) ?>#projects" style="text-decoration:none;font-size:14px"><?= !empty($p['is_pinned']) ? '📌' : '📍' ?></a>
          </td>
          <td style="padding:8px 10px">
            <span style="background:rgba(59,130,246,.1);color:#1b4fd8;font-family:monospace;font-size:11px;padding:2px 7px;border-radius:5px;font-weight:600"><?= htmlspecialchars($p['survey_id']) ?></span>
          </td>
          <td style="padding:8px 10px">
            <?php if ($is_child_row): ?>
            <span style="font-family:monospace;font-size:11px;color:#94a3b8"><?= htmlspecialchars($p['_parent_row_sid']) ?></span>
            <?php elseif (!empty($p['_orphaned_parent_sid'])): ?>
            <span style="font-family:monospace;font-size:11px;color:#dc2626" title="Parent no longer exists"><?= htmlspecialchars($p['_orphaned_parent_sid']) ?> ⚠</span>
            <?php else: ?>
            <span style="background:rgba(245,158,11,.12);color:#b45309;font-size:9px;padding:2px 7px;border-radius:5px;font-weight:600;letter-spacing:.5px">ROOT</span>
            <?php endif; ?>
          </td>
          <td style="padding:8px 10px<?= $is_group_parent ? ';cursor:pointer' : '' ?>"<?= $is_group_parent ? ' onclick="toggleProjectChildren(\''.htmlspecialchars($p['survey_id'], ENT_QUOTES).'\', this.querySelector(\'.proj-chevron\'))" title="Click to expand/collapse children"' : '' ?>>
            <?php if ($is_group_parent): ?>
            <span class="proj-chevron" style="font-size:11px;color:#64748b;margin-right:4px;display:inline-block;width:12px" title="Expand/collapse children">▾</span>
            <?php elseif ($is_child_row): ?>
            <span style="color:#94a3b8;margin-right:4px">└─</span>
            <?php endif; ?>
            <strong<?= $is_group_parent ? ' style="font-size:13px"' : '' ?>><?= htmlspecialchars($p['project_name'] ?: $p['survey_id']) ?></strong>
            <?php if ($is_group_parent): ?>
            <span class="pill" style="background:rgba(59,130,246,.1);color:#1b4fd8;border:1px solid rgba(59,130,246,.25);font-size:9px;margin-left:4px">Parent · <?= intval($p['_child_count']) ?> <?= $p['_child_count']==1?'child':'children' ?></span>
            <?php elseif ($is_child_row): ?>
            <span class="pill" style="background:rgba(148,163,184,.15);color:#64748b;border:1px solid rgba(148,163,184,.3);font-size:9px;margin-left:4px">Child of <?= htmlspecialchars($p['_parent_row_sid']) ?></span>
            <?php elseif (!empty($p['_orphaned_parent_sid'])): ?>
            <span class="pill" style="background:rgba(239,68,68,.1);color:#dc2626;border:1px solid rgba(239,68,68,.3);font-size:9px;margin-left:4px" title="Its parent project no longer exists">⚠ orphaned (was child of <?= htmlspecialchars($p['_orphaned_parent_sid']) ?>)</span>
            <?php endif; ?>
            <form method="POST" style="margin-top:4px" onclick="event.stopPropagation()">
              <input type="hidden" name="set_project_color" value="1">
              <input type="hidden" name="pc_sid" value="<?= htmlspecialchars($p['survey_id']) ?>">
              <select name="color_tag" onchange="this.form.submit()" style="font-size:10px;padding:2px">
                <option value="">Color tag</option>
                <?php foreach($color_opts as $val=>$hex): ?>
                <option value="<?= $val ?>" <?= ($p['color_tag']??'')===$val?'selected':'' ?>><?= ucfirst($val) ?></option>
                <?php endforeach; ?>
              </select>
            </form>
          </td>
          <td style="padding:8px 10px;font-size:12px"><?= $p['client_row'] ? htmlspecialchars($p['client_row']['client_name']) : '—' ?></td>
          <td style="padding:8px 10px;font-size:12px">$<?= number_format($p['cpi'],2) ?> / $<?= number_format($p['vendor_cost'],2) ?></td>
          <td style="padding:8px 10px;font-size:12px">
            <?= intval($p['live_completes']) ?> / <?= intval($p['target']) ?: '—' ?>
            <?php if (intval($p['target']) > 0): $pct = min(100, round(intval($p['live_completes'])/intval($p['target'])*100)); ?>
            <div style="background:#e2e8f0;border-radius:6px;height:5px;margin-top:4px;overflow:hidden">
              <div style="background:<?= $pct>=100?'#22c55e':($pct>=70?'#f59e0b':'#3b82f6') ?>;height:100%;width:<?= $pct ?>%"></div>
            </div>
            <div style="font-size:9px;color:#94a3b8;margin-top:2px"><?= $pct ?>%</div>
            <?php endif; ?>
          </td>
          <td style="padding:8px 10px;font-size:11px;white-space:nowrap">
            <span style="font-weight:600"><?= intval($p['live_starts']) ?></span> /
            <span style="color:#94a3b8" title="Started but no final status yet"><?= intval($p['live_dropout']) ?></span>
          </td>
          <td style="padding:8px 10px;font-size:11px;white-space:nowrap">
            <span style="color:#f59e0b" title="Incomplete/Terminate"><?= intval($p['live_terminates']) ?></span> /
            <span style="color:#3b82f6" title="Quota-full"><?= intval($p['live_quotafull']) ?></span> /
            <span style="color:#a855f7" title="Duplicate"><?= intval($p['live_duplicates']) ?></span> /
            <span style="color:#ef4444" title="Quality-fail"><?= intval($p['live_quality']) ?></span>
          </td>
          <td style="padding:8px 10px;font-size:11px">
            <?php if(empty($p['vendors'])): ?><span style="color:#94a3b8">None assigned</span><?php else: foreach($p['vendors'] as $pv): ?>
            <span class="pill" style="background:rgba(59,130,246,.1);color:#1b4fd8;border:1px solid rgba(59,130,246,.25);margin:1px"><?= htmlspecialchars($pv['vendor_name']) ?>
              <span onclick="showVendorLinks('<?= htmlspecialchars(addslashes($pv['vendor_name'])) ?>','<?= htmlspecialchars($p['survey_id']) ?>','<?= $pv['id'] ?>','<?= htmlspecialchars($pv['short_code'] ?? '') ?>')" style="color:#1b4fd8;text-decoration:none;cursor:pointer" title="Get entry link">🔗</span>
              <a href="?unassign_vendor=<?= $pv['id'] ?>&sid=<?= urlencode($p['survey_id']) ?>#projects" style="color:#dc2626;text-decoration:none">✕</a></span>
            <?php endforeach; endif; ?>
            <form method="POST" style="margin-top:4px;display:flex;gap:3px">
              <input type="hidden" name="assign_vendor" value="1">
              <input type="hidden" name="av_sid" value="<?= htmlspecialchars($p['survey_id']) ?>">
              <select name="av_vendor" style="font-size:10px;padding:2px">
                <option value="">+ Assign vendor</option>
                <?php foreach($master_vendors as $mv): ?>
                <option value="<?= $mv['id'] ?>"><?= htmlspecialchars($mv['vendor_name']) ?></option>
                <?php endforeach; ?>
              </select>
              <button type="submit" style="font-size:10px;padding:2px 6px;border:1px solid #e2e8f0;border-radius:4px;background:#fff;cursor:pointer">Add</button>
            </form>
          </td>
          <td style="padding:8px 10px">
            <?php $display_status = $is_group_parent ? $p['_derived_status'] : $p['status']; ?>
            <span class="pill <?= in_array($display_status,['active','complete'])?'complete':'terminate' ?>"><?= ucfirst($display_status) ?></span>
          </td>
          <td style="padding:8px 10px">
            <div style="display:flex;gap:5px;flex-wrap:wrap">
              <a href="project_view.php?sid=<?= urlencode($p['survey_id']) ?>" class="btn-sm btn-blue">View</a>
              <a href="?toggle_project=<?= urlencode($p['survey_id']) ?>#projects" class="btn-sm <?= $p['status']==='active'?'btn-amber':'btn-green' ?>" style="<?= $p['status']==='active' ? 'background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff' : '' ?>"><?= $p['status']==='active'?'⏸ Pause':'▶ Resume' ?></a>
              <a href="?duplicate_project=<?= urlencode($p['survey_id']) ?>#projects" class="btn-sm btn-blue" onclick="return confirm('Duplicate this project?')">⧉ Copy</a>
              <a href="?delete_project=<?= urlencode($p['survey_id']) ?>#projects" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Delete this project?')">Del</a>
            </div>
          </td>
        </tr>
        <?php endforeach; if(empty($projects_full)): ?>
        <tr><td colspan="13" style="text-align:center;padding:28px;color:#94a3b8">No projects yet. Add one above.</td></tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
</div><!-- /projects -->

<!-- ════════ RESPONSES TAB ════════ -->
<div class="tab-pane" id="tab-responses">
<div class="filters-row" style="margin-top:16px">
  <select class="fsel" id="fSt" onchange="ft()">
    <option value="">All Statuses</option>
    <option value="complete">Complete</option>
    <option value="terminate">Terminate</option>
    <option value="quotafull">Quota Full</option>
    <option value="qc">Quality Fail (qc)</option>
    <option value="quality">Quality Fail (quality)</option>
    <option value="unmatched">Unmatched</option>
    <option value="pending">Pending</option>
    <option value="click_only">Click Only</option>
  </select>
  <select class="fsel" id="fPr" onchange="ft()">
    <option value="">All Projects</option>
    <?php foreach($projects as $p): ?>
    <option value="<?= htmlspecialchars($p['survey_id']) ?>"><?= htmlspecialchars($p['survey_id']) ?></option>
    <?php endforeach; ?>
  </select>
  <select class="fsel" id="fDv" onchange="ft()">
    <option value="">All Devices</option>
    <option value="mobile">Mobile</option>
    <option value="desktop">Desktop</option>
    <option value="tablet">Tablet</option>
  </select>
  <select class="fsel" id="fSrc" onchange="ft()">
    <option value="">All Sources</option>
    <option value="direct">Direct</option>
    <option value="thirdparty">Third Party</option>
  </select>
  <select class="fsel" id="fCl" onchange="ft()">
    <option value="">All Clients</option>
    <?php foreach($master_clients as $mc): ?>
    <option value="<?= htmlspecialchars(strtolower($mc['client_name'])) ?>"><?= htmlspecialchars($mc['client_name']) ?></option>
    <?php endforeach; ?>
  </select>
  <select class="fsel" id="fVd" onchange="ft()">
    <option value="">All Vendors</option>
    <?php foreach($master_vendors as $mv): ?>
    <option value="<?= $mv['id'] ?>"><?= htmlspecialchars($mv['vendor_name']) ?></option>
    <?php endforeach; ?>
  </select>
  <input class="fsrch" id="fsrch" placeholder="Search UID, client, country, city..." oninput="ft()">
  <input type="date" class="fsel" id="fDateFrom" style="max-width:135px" title="From date">
  <input type="date" class="fsel" id="fDateTo" style="max-width:135px" title="To date">
  <a href="?export=csv" id="csvExportLink" class="btn-sm btn-green" onclick="return buildExportUrl(this,'csv')">⬇ CSV</a>
  <a href="?export=json" id="jsonExportLink" class="btn-sm btn-blue" onclick="return buildExportUrl(this,'json')">⬇ JSON</a>
  <a href="?export=xlsx" id="xlsxExportLink" class="btn-sm" style="background:#16a34a;color:#fff" onclick="return buildExportUrl(this,'xlsx')">⬇ Excel</a>
</div>
<script>
function buildExportUrl(el, kind){
  var params = new URLSearchParams();
  params.set('export', kind);
  var st = document.getElementById('fSt').value; if (st) params.set('estat', st);
  var pr = document.getElementById('fPr').value; if (pr) params.set('esid', pr);
  var sc = document.getElementById('fSrc').value; if (sc) params.set('esrc', sc);
  var vd = document.getElementById('fVd').value; if (vd) params.set('evid', vd);
  var df = document.getElementById('fDateFrom').value; if (df) params.set('edatefrom', df);
  var dt = document.getElementById('fDateTo').value; if (dt) params.set('edateto', dt);
  el.href = '?' + params.toString();
  return true;
}
</script>

<!-- Per-project CSV export -->
<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
  <?php foreach($projects as $p): ?>
  <a href="?export=csv&esid=<?= urlencode($p['survey_id']) ?>" class="btn-sm" style="background:#e2e8f0;color:#374151;font-size:10px">
    ⬇ <?= htmlspecialchars($p['survey_id']) ?>
  </a>
  <?php endforeach; ?>
</div>

<div class="tbl-card">
  <div class="tbl-head">
    <div class="tbl-title">Response Log</div>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <div class="tbl-count" id="rowCount"><?= count($rows) ?> responses</div>
      <button onclick="selAll(true)" style="background:rgba(255,255,255,.08);color:var(--muted);border:1px solid rgba(255,255,255,.15);border-radius:5px;padding:3px 9px;font-size:10px;cursor:pointer">Select All</button>
      <button onclick="selAll(false)" style="background:rgba(255,255,255,.08);color:var(--muted);border:1px solid rgba(255,255,255,.15);border-radius:5px;padding:3px 9px;font-size:10px;cursor:pointer">Clear</button>
      <?php if (exz_is_superadmin()): ?><button onclick="confirmDelete()" style="background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.35);border-radius:5px;padding:3px 11px;font-size:10px;font-weight:600;cursor:pointer">🗑️ Delete Selected</button><?php endif; ?>
    </div>
  </div>
  <form method="POST" id="delForm">
    <input type="hidden" name="delete_responses" value="1">
  <div class="tbl-wrap">
  <table id="mainTbl">
    <thead><tr>
      <th style="width:32px"><input type="checkbox" id="chkAll" onchange="selAll(this.checked)" style="cursor:pointer"></th>
      <th>#</th><th>Status</th><th>Respondent ID</th><th>Encrypted ID</th><th>Survey ID</th>
      <th>Source</th><th>Client</th><th>Device</th><th>Country</th><th>City</th>
      <th>LOI</th><th>IP</th><th>Date</th><th>Time</th><th>View</th>
    </tr></thead>
    <tbody>
    <?php foreach($rows as $i=>$r):
      $loi   = isset($r['loi_seconds']) ? intval($r['loi_seconds']) : null;
      $isspd = $loi !== null && $loi > 0 && $loi < SPEEDER_THRESHOLD && $r['status']==='complete';
      $st    = ($r['status']==='quality') ? 'qc' : $r['status'];
      $is_synthetic = ($r['id'] === null);
      $status_label = $st === 'click_only' ? 'Click Only' : ucfirst($r['status']);
    ?>
    <tr class="<?= $isspd?'spd-row':'' ?>"
        data-st="<?= htmlspecialchars($st) ?>"
        data-pr="<?= strtolower(htmlspecialchars($r['survey_id'])) ?>"
        data-dv="<?= strtolower($r['device']??'') ?>"
        data-src="<?= strtolower(htmlspecialchars($r['source']??'')) ?>"
        data-srctype="<?= (empty($r['source']) || strtolower($r['source'])==='direct') ? 'direct' : 'thirdparty' ?>"
        data-cl="<?= strtolower(htmlspecialchars($r['client_name']??'')) ?>"
        data-vd="<?= intval($r['vendor_id'] ?? 0) ?>"
        data-s="<?= strtolower(htmlspecialchars(($r['respondent']??'').'|'.($r['original_uid']??'').'|'.($r['client_name']??'').'|'.($r['country']??'').'|'.($r['city']??''))) ?>">
      <td><?php if ($is_synthetic): ?><input type="checkbox" name="del_ids[]" value="start:<?= htmlspecialchars($r['survey_id']) ?>:<?= htmlspecialchars($r['respondent']) ?>" class="del-chk" style="cursor:pointer" title="Deletes the entry record — this respondent's click/traffic history"><?php else: ?><input type="checkbox" name="del_ids[]" value="<?= intval($r['id']) ?>" class="del-chk" style="cursor:pointer"><?php endif; ?></td>
      <td style="color:#94a3b8"><?= $i+1 ?></td>
      <td>
        <span class="pill <?= $st ?>"><?= $status_label ?></span>
        <?= ($r['is_duplicate']??0) ? '<span class="tag tag-dup">DUP</span>' : '' ?>
        <?= $isspd ? '<span class="tag tag-spd">⚡SPD</span>' : '' ?>
      </td>
      <td class="mono">
        <?php if (!empty($r['original_uid']) && $r['original_uid'] !== $r['respondent']): ?>
        <?= htmlspecialchars($r['original_uid']) ?>
        <?php else: ?>
        <?= htmlspecialchars($r['respondent']) ?>
        <?php endif; ?>
      </td>
      <td class="mono" style="color:#94a3b8;font-size:10px">
        <?php if (!empty($r['original_uid']) && $r['original_uid'] !== $r['respondent']): ?>
        🔒 <?= htmlspecialchars($r['respondent']) ?>
        <?php else: ?>
        —
        <?php endif; ?>
      </td>
      <td><b style="font-family:'Bebas Neue',sans-serif;color:var(--blue)"><?= htmlspecialchars($r['survey_id']) ?></b></td>
      <td><?= htmlspecialchars($r['source']??'—') ?></td>
      <td><?= htmlspecialchars($r['client_name']??'—') ?></td>
      <td><?= htmlspecialchars($r['device']??'—') ?></td>
      <td><?= htmlspecialchars($r['country']??'—') ?></td>
      <td style="color:#94a3b8"><?= htmlspecialchars($r['city']??'—') ?></td>
      <td class="<?= loi_cls($loi) ?>"><?= fmt_loi($loi) ?></td>
      <td class="mono" style="color:#94a3b8"><?= htmlspecialchars($r['ip']??'') ?></td>
      <td><?= date('d M Y',strtotime($r['created_at'].' UTC')) ?></td>
      <td class="mono"><?= date('H:i:s',strtotime($r['created_at'].' UTC')) ?></td>
      <td><a href="respondent_view.php?uid=<?= urlencode($r['respondent']) ?>&sid=<?= urlencode($r['survey_id']) ?>" class="btn-sm btn-blue" style="font-size:10px">View</a></td>
    </tr>
    <?php endforeach; if(empty($rows)): ?>
    <tr><td colspan="15" style="text-align:center;padding:28px;color:#94a3b8;font-style:italic">No responses yet.</td></tr>
    <?php endif; ?>
    </tbody>
  </table>
  </div>
  </form>
</div>
</div><!-- /responses -->

<!-- ════════ FRAUD TAB ════════ -->
<div class="tab-pane" id="tab-fraud">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px">
<div>
  <div class="sec-title">⚡ Speeders — LOI &lt; 3 Min</div>
  <?php if(empty($speeders_list)): ?>
  <div class="chart-card" style="color:#94a3b8;font-size:13px;text-align:center;padding:28px">No speeders — great quality! ✅</div>
  <?php else: ?>
  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">Speeder Log</div><div class="tbl-count"><?= count($speeders_list) ?> flagged</div></div>
    <div class="tbl-wrap"><table><thead><tr><th>UID</th><th>Survey</th><th>Status</th><th>LOI</th><th>Country</th><th>Device</th><th>Time</th></tr></thead><tbody>
    <?php foreach($speeders_list as $r): ?>
    <tr><td class="mono loi-red"><?= htmlspecialchars($r['respondent']) ?></td>
    <td><b style="color:var(--blue)"><?= htmlspecialchars($r['survey_id']) ?></b></td>
    <td><span class="pill <?= $r['status']==='quality'?'qc':$r['status'] ?>"><?= ucfirst($r['status']) ?></span></td>
    <td class="loi-red"><?= fmt_loi($r['loi_seconds']) ?></td>
    <td><?= htmlspecialchars($r['country']??'—') ?></td>
    <td><?= htmlspecialchars($r['device']??'—') ?></td>
    <td style="color:#94a3b8"><?= date('d M H:i',strtotime($r['created_at'].' UTC')) ?></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>
  </div>
  <?php endif; ?>
</div>
<div>
  <div class="sec-title">⚠️ Duplicate UIDs</div>
  <?php if(empty($dup_rows)): ?>
  <div class="chart-card" style="color:#94a3b8;font-size:13px;text-align:center;padding:28px">No duplicates detected. ✅</div>
  <?php else: ?>
  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">Duplicate Log</div><div class="tbl-count"><?= count($dup_rows) ?> flagged</div></div>
    <div class="tbl-wrap"><table><thead><tr><th>UID</th><th>Survey</th><th>Status</th><th>LOI</th><th>IP</th><th>Time</th></tr></thead><tbody>
    <?php foreach($dup_rows as $r): ?>
    <tr><td class="mono" style="color:#b45309"><?= htmlspecialchars($r['respondent']) ?></td>
    <td><b style="color:var(--blue)"><?= htmlspecialchars($r['survey_id']) ?></b></td>
    <td><span class="pill <?= $r['status']==='quality'?'qc':$r['status'] ?>"><?= ucfirst($r['status']) ?></span></td>
    <td><?= fmt_loi($r['loi_seconds']) ?></td>
    <td class="mono" style="color:#94a3b8"><?= htmlspecialchars($r['ip']??'') ?></td>
    <td style="color:#94a3b8"><?= date('d M H:i',strtotime($r['created_at'].' UTC')) ?></td></tr>
    <?php endforeach; ?>
    </tbody></table></div>
  </div>
  <?php endif; ?>
</div>
</div>
<!-- Ghost Entries — no matching entry-link record -->
<div class="sec-title" style="margin-top:20px">👻 Ghost Entries — No Entry-Link Record</div>
<div style="font-size:12px;color:#64748b;margin-bottom:14px">These completions/terminates arrived without ever going through your real entry link (vendor.php) — someone hit the completion URL directly. They are saved here for audit but are NOT counted in your normal stats, and no vendor postback was sent for them. Check the IP and time to trace who it was.</div>
<?php if(empty($ghost_entries)): ?>
<div class="chart-card" style="color:#94a3b8;font-size:13px;text-align:center;padding:28px">No ghost entries detected. ✅</div>
<?php else: ?>
<div class="tbl-card" style="margin-bottom:16px">
  <div class="tbl-head"><div class="tbl-title">Ghost Entry Log</div><div class="tbl-count"><?= count($ghost_entries) ?> flagged</div></div>
  <div class="tbl-wrap"><table><thead><tr><th>UID</th><th>Survey</th><th>Status</th><th>IP</th><th>Country</th><th>Device</th><th>Time</th></tr></thead><tbody>
  <?php foreach($ghost_entries as $r): ?>
  <tr><td class="mono" style="color:#dc2626"><?= htmlspecialchars($r['respondent']) ?></td>
  <td><b style="color:var(--blue)"><?= htmlspecialchars($r['survey_id']) ?></b></td>
  <td><span class="pill <?= $r['status']==='quality'?'qc':$r['status'] ?>"><?= ucfirst($r['status']) ?></span></td>
  <td class="mono" style="color:#94a3b8"><?= htmlspecialchars($r['ip']??'') ?></td>
  <td><?= htmlspecialchars($r['country']??'—') ?></td>
  <td><?= htmlspecialchars($r['device']??'—') ?></td>
  <td style="color:#94a3b8"><?= date('d M H:i',strtotime($r['created_at'].' UTC')) ?></td></tr>
  <?php endforeach; ?>
  </tbody></table></div>
</div>
<?php endif; ?>
<!-- Same-IP Fraud Detection -->
<div class="sec-title" style="margin-top:20px">🕵️ Same-IP Fraud Detection</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">Same IP — Multiple UIDs (one project)</div><div class="tbl-count"><?= count($ip_same_project) ?> flagged</div></div>
    <?php if(empty($ip_same_project)): ?>
    <div style="color:#94a3b8;font-size:13px;text-align:center;padding:24px">No same-IP-multi-UID pattern detected. ✅</div>
    <?php else: ?>
    <div class="tbl-wrap"><table style="width:100%"><thead><tr>
      <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">IP</th>
      <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project</th>
      <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">UIDs</th>
    </tr></thead><tbody>
    <?php foreach($ip_same_project as $r): ?>
    <tr>
      <td style="padding:8px 10px;font-size:11px;font-family:monospace;color:#94a3b8"><?= htmlspecialchars($r['ip']) ?></td>
      <td style="padding:8px 10px;font-size:12px"><b style="color:var(--blue)"><?= htmlspecialchars($r['survey_id']) ?></b></td>
      <td style="padding:8px 10px;font-size:11px"><span class="pill terminate"><?= $r['uid_count'] ?> UIDs</span> <?= htmlspecialchars($r['uids']) ?></td>
    </tr>
    <?php endforeach; ?>
    </tbody></table></div>
    <?php endif; ?>
  </div>
  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">Same IP — Across Multiple Projects</div><div class="tbl-count"><?= count($ip_cross_project) ?> flagged</div></div>
    <?php if(empty($ip_cross_project)): ?>
    <div style="color:#94a3b8;font-size:13px;text-align:center;padding:24px">No cross-project same-IP pattern detected. ✅</div>
    <?php else: ?>
    <div class="tbl-wrap"><table style="width:100%"><thead><tr>
      <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">IP</th>
      <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Projects</th>
    </tr></thead><tbody>
    <?php foreach($ip_cross_project as $r): ?>
    <tr>
      <td style="padding:8px 10px;font-size:11px;font-family:monospace;color:#94a3b8"><?= htmlspecialchars($r['ip']) ?></td>
      <td style="padding:8px 10px;font-size:11px"><span class="pill terminate"><?= $r['proj_count'] ?> projects</span> <?= htmlspecialchars($r['sids']) ?></td>
    </tr>
    <?php endforeach; ?>
    </tbody></table></div>
    <?php endif; ?>
  </div>
</div>

<!-- Quality Risk Summary -->
<div class="chart-card" style="margin-top:16px">
  <div class="chart-title">Quality Risk Summary</div>
  <?php $tf=intval($stats['speeders']??0)+intval($stats['duplicates']??0)+intval($stats['quality']??0);
  $fr=$stats['total']>0?round($tf/$stats['total']*100,1):0; ?>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px">
    <div style="text-align:center"><div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:<?= ($stats['speeders']??0)>0?'var(--red)':'var(--green)' ?>"><?= $stats['speeders']??0 ?></div><div class="stat-lbl">Speeders</div></div>
    <div style="text-align:center"><div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:<?= ($stats['duplicates']??0)>0?'var(--yellow)':'var(--green)' ?>"><?= $stats['duplicates']??0 ?></div><div class="stat-lbl">Duplicates</div></div>
    <div style="text-align:center"><div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:var(--purple)"><?= $stats['quality']??0 ?></div><div class="stat-lbl">Quality Fails</div></div>
    <div style="text-align:center"><div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:<?= $fr>10?'var(--red)':($fr>5?'var(--yellow)':'var(--green)') ?>"><?= $fr ?>%</div><div class="stat-lbl">Flag Rate</div></div>
  </div>
</div>
</div><!-- /fraud -->

<!-- ════════ VENDORS TAB ════════ -->
<div class="tab-pane" id="tab-vendors">
<div style="margin-top:16px">
<div class="sec-title">👥 Vendors</div>

<!-- STATS -->
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px">
  <div class="stat-card"><div class="stat-num navy"><?= $vendor_total_clicks ?></div><div class="stat-lbl">Total Clicks (All Vendors)</div></div>
  <div class="stat-card"><div class="stat-num green"><?= $vendor_total_completes ?></div><div class="stat-lbl">Total Completes</div></div>
  <div class="stat-card"><div class="stat-num blue"><?= $vendor_total_clicks>0 ? round($vendor_total_completes/$vendor_total_clicks*100,1) : 0 ?>%</div><div class="stat-lbl">Overall Conversion</div></div>
  <div class="stat-card"><div class="stat-num orange">
    <?php
      $top_vendor = '—'; $top_conv = 0;
      foreach($master_vendors as $mv){
        $vs = $vendor_stats[$mv['id']] ?? null;
        if($vs && $vs['clicks']>0){ $c = round($vs['completes']/$vs['clicks']*100,1); if($c>$top_conv){$top_conv=$c;$top_vendor=$mv['vendor_name'];} }
      }
      echo htmlspecialchars($top_vendor);
    ?>
  </div><div class="stat-lbl">Top Vendor (by Conv%)</div></div>
</div>

<div style="display:flex;justify-content:flex-end;gap:8px;margin-bottom:12px">
  <?php if (exz_is_superadmin()): ?><button type="button" onclick="bulkDeleteVendors()" style="background:rgba(239,68,68,.15);color:#dc2626;border:none;border-radius:8px;padding:10px 18px;font-size:12px;font-weight:600;cursor:pointer">🗑 Delete Selected</button><?php endif; ?>
  <button type="button" onclick="openVendorModal()" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">+ Add Vendor</button>
</div>

<div style="margin-bottom:12px">
  <input type="text" id="vendorSearchBox" placeholder="🔍 Search vendors by name or email..." oninput="filterVendorTable(this.value)"
    style="width:100%;max-width:340px;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
</div>

<form id="vendorBulkForm" method="POST">
  <input type="hidden" name="bulk_delete_vendors" value="1">
  <input type="hidden" name="vendor_ids" id="vendorIdsInput">
</form>

<div class="tbl-card" style="margin-bottom:18px">
  <div class="tbl-head"><div class="tbl-title">All Vendors</div><div class="tbl-count"><?= count($master_vendors) ?> vendors</div></div>
  <div class="tbl-wrap">
    <table style="width:100%">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left"><input type="checkbox" onclick="toggleAllVendors(this)"></th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">#</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Vendor</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Email</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Panel Size</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Total Proj</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Clicks</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Completes</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Terminates</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Conv%</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Status</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Actions</th>
      </tr></thead>
      <tbody>
      <?php if(empty($master_vendors)): ?>
      <tr><td colspan="12" style="text-align:center;padding:24px;color:#94a3b8">No vendors yet. Add one above.</td></tr>
      <?php else: foreach($master_vendors as $i=>$mv):
        $vs = $vendor_stats[$mv['id']] ?? ['clicks'=>0,'completes'=>0,'terminates'=>0,'total_projects'=>0];
        $conv = $vs['clicks']>0 ? round($vs['completes']/$vs['clicks']*100,1).'%' : '—';
      ?>
      <tr data-vname="<?= htmlspecialchars(strtolower($mv['vendor_name'] . ' ' . ($mv['email'] ?? ''))) ?>">
        <td style="padding:8px 10px"><input type="checkbox" class="vendor-chk" value="<?= $mv['id'] ?>"></td>
        <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
        <td style="padding:8px 10px"><strong><a href="vendor_view.php?vid=<?= $mv['id'] ?>" style="color:var(--blue2);text-decoration:none"><?= htmlspecialchars($mv['vendor_name']) ?></a></strong></td>
        <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($mv['email'] ?: '—') ?></td>
        <td style="padding:8px 10px;font-size:12px"><?= !empty($mv['panel_size']) ? number_format($mv['panel_size']) : '—' ?></td>
        <td style="padding:8px 10px;font-size:12px;font-weight:600"><?= $vs['total_projects'] ?? 0 ?></td>
        <td style="padding:8px 10px;font-size:12px"><?= $vs['clicks'] ?></td>
        <td style="padding:8px 10px;font-size:12px"><?= $vs['completes'] ?></td>
        <td style="padding:8px 10px;font-size:12px"><?= $vs['terminates'] ?></td>
        <td style="padding:8px 10px;font-size:12px"><?= $conv ?></td>
        <td style="padding:8px 10px"><span class="pill <?= ($mv['status']??'active')==='active'?'complete':'terminate' ?>"><?= ucfirst($mv['status'] ?? 'active') ?></span></td>
        <td style="padding:8px 10px">
          <div style="display:flex;gap:5px">
            <button type="button" class="btn-sm btn-blue" onclick="openVendorModal(<?= htmlspecialchars(json_encode($mv), ENT_QUOTES) ?>)">Edit</button>
            <a href="?toggle_vendor=<?= $mv['id'] ?>#vendors" class="btn-sm" style="background:<?= ($mv['status']??'active')==='active' ? 'rgba(245,158,11,.15);color:#b45309' : 'rgba(34,197,94,.15);color:#16a34a' ?>" onclick="return confirm('<?= ($mv['status']??'active')==='active' ? 'Pause' : 'Activate' ?> <?= htmlspecialchars($mv['vendor_name']) ?>? This blocks/unblocks their traffic link across ALL projects immediately.')"><?= ($mv['status']??'active')==='active' ? '⏸ Pause' : '▶ Activate' ?></a>
            <a href="?del_vendor=<?= $mv['id'] ?>#vendors" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Delete <?= htmlspecialchars($mv['vendor_name']) ?>?')">Del</a>
          </div>
        </td>
      </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
</div>

<!-- ADD/EDIT VENDOR MODAL -->
<div class="modal-overlay" id="vendorModal">
  <div class="modal" style="max-width:560px;max-height:85vh;overflow-y:auto">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <div style="font-family:'Bebas Neue',sans-serif;font-size:16px;letter-spacing:1px;color:var(--navy)">Add / Edit Vendor</div>
      <span onclick="closeVendorModal()" style="cursor:pointer;font-size:18px;color:#94a3b8">✕</span>
    </div>
    <form method="POST">
      <input type="hidden" name="save_vendor" value="1">
      <input type="hidden" name="v_id" id="vm_id" value="">
      <input type="hidden" name="v_contact" id="vm_contact" value="">
      <div style="margin-bottom:10px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Vendor Name *</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="v_name" id="vm_name" placeholder="e.g. Cint" required>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Email</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="email" name="v_email" id="vm_email" placeholder="vendor@example.com">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Phone</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="v_phone" id="vm_phone" placeholder="+91...">
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Panel Size</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="number" name="v_panel_size" id="vm_panel_size" placeholder="e.g. 500000">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Availability</div>
          <select style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" name="v_availability" id="vm_availability">
            <option value="open">Open</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>
      <div style="font-size:11px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin:14px 0 8px">Postback URLs — [UID]/[SID]/[LOI] placeholders supported</div>
      <div style="margin-bottom:10px">
        <div style="font-size:10px;color:#64748b;margin-bottom:4px">Complete URL</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:11px;color:#1e293b;outline:none" type="text" name="v_complete_url" id="vm_complete_url" placeholder="https://vendor.com/postback?status=complete&username=[UID]">
      </div>
      <div style="margin-bottom:10px">
        <div style="font-size:10px;color:#64748b;margin-bottom:4px">Terminate URL</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:11px;color:#1e293b;outline:none" type="text" name="v_terminate_url" id="vm_terminate_url" placeholder="https://vendor.com/postback?status=terminate&username=[UID]">
      </div>
      <div style="margin-bottom:10px">
        <div style="font-size:10px;color:#64748b;margin-bottom:4px">Screenout URL</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:11px;color:#1e293b;outline:none" type="text" name="v_screenout_url" id="vm_screenout_url" placeholder="https://vendor.com/postback?status=screenout&username=[UID]">
      </div>
      <div style="margin-bottom:10px">
        <div style="font-size:10px;color:#64748b;margin-bottom:4px">Quotafull URL</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:11px;color:#1e293b;outline:none" type="text" name="v_quotafull_url" id="vm_quotafull_url" placeholder="https://vendor.com/postback?status=quotafull&username=[UID]">
      </div>
      <div style="font-size:10px;color:#94a3b8;margin-bottom:14px">Available placeholders: [UID] (vendor's own respondent ID), [SID] (project ID), [LOI] (time taken in seconds, complete only). Leave blank if the vendor doesn't need a postback/redirect.</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">End Page Behavior</div>
          <select name="v_end_behavior" id="vm_end_behavior" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
            <option value="show_page">Show our page (postback in background) — recommended</option>
            <option value="redirect">Redirect straight to vendor's page</option>
          </select>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Status</div>
          <select name="v_status" id="vm_status" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">Save Vendor</button>
        <button type="button" onclick="closeVendorModal()" style="background:#f1f3f9;color:#475569;border:none;border-radius:8px;padding:10px 22px;font-size:13px;font-weight:600;cursor:pointer">Cancel</button>
      </div>
    </form>
  </div>
</div>
<script>
function filterVendorTable(q){
  q = q.toLowerCase().trim();
  document.querySelectorAll('tr[data-vname]').forEach(function(tr){
    tr.style.display = tr.getAttribute('data-vname').indexOf(q) !== -1 ? '' : 'none';
  });
}
function openVendorModal(mv){
  mv = mv || {};
  document.getElementById('vm_id').value = mv.id || '';
  document.getElementById('vm_contact').value = mv.contact_person || '';
  document.getElementById('vm_name').value = mv.vendor_name || '';
  document.getElementById('vm_email').value = mv.email || '';
  document.getElementById('vm_phone').value = mv.phone || '';
  document.getElementById('vm_complete_url').value = mv.complete_url || '';
  document.getElementById('vm_terminate_url').value = mv.terminate_url || '';
  document.getElementById('vm_screenout_url').value = mv.screenout_url || '';
  document.getElementById('vm_quotafull_url').value = mv.quotafull_url || '';
  document.getElementById('vm_end_behavior').value = mv.end_behavior || 'show_page';
  document.getElementById('vm_status').value = mv.status || 'active';
  document.getElementById('vm_panel_size').value = mv.panel_size || '';
  document.getElementById('vm_availability').value = mv.availability_status || 'open';
  document.getElementById('vendorModal').classList.add('open');
}
function toggleAllProjects(cb){
  document.querySelectorAll('.project-chk').forEach(c => c.checked = cb.checked);
}
function toggleProjectChildren(parentSid, chevronEl){
  var rows = document.querySelectorAll('.project-child-row[data-parent-group="' + CSS.escape(parentSid) + '"]');
  var collapsed = chevronEl.textContent.trim() === '▸';
  rows.forEach(r => r.style.display = collapsed ? '' : 'none');
  chevronEl.textContent = collapsed ? '▾' : '▸';
}
function toggleAllScreener(cb){
  document.querySelectorAll('.screener-chk').forEach(c => c.checked = cb.checked);
}
function bulkDeleteScreener(){
  const ids = Array.from(document.querySelectorAll('.screener-chk:checked')).map(c => c.value);
  if(ids.length === 0){ alert('Please select at least one answer.'); return; }
  if(!confirm('Delete all answers for ' + ids.length + ' respondent(s)?')) return;
  document.getElementById('screenerIdsInput').value = ids.join(',');
  document.getElementById('screenerBulkForm').submit();
}
// ── Recently Added Projects — client-side pagination (max 50 rows total,
// so no extra server round-trip needed; just slice/hide via JS) ────────
let rapPage = 1;
function rapRender(){
  const size = parseInt(document.getElementById('rapPageSize').value, 10);
  const rows = Array.from(document.querySelectorAll('#rapTable .rap-row'));
  const totalPages = Math.max(1, Math.ceil(rows.length / size));
  if (rapPage > totalPages) rapPage = totalPages;
  rows.forEach((row, i) => {
    const page = Math.floor(i / size) + 1;
    row.style.display = (page === rapPage) ? '' : 'none';
  });
  const start = rows.length === 0 ? 0 : (rapPage - 1) * size + 1;
  const end = Math.min(rapPage * size, rows.length);
  document.getElementById('rapCount').textContent = rows.length === 0 ? '0 shown' : `${start}–${end} of ${rows.length}`;

  const pagDiv = document.getElementById('rapPagination');
  if (!pagDiv) return;
  pagDiv.innerHTML = '';
  if (totalPages <= 1) return;
  const mkBtn = (label, page, disabled, active) => {
    const b = document.createElement('button');
    b.textContent = label;
    b.disabled = disabled;
    b.style.cssText = 'padding:5px 11px;font-size:11px;border-radius:6px;cursor:'+(disabled?'default':'pointer')+';border:1px solid #e2e8f0;background:'+(active?'#1b4fd8':'#fff')+';color:'+(active?'#fff':'#475569');
    b.onclick = () => { rapPage = page; rapRender(); };
    return b;
  };
  pagDiv.appendChild(mkBtn('← Prev', rapPage - 1, rapPage === 1, false));
  for (let p = 1; p <= totalPages; p++) pagDiv.appendChild(mkBtn(String(p), p, false, p === rapPage));
  pagDiv.appendChild(mkBtn('Next →', rapPage + 1, rapPage === totalPages, false));
}
document.addEventListener('DOMContentLoaded', function(){
  if (document.getElementById('rapPageSize')) rapRender();
});
function filterProjectsTable(){
  const q = document.getElementById('projectSearchBox').value.trim().toLowerCase();
  document.querySelectorAll('.project-row').forEach(row => {
    const hay = row.getAttribute('data-search') || '';
    row.style.display = (!q || hay.includes(q)) ? '' : 'none';
  });
}
function bulkDeleteProjects(){
  const ids = Array.from(document.querySelectorAll('.project-chk:checked')).map(c => c.value);
  if(ids.length === 0){ alert('Please select at least one project.'); return; }
  if(!confirm('Delete ' + ids.length + ' project(s)? This cannot be undone.')) return;
  document.getElementById('projectSidsInput').value = ids.join(',');
  document.getElementById('projectBulkForm').submit();
}
function closeVendorModal(){ document.getElementById('vendorModal').classList.remove('open'); }

function toggleAllVendors(cb){
  document.querySelectorAll('.vendor-chk').forEach(c => c.checked = cb.checked);
}
function bulkDeleteVendors(){
  const ids = Array.from(document.querySelectorAll('.vendor-chk:checked')).map(c => c.value);
  if(ids.length === 0){ alert('Please select at least one vendor.'); return; }
  if(!confirm('Delete ' + ids.length + ' vendor(s)? This cannot be undone.')) return;
  document.getElementById('vendorIdsInput').value = ids.join(',');
  document.getElementById('vendorBulkForm').submit();
}
</script>

<div class="sec-title">👥 Vendor / Source Scorecard</div>
<div class="tbl-card">
  <div class="tbl-head"><div class="tbl-title">Source Performance</div><div class="tbl-count"><?= count($vendors) ?> sources</div></div>
  <div class="tbl-wrap">
  <table><thead><tr><th>Source</th><th>Total</th><th>Completes</th><th>Term</th><th>CR%</th><th>IR%</th><th>Speeders</th><th>Dups</th><th>Avg LOI</th><th>Quality /100</th></tr></thead><tbody>
  <?php foreach($vendors as $v):
    $vcr  = $v['total']>0 ? round($v['completes']/$v['total']*100) : 0;
    $vir  = ($v['completes']+$v['terminates'])>0 ? round($v['completes']/($v['completes']+$v['terminates'])*100,1) : 0;
    $qs   = 100;
    if($v['total']>0){ $qs -= round($v['speeders']/$v['total']*40); $qs -= round($v['dups']/$v['total']*30); }
    $qs   = max(0,min(100,$qs));
    $qsc  = $qs>=80?'var(--green)':($qs>=60?'var(--yellow)':'var(--red)');
    $stars= $qs>=90?'⭐⭐⭐⭐⭐':($qs>=75?'⭐⭐⭐⭐':($qs>=60?'⭐⭐⭐':($qs>=40?'⭐⭐':'⭐')));
  ?>
  <tr>
    <td><strong><?= htmlspecialchars($v['source']) ?></strong></td>
    <td><?= $v['total'] ?></td>
    <td style="color:var(--green);font-weight:600"><?= $v['completes'] ?></td>
    <td style="color:var(--red)"><?= $v['terminates'] ?></td>
    <td><strong><?= $vcr ?>%</strong><div class="score-bar"><div class="score-fill" style="width:<?= $vcr ?>%;background:var(--blue2)"></div></div></td>
    <td style="color:var(--teal);font-weight:600"><?= $vir ?>%</td>
    <td style="color:<?= $v['speeders']>0?'var(--red)':'var(--green)' ?>"><?= $v['speeders'] ?></td>
    <td style="color:<?= $v['dups']>0?'var(--yellow)':'var(--green)' ?>"><?= $v['dups'] ?></td>
    <td class="<?= loi_cls($v['avg_loi']) ?>"><?= fmt_loi($v['avg_loi']) ?></td>
    <td><span style="font-family:'Bebas Neue',sans-serif;font-size:18px;color:<?= $qsc ?>"><?= $qs ?>/100</span><br><span style="font-size:10px"><?= $stars ?></span><div class="score-bar"><div class="score-fill" style="width:<?= $qs ?>%;background:<?= $qsc ?>"></div></div></td>
  </tr>
  <?php endforeach; if(empty($vendors)): ?>
  <tr><td colspan="10" style="text-align:center;padding:28px;color:#94a3b8">No source data yet.</td></tr>
  <?php endif; ?>
  </tbody></table>
  </div>
</div>
<div class="chart-card" style="margin-top:12px;font-size:12px;color:#64748b;line-height:1.8">
  <div class="chart-title" style="margin-bottom:6px">Quality Score Formula</div>
  Starts at <strong>100</strong>. Speeders (LOI&lt;3min) → -40pts · Duplicates → -30pts<br>
  ≥80 = Good ✅ &nbsp;|&nbsp; 60–79 = Average ⚠️ &nbsp;|&nbsp; &lt;60 = Poor 🚨
</div>
</div>
</div><!-- /vendors -->

<!-- ════════ ANALYTICS TAB ════════ -->
<div class="tab-pane" id="tab-charts">
<div class="charts-row2" style="margin-top:16px">
  <div class="chart-card"><div class="chart-title">Country Distribution (Top 10)</div><canvas id="countryChart" height="200"></canvas></div>
  <div class="chart-card"><div class="chart-title">Source / Vendor Traffic</div><canvas id="sourceChart" height="200"></canvas></div>
</div>
<div class="chart-card" style="margin-bottom:16px"><div class="chart-title">Daily Trend — Last 7 Days</div><canvas id="trendChart2" height="90"></canvas></div>
<div class="chart-card" style="margin-bottom:16px"><div class="chart-title">Hourly Response Rate — Today</div><canvas id="hrChart2" height="70"></canvas></div>
</div><!-- /charts -->

<!-- ════════ ALERTS TAB ════════ -->
<div class="tab-pane" id="tab-prescreentemplates">
<div style="margin-top:16px">
  <div class="sec-title">📋 PreScreen Template List</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Create a template, attach questions from the Question Library, then assign it to any project in 1 click.</div>

  <form method="POST" style="display:flex;gap:10px;margin-bottom:20px">
    <input type="hidden" name="save_template" value="1">
    <input type="text" name="t_name" required placeholder="Template Name — e.g. Healthcare, Gender, Age" style="flex:1;max-width:320px;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:9px 20px;font-size:12px;font-weight:600;cursor:pointer">+ Add Template</button>
  </form>

  <div class="tbl-card" style="overflow-x:auto;margin-bottom:24px">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">S.No</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Template Name</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">No. of Questions</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Action</th>
      </tr></thead>
      <tbody>
      <?php if(empty($prescreen_templates)): ?>
        <tr><td colspan="4" style="text-align:center;padding:24px;color:#94a3b8">No templates yet.</td></tr>
      <?php else: foreach($prescreen_templates as $i=>$t): ?>
        <tr style="<?= $editing_template_id==$t['id'] ? 'background:#eff6ff' : '' ?>">
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:600"><?= htmlspecialchars($t['template_name']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $template_qcounts[$t['id']] ?? 0 ?></td>
          <td style="padding:8px 10px;white-space:nowrap">
            <a href="?edit_template=<?= $t['id'] ?>#prescreentemplates" class="btn-sm btn-blue">Manage Questions</a>
            <a href="?delete_template=<?= $t['id'] ?>#prescreentemplates" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Delete template <?= htmlspecialchars(addslashes($t['template_name'])) ?>? Projects using it will fall back to the default questions.')">Del</a>
          </td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>

  <?php if ($editing_template_id): ?>
  <?php
    $et_name = '';
    foreach ($prescreen_templates as $t) if ($t['id']==$editing_template_id) $et_name = $t['template_name'];
    $attached_ids = array_column($editing_template_questions, 'id');
  ?>
  <div class="tbl-card" style="padding:18px">
    <div style="font-size:14px;font-weight:700;color:var(--navy);margin-bottom:14px">Managing: <?= htmlspecialchars($et_name) ?></div>

    <form method="POST" style="display:flex;gap:10px;margin-bottom:16px;align-items:center">
      <input type="hidden" name="attach_question" value="1">
      <input type="hidden" name="at_template_id" value="<?= $editing_template_id ?>">
      <select name="at_question_id" required style="flex:1;max-width:320px;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
        <option value="">— Select a question from the Library —</option>
        <?php foreach ($question_library as $q): if (in_array($q['id'], $attached_ids)) continue; ?>
        <option value="<?= $q['id'] ?>"><?= htmlspecialchars($q['title']) ?> — <?= htmlspecialchars(mb_strimwidth($q['question_text'],0,50,'...')) ?></option>
        <?php endforeach; ?>
      </select>
      <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:9px 18px;font-size:12px;font-weight:600;cursor:pointer">+ Attach</button>
    </form>

    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Order</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Title</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Question</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Type</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Action</th>
      </tr></thead>
      <tbody>
      <?php if(empty($editing_template_questions)): ?>
        <tr><td colspan="5" style="text-align:center;padding:20px;color:#94a3b8">No questions attached yet — select from above.</td></tr>
      <?php else: foreach($editing_template_questions as $i=>$eq): ?>
        <tr>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:600"><?= htmlspecialchars($eq['title']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($eq['question_text']) ?></td>
          <td style="padding:8px 10px;font-size:11px"><?= htmlspecialchars(ucfirst($eq['control_type'])) ?></td>
          <td style="padding:8px 10px">
            <a href="?detach_question=<?= $eq['link_id'] ?>&tid=<?= $editing_template_id ?>#prescreentemplates" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Remove this question from the template?')">Remove</a>
          </td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
  <?php endif; ?>
</div>
</div>

<div class="tab-pane" id="tab-pmtimereport">
<div style="margin-top:16px">
  <div class="sec-title">🕒 PM Time Report</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Total time given by each team member — combined across all projects.</div>

  <form method="GET" style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-end">
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">From</div>
      <input type="date" name="pmt_from" value="<?= htmlspecialchars($pmt_from) ?>" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    </div>
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">To</div>
      <input type="date" name="pmt_to" value="<?= htmlspecialchars($pmt_to) ?>" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    </div>
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:9px 20px;font-size:12px;font-weight:600;cursor:pointer">Filter</button>
    <?php if ($pmt_from || $pmt_to): ?><a href="index.php#pmtimereport" style="align-self:center;font-size:12px;color:#64748b">Clear</a><?php endif; ?>
  </form>

  <div class="tbl-card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Team Member</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Total Time</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Total Activities</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Projects Touched</th>
      </tr></thead>
      <tbody>
      <?php if(empty($pm_time_report)): ?>
        <tr><td colspan="4" style="text-align:center;padding:24px;color:#94a3b8">No activity log found.</td></tr>
      <?php else: foreach($pm_time_report as $pmr):
        $h = intdiv($pmr['total_minutes'], 60); $m = $pmr['total_minutes'] % 60;
      ?>
        <tr>
          <td style="padding:8px 10px;font-size:12px;font-weight:700"><?= htmlspecialchars($pmr['user_name'] ?: 'Unknown') ?></td>
          <td style="padding:8px 10px;font-size:12px;color:var(--blue);font-weight:600"><?= $h ?>h <?= $m ?>m</td>
          <td style="padding:8px 10px;font-size:12px"><?= $pmr['total_activities'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $pmr['projects_touched'] ?></td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
</div>
</div>

<div class="tab-pane" id="tab-clientreport">
<div style="margin-top:16px">
  <div class="sec-title">📊 Client Report</div>
  <form method="GET" style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-end">
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Client</div>
      <select name="cr_client" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;min-width:200px">
        <option value="">— Select Client —</option>
        <?php foreach ($master_clients as $mc): ?>
        <option value="<?= $mc['id'] ?>" <?= $cr_client==$mc['id']?'selected':'' ?>><?= htmlspecialchars($mc['client_name']) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">From</div>
      <input type="date" name="cr_from" value="<?= htmlspecialchars($cr_from) ?>" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    </div>
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">To</div>
      <input type="date" name="cr_to" value="<?= htmlspecialchars($cr_to) ?>" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    </div>
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:9px 20px;font-size:12px;font-weight:600;cursor:pointer">View Report</button>
  </form>

  <?php if ($cr_client): ?>
  <div class="tbl-card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project Code</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project Name</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Complete</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Terminate</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Over Quota</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Quality Fail</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Total</th>
      </tr></thead>
      <tbody>
      <?php if(empty($client_report_rows)): ?>
        <tr><td colspan="7" style="text-align:center;padding:24px;color:#94a3b8">No data found for this date range.</td></tr>
      <?php else:
        $cr_parent_shown = [];
        foreach($client_report_rows as $cr):
        if (!empty($cr['parent_sid']) && empty($cr_parent_shown[$cr['parent_sid']])):
            $cr_parent_shown[$cr['parent_sid']] = true;
            $roll = $client_report_parent_rollup[$cr['parent_sid']] ?? ['completes'=>0,'terminates'=>0,'overquota'=>0,'qualityfail'=>0,'total'=>0,'child_count'=>0];
      ?>
        <tr style="background:#f8faff">
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><strong><?= htmlspecialchars($cr['parent_sid']) ?></strong></td>
          <td style="padding:8px 10px;font-size:12px">
            <span class="pill" style="background:rgba(59,130,246,.1);color:#1b4fd8;border:1px solid rgba(59,130,246,.25);font-size:9px">Parent rollup · <?= intval($roll['child_count']) ?> children</span>
          </td>
          <td style="padding:8px 10px;font-size:12px;color:#16a34a;font-weight:600"><?= $roll['completes'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $roll['terminates'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $roll['overquota'] ?></td>
          <td style="padding:8px 10px;font-size:12px;color:#dc2626"><?= $roll['qualityfail'] ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:700"><?= $roll['total'] ?></td>
        </tr>
      <?php endif; ?>
        <tr<?= !empty($cr['parent_sid']) ? ' style="background:#fcfdff"' : '' ?>>
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><?= !empty($cr['parent_sid']) ? '<span style="color:#94a3b8">└─ </span>' : '' ?><?= htmlspecialchars($cr['survey_id']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($cr['project_name']) ?></td>
          <td style="padding:8px 10px;font-size:12px;color:#16a34a;font-weight:600"><?= $cr['completes'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $cr['terminates'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $cr['overquota'] ?></td>
          <td style="padding:8px 10px;font-size:12px;color:#dc2626"><?= $cr['qualityfail'] ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:700"><?= $cr['total'] ?></td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
  <?php else: ?>
    <div style="text-align:center;padding:40px;color:#94a3b8;font-size:13px">Select a client to view the report.</div>
  <?php endif; ?>
</div>
</div>

<div class="tab-pane" id="tab-supplierreport">
<div style="margin-top:16px">
  <div class="sec-title">📊 Supplier Report</div>
  <form method="GET" style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-end">
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Supplier</div>
      <select name="sr_vendor" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;min-width:200px">
        <option value="">— Select Supplier —</option>
        <?php foreach ($master_vendors as $mv): ?>
        <option value="<?= $mv['id'] ?>" <?= $sr_vendor==$mv['id']?'selected':'' ?>><?= htmlspecialchars($mv['vendor_name']) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">From</div>
      <input type="date" name="sr_from" value="<?= htmlspecialchars($sr_from) ?>" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    </div>
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">To</div>
      <input type="date" name="sr_to" value="<?= htmlspecialchars($sr_to) ?>" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    </div>
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:9px 20px;font-size:12px;font-weight:600;cursor:pointer">View Report</button>
  </form>

  <?php if ($sr_vendor): ?>
  <div class="tbl-card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project Code</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project Name</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Total Traffic</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Complete</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Terminate</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Conversion %</th>
      </tr></thead>
      <tbody>
      <?php if(empty($supplier_report_rows)): ?>
        <tr><td colspan="6" style="text-align:center;padding:24px;color:#94a3b8">No data found for this date range.</td></tr>
      <?php else:
        $sr_parent_shown = [];
        foreach($supplier_report_rows as $sre):
        if (!empty($sre['parent_sid']) && empty($sr_parent_shown[$sre['parent_sid']])):
            $sr_parent_shown[$sre['parent_sid']] = true;
            $roll = $supplier_report_parent_rollup[$sre['parent_sid']] ?? ['total'=>0,'completes'=>0,'terminates'=>0,'child_count'=>0];
      ?>
        <tr style="background:#f8faff">
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><strong><?= htmlspecialchars($sre['parent_sid']) ?></strong></td>
          <td style="padding:8px 10px;font-size:12px"><span class="pill" style="background:rgba(59,130,246,.1);color:#1b4fd8;border:1px solid rgba(59,130,246,.25);font-size:9px">Parent rollup · <?= intval($roll['child_count']) ?> children</span></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:700"><?= $roll['total'] ?></td>
          <td style="padding:8px 10px;font-size:12px;color:#16a34a;font-weight:600"><?= $roll['completes'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $roll['terminates'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $roll['total']>0 ? round($roll['completes']/$roll['total']*100,1) : 0 ?>%</td>
        </tr>
      <?php endif; ?>
        <tr<?= !empty($sre['parent_sid']) ? ' style="background:#fcfdff"' : '' ?>>
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><?= !empty($sre['parent_sid']) ? '<span style="color:#94a3b8">└─ </span>' : '' ?><?= htmlspecialchars($sre['survey_id']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($sre['project_name'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:700"><?= $sre['total'] ?></td>
          <td style="padding:8px 10px;font-size:12px;color:#16a34a;font-weight:600"><?= $sre['completes'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $sre['terminates'] ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $sre['total']>0 ? round($sre['completes']/$sre['total']*100,1) : 0 ?>%</td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
  <?php else: ?>
    <div style="text-align:center;padding:40px;color:#94a3b8;font-size:13px">Select a supplier to view the report.</div>
  <?php endif; ?>
</div>
</div>

<div class="tab-pane" id="tab-questionlibrary">
<div style="margin-top:16px">
  <div class="sec-title">📚 Question Library</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Create a question once, reuse it in any PreScreen Template — no need to recreate it for every project.</div>

  <form method="POST" class="tbl-card" style="padding:18px;margin-bottom:20px">
    <input type="hidden" name="save_question" value="1">
    <input type="hidden" name="q_id" id="qEditId" value="">
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
      <div>
        <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Country</div>
        <input type="text" name="q_country" id="qCountry" placeholder="e.g. United States" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
      </div>
      <div>
        <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Language</div>
        <input type="text" name="q_language" id="qLanguage" placeholder="e.g. English" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
      </div>
      <div>
        <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Control Type</div>
        <select name="q_control_type" id="qControlType" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
          <option value="text">Text</option>
          <option value="radio">Radio (single choice)</option>
          <option value="select">Dropdown</option>
          <option value="checkbox">Checkbox (multi choice)</option>
        </select>
      </div>
    </div>
    <div style="margin-bottom:10px">
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Title (internal reference name)</div>
      <input type="text" name="q_title" id="qTitle" required placeholder="e.g. Age Group" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
    </div>
    <div style="margin-bottom:10px">
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Question (shown to respondent)</div>
      <input type="text" name="q_text" id="qText" required placeholder="e.g. What is your age group?" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
      <div>
        <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Min-Length</div>
        <input type="number" name="q_min_length" id="qMinLength" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
      </div>
      <div>
        <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Max-Length</div>
        <input type="number" name="q_max_length" id="qMaxLength" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
      </div>
      <div>
        <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Text Type</div>
        <select name="q_text_type" id="qTextType" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
          <option value="">— Any —</option>
          <option value="alphanumeric">Alphanumeric</option>
          <option value="numeric">Numeric only</option>
          <option value="alpha">Letters only</option>
        </select>
      </div>
    </div>
    <div style="margin-bottom:14px">
      <div style="font-size:10px;font-weight:600;color:#64748b;text-transform:uppercase;margin-bottom:4px">Options (comma-separated — for Radio/Dropdown/Checkbox only)</div>
      <input type="text" name="q_options" id="qOptions" placeholder="e.g. 18-24, 25-34, 35-44, 45+" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 10px;font-size:12px">
    </div>
    <button type="submit" id="qSubmitBtn" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 24px;font-size:13px;font-weight:600;cursor:pointer">+ Add Question</button>
    <button type="button" onclick="resetQuestionForm()" id="qCancelBtn" style="display:none;background:#e2e8f0;color:#475569;border:none;border-radius:8px;padding:10px 24px;font-size:13px;cursor:pointer;margin-left:8px">Cancel Edit</button>
  </form>

  <div class="tbl-card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">S.No</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Title</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Question</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Type</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Country/Lang</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Action</th>
      </tr></thead>
      <tbody>
      <?php if(empty($question_library)): ?>
        <tr><td colspan="6" style="text-align:center;padding:24px;color:#94a3b8">No questions yet.</td></tr>
      <?php else: foreach($question_library as $i=>$q): ?>
        <tr>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:600"><?= htmlspecialchars($q['title']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($q['question_text']) ?></td>
          <td style="padding:8px 10px;font-size:11px"><?= htmlspecialchars(ucfirst($q['control_type'])) ?></td>
          <td style="padding:8px 10px;font-size:11px"><?= htmlspecialchars(trim(($q['country']?:'').(($q['country']&&$q['language'])?' / ':'').($q['language']?:'')) ?: '—') ?></td>
          <td style="padding:8px 10px;white-space:nowrap">
            <button type="button" class="btn-sm btn-blue" onclick='editQuestion(<?= htmlspecialchars(json_encode($q), ENT_QUOTES) ?>)'>Edit</button>
            <a href="?delete_question=<?= $q['id'] ?>#questionlibrary" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Delete this question? Attached templates will lose it too.')">Del</a>
          </td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
</div>
</div>

<div class="tab-pane" id="tab-iptracker">
<div style="margin-top:16px">
  <div class="sec-title">📍 IP Tracker</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">IP, Geo, Device, and Browser details for every respondent hit — searchable by IP, UID, project name, or SID.</div>

  <form method="GET" action="index.php#iptracker" style="display:flex;gap:10px;margin-bottom:16px">
    <input type="text" name="ipt_query" value="<?= htmlspecialchars($ipt_query) ?>" placeholder="Search by IP, UID, project name, or SID..." style="flex:1;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;outline:none">
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-size:13px;font-weight:600;cursor:pointer">Search</button>
    <?php if ($ipt_query): ?><a href="index.php#iptracker" style="align-self:center;font-size:12px;color:#64748b">Clear</a><?php endif; ?>
  </form>

  <div class="tbl-card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">S.No</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project Code</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project Name</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Vendor</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Identifier</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Status</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Date</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">IP</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Geo Location</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Device</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Browser</th>
      </tr></thead>
      <tbody>
      <?php if(empty($ip_tracker_rows)): ?>
        <tr><td colspan="11" style="text-align:center;padding:24px;color:#94a3b8">No records found.</td></tr>
      <?php else: foreach($ip_tracker_rows as $i=>$itr): ?>
        <tr>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><?= htmlspecialchars($itr['survey_id']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($itr['project_name'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($itr['vendor_name'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><?= htmlspecialchars($itr['respondent']) ?></td>
          <td style="padding:8px 10px;font-size:11px"><?= htmlspecialchars(ucfirst($itr['status'])) ?></td>
          <td style="padding:8px 10px;font-size:11px"><?= date('d M Y, H:i', strtotime($itr['created_at'])) ?></td>
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><?= htmlspecialchars($itr['ip'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars(trim(($itr['city'] ?: '').(($itr['city'] && $itr['country'])?', ':'').($itr['country'] ?: '')) ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($itr['device'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($itr['browser'] ?: '—') ?></td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
</div>
</div>

<div class="tab-pane" id="tab-blockedips">
<div style="margin-top:16px">
  <div class="sec-title">⛔ Blocked IP List</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Add any IP here — a respondent coming from that IP will be blocked instantly (right at vendor.php), and no lead/click record will be created either.</div>

  <form method="POST" class="tbl-card" style="padding:16px;margin-bottom:20px;display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
    <input type="hidden" name="add_blocked_ip" value="1">
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">IP Address</div>
      <input type="text" name="bip_ip" required placeholder="192.168.1.100" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;font-family:monospace">
    </div>
    <div style="flex:1;min-width:200px">
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Comment (optional)</div>
      <input type="text" name="bip_comment" placeholder="e.g. Spamming, bot traffic..." style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
    </div>
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-size:12px;font-weight:600;cursor:pointer">⛔ Block IP</button>
  </form>

  <div class="tbl-card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">S.No</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">IP</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Blocked On</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Comment</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Blocked By</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Action</th>
      </tr></thead>
      <tbody>
      <?php if(empty($blocked_ips)): ?>
        <tr><td colspan="6" style="text-align:center;padding:24px;color:#94a3b8">No IPs blocked yet.</td></tr>
      <?php else: foreach($blocked_ips as $i=>$bip): ?>
        <tr>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px;font-family:monospace"><?= htmlspecialchars($bip['ip']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= date('d M Y, H:i', strtotime($bip['created_at'])) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($bip['comment'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($bip['blocked_by'] ?: '—') ?></td>
          <td style="padding:8px 10px">
            <a href="?unblock_ip=<?= $bip['id'] ?>#blockedips" class="btn-sm" style="background:rgba(34,197,94,.15);color:#16a34a" onclick="return confirm('Unblock <?= htmlspecialchars($bip['ip']) ?>?')">Unblock</a>
          </td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
</div>
</div>

<div class="tab-pane" id="tab-alerts">
<div style="margin-top:16px;max-width:700px">
<div class="sec-title">🔔 Alert Settings</div>

<?php if (isset($_GET['msg'])): ?>
<div style="background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#15803d;border-radius:8px;padding:10px 16px;font-size:13px;margin-bottom:14px">✓ <?= htmlspecialchars($_GET['msg']) ?></div>
<?php endif; ?>

<div class="tbl-card" style="padding:22px">
  <form method="POST">
    <input type="hidden" name="save_alert_settings" value="1">
    <div style="margin-bottom:16px">
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Telegram Bot Token</div>
      <input type="text" name="as_tg_token" value="<?= htmlspecialchars($alert_settings['telegram_bot_token']) ?>" placeholder="123456789:ABC-DEF..." style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;color:#1e293b;outline:none;font-family:monospace">
    </div>
    <div style="margin-bottom:16px">
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Telegram Chat ID</div>
      <input type="text" name="as_tg_chat" value="<?= htmlspecialchars($alert_settings['telegram_chat_id']) ?>" placeholder="-1001234567890 or your user ID" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;color:#1e293b;outline:none;font-family:monospace">
    </div>
    <div style="margin-bottom:16px">
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Alert Email Address</div>
      <input type="text" name="as_email" value="<?= htmlspecialchars($alert_settings['alert_email']) ?>" placeholder="you@exazonresearch.com" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;color:#1e293b;outline:none">
    </div>
    <div style="font-size:12px;color:#64748b;line-height:1.7;margin-bottom:16px">
      These settings are used for alerts — automatic notifications will be sent when a quota is reached and when a speeder/duplicate is detected. For Telegram, <a href="https://core.telegram.org/bots#how-do-i-create-a-bot" target="_blank" style="color:var(--blue2)">create a Bot</a> and paste the token here, and get your Chat ID from <a href="https://t.me/userinfobot" target="_blank" style="color:var(--blue2)">@userinfobot</a>.
    </div>
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">Save Settings</button>
  </form>
</div>

<div class="chart-card" style="margin-top:14px">
  <div class="chart-title">Alert Triggers</div>
  <table style="width:100%;font-size:12px">
    <thead><tr><th style="padding:8px;background:#f8faff;text-align:left">Trigger</th><th style="padding:8px;background:#f8faff;text-align:left">Channel</th><th style="padding:8px;background:#f8faff;text-align:left">Condition</th></tr></thead>
    <tbody>
      <tr><td style="padding:8px">⚡ Speeder Detected</td><td style="padding:8px">Telegram</td><td style="padding:8px">LOI under 3 min on complete</td></tr>
      <tr><td style="padding:8px">⚠️ Duplicate UID</td><td style="padding:8px">Telegram</td><td style="padding:8px">Same respondent submits again on a project</td></tr>
      <tr><td style="padding:8px">🎯 Quota Reached</td><td style="padding:8px">Telegram + Email</td><td style="padding:8px">Project hits its target completes (auto-pauses)</td></tr>
      <tr><td style="padding:8px">📊 Daily Report</td><td style="padding:8px">Telegram + Email</td><td style="padding:8px">Manual (📲 Report button) or cron job</td></tr>
    </tbody>
  </table>
</div>

<div class="setup-box" style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.25);color:#78350f;margin-top:14px">
  <strong>⏰ Auto Daily Report — Cron Job</strong><br>
  Hostinger cPanel → Cron Jobs → Add:<br>
  <code>0 9 * * * curl "https://<?= $_SERVER['HTTP_HOST'] ?>/index.php?send_report=1"</code><br>
  Sends Telegram + Email every day at 9:00 AM IST.
</div>

<div class="sec-title" style="margin-top:20px">🔤 Status Synonym Mapping</div>
<div style="font-size:11px;color:#94a3b8;margin-bottom:12px">
  Different client platforms send different words for the same outcome (e.g. "success" instead of "complete"). Map those words here so they're recognized correctly instead of showing up as "Unmatched". Global rules apply to every project; a project-specific rule overrides the global one for that SID only.
</div>
<div class="tbl-card" style="padding:18px;margin-bottom:14px">
  <form method="POST" style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end">
    <input type="hidden" name="add_status_synonym" value="1">
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Word Client Sends</div>
      <input type="text" name="syn_word" placeholder="e.g. success" required style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;outline:none">
    </div>
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Maps To</div>
      <select name="syn_target" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;outline:none">
        <option value="complete">Complete</option>
        <option value="terminate">Terminate</option>
        <option value="quotafull">Quota Full</option>
        <option value="qc">Quality Fail (qc)</option>
        <option value="quality">Quality Fail (quality)</option>
      </select>
    </div>
    <div>
      <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Project (optional)</div>
      <select name="syn_sid" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;outline:none">
        <option value="">— Global (all projects) —</option>
        <?php foreach ($projects_full as $pf): ?>
        <option value="<?= htmlspecialchars($pf['survey_id']) ?>"><?= htmlspecialchars($pf['survey_id']) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 18px;font-family:'Bebas Neue',sans-serif;font-size:12px;letter-spacing:1px;cursor:pointer;height:36px">+ Add</button>
  </form>
</div>
<div class="tbl-card">
  <div class="tbl-wrap">
    <table style="width:100%">
      <thead><tr>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Word</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Maps To</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Scope</th>
        <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Action</th>
      </tr></thead>
      <tbody>
        <?php if (empty($status_synonyms)): ?>
        <tr><td colspan="4" style="text-align:center;padding:20px;color:#94a3b8">No synonyms configured yet.</td></tr>
        <?php else: foreach ($status_synonyms as $syn): ?>
        <tr>
          <td style="padding:8px 10px;font-family:monospace;font-size:12px"><?= htmlspecialchars($syn['synonym']) ?></td>
          <td style="padding:8px 10px"><span class="pill <?= $syn['maps_to'] ?>"><?= ucfirst($syn['maps_to']) ?></span></td>
          <td style="padding:8px 10px;font-size:11px;color:#64748b"><?= $syn['survey_id'] ? htmlspecialchars($syn['survey_id']) : '<span style="color:#94a3b8">Global</span>' ?></td>
          <td style="padding:8px 10px">
            <a href="?del_status_synonym=<?= $syn['id'] ?>#alerts" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Remove this mapping?')">Del</a>
          </td>
        </tr>
        <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
</div>
</div>
</div><!-- /alerts -->

<!-- ════════ NOTES TAB ════════ -->
<div class="tab-pane" id="tab-notes">
<div class="notes-card" style="margin-top:16px" id="notes">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
    <div class="sec-title" style="margin:0">📝 Notes & Reminders</div>
    <span style="font-size:11px;color:var(--muted)"><?= count($notes) ?> note<?= count($notes)!=1?'s':'' ?></span>
  </div>
  <form method="POST">
    <div class="notes-row">
      <textarea class="notes-ta" name="note_text" placeholder="Add a note, reminder, or client instruction..."></textarea>
      <button type="submit" name="save_note" class="btn-note">Add</button>
    </div>
  </form>
  <?php if(empty($notes)): ?>
  <div style="color:#94a3b8;font-size:13px;text-align:center;padding:18px">No notes yet.</div>
  <?php else: foreach($notes as $n): ?>
  <div class="note-item">
    <div><div class="note-text"><?= nl2br(htmlspecialchars($n['note'])) ?></div><div class="note-meta"><?= date('d M Y H:i',strtotime($n['created_at'].' UTC')) ?> IST</div></div>
    <a href="?del_note=<?= $n['id'] ?>" class="note-del" onclick="return confirm('Delete?')">✕</a>
  </div>
  <?php endforeach; endif; ?>
</div>
</div><!-- /notes -->

<!-- ===== CLIENT ACCOUNTS TAB ===== -->
<div class="tab-pane" id="tab-clients">
<div style="margin-top:16px;max-width:960px">

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px">
    <div class="sec-title" style="margin-bottom:0">👤 Client Portal Accounts</div>
    <a href="client/login.php" target="_blank" class="btn-sm btn-blue" style="text-decoration:none">🔗 Open Client Portal Login</a>
  </div>

  <!-- ADD CLIENT FORM -->
  <div style="background:#fff;border-radius:12px;padding:20px;border:1px solid #e2e8f0;box-shadow:0 1px 6px rgba(10,22,40,0.04);margin-bottom:18px">
    <div style="font-family:'Bebas Neue',sans-serif;font-size:14px;letter-spacing:2px;color:var(--navy);margin-bottom:14px">➕ Add / Update Client Account</div>
    <form method="POST">
      <input type="hidden" name="add_client" value="1">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;margin-bottom:12px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Client * <span style="font-weight:400;text-transform:none;color:#94a3b8">(Clients tab se)</span></div>
          <select style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-family:'DM Sans',sans-serif;font-size:12px;color:#1e293b;outline:none" name="cl_masterid" required>
            <option value="">— Select client —</option>
            <?php foreach($master_clients as $mc): ?>
            <option value="<?= $mc['id'] ?>"><?= htmlspecialchars($mc['client_name']) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Username</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-family:'DM Sans',sans-serif;font-size:12px;color:#1e293b;outline:none" type="text" name="cl_username" placeholder="e.g. globalopine" required>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Password</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-family:'DM Sans',sans-serif;font-size:12px;color:#1e293b;outline:none" type="text" name="cl_password" placeholder="Set password" required>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Extra Projects (optional, comma)</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-family:'DM Sans',sans-serif;font-size:12px;color:#1e293b;outline:none" type="text" name="cl_projects" placeholder="ONLY if extra SIDs are needed">
        </div>
      </div>
      <div style="font-size:11px;color:#94a3b8;margin-bottom:10px">As soon as a client is selected, all Projects linked to that client (in the Projects tab) will automatically show up in the client's portal — when a new project is added, nothing needs to be manually added here. Only fill "Extra Projects" when a SID is linked to another client but should still be shown to this client.</div>
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">Save Client</button>
        <span style="font-size:11px;color:#94a3b8">⚠ Same username = password &amp; projects will be updated</span>
      </div>
    </form>
  </div>

  <!-- CLIENTS TABLE -->
  <div class="tbl-card">
    <div class="tbl-head">
      <div class="tbl-title">All Client Accounts</div>
      <div class="tbl-count"><?= count($clients_list) ?> accounts</div>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr>
          <th>#</th><th>Client Name</th><th>Username</th>
          <th>Allowed Projects</th><th>Status</th>
          <th>Last Login</th><th>Created</th><th>Actions</th>
        </tr></thead>
        <tbody>
        <?php if(empty($clients_list)): ?>
        <tr><td colspan="8" style="text-align:center;padding:32px;color:#94a3b8;font-style:italic">No client accounts yet. Add one above.</td></tr>
        <?php else: foreach($clients_list as $i=>$cl): ?>
        <tr>
          <td style="color:#94a3b8"><?= $i+1 ?></td>
          <td><strong><?= htmlspecialchars($cl['client_name']) ?></strong></td>
          <td class="mono"><?= htmlspecialchars($cl['username']) ?></td>
          <td style="font-size:11px;color:#64748b;max-width:200px;word-break:break-all"><?= htmlspecialchars($cl['allowed_projects']?:'—') ?></td>
          <td>
            <?php if($cl['is_active']): ?>
            <span class="pill complete">Active</span>
            <?php else: ?>
            <span class="pill terminate">Inactive</span>
            <?php endif; ?>
          </td>
          <td style="font-size:11px;color:#94a3b8"><?= $cl['last_login'] ? date('d M H:i',strtotime($cl['last_login'].' UTC')) : 'Never' ?></td>
          <td style="font-size:11px;color:#94a3b8"><?= date('d M Y',strtotime($cl['created_at'].' UTC')) ?></td>
          <td>
            <div style="display:flex;gap:5px">
              <a href="?toggle_client=<?= $cl['id'] ?>" style="background:<?= $cl['is_active']?'rgba(245,158,11,0.1)':'rgba(34,197,94,0.1)' ?>;color:<?= $cl['is_active']?'#b45309':'#16a34a' ?>;border:1px solid <?= $cl['is_active']?'rgba(245,158,11,0.3)':'rgba(34,197,94,0.3)' ?>;border-radius:5px;padding:3px 8px;font-size:10px;font-weight:600;text-decoration:none;white-space:nowrap"><?= $cl['is_active']?'Disable':'Enable' ?></a>
              <a href="?del_client=<?= $cl['id'] ?>" onclick="return confirm('Delete <?= htmlspecialchars($cl['client_name']) ?>?')" style="background:rgba(239,68,68,0.1);color:#dc2626;border:1px solid rgba(239,68,68,0.3);border-radius:5px;padding:3px 8px;font-size:10px;font-weight:600;text-decoration:none">Delete</a>
            </div>
          </td>
        </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <!-- INFO BOX -->
  <div style="background:#fff;border-radius:10px;padding:14px 18px;border:1px solid #e2e8f0;margin-top:14px;font-size:12px;color:#64748b;line-height:1.9">
    <div style="font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:2px;color:var(--navy);margin-bottom:6px">📋 Portal Info</div>
    Client Login URL: <strong style="color:#1e293b">https://<?= $_SERVER['HTTP_HOST'] ?>/client/login.php</strong><br>
    Client can only see their own assigned projects — no CPI, vendor, or fraud data is shown.<br>
    To update a password, save again with the same username — the hash will auto-update.<br>
    Portal auto-refresh: every 2 minutes.
  </div>

</div>
</div><!-- /clients -->

<!-- ════════ VENDOR × PROJECT MATRIX TAB ════════ -->
<div class="tab-pane" id="tab-matrix">
  <div style="margin-top:16px">
    <div class="sec-title">🔲 Vendor × Project Matrix</div>
    <div style="font-size:12px;color:#94a3b8;margin-bottom:14px">Every vendor's clicks/completes on every project, at a glance. ⏸ badge means that specific vendor-project mapping is paused. Click any number to jump to that vendor+project's filtered Leads. <em>(Newest 30 projects, first 50 vendors alphabetically — keeps very large lists fast.)</em></div>
    <?php if (empty($matrix_vendors) || empty($matrix_projects)): ?>
    <div style="text-align:center;padding:32px;color:#94a3b8">No vendor or project data yet.</div>
    <?php else: ?>
    <div style="overflow-x:auto;border:1px solid #e2e8f0;border-radius:10px">
    <table style="border-collapse:collapse;width:max-content">
      <thead>
        <tr>
          <th style="padding:8px 12px;font-size:10px;background:#f8faff;text-align:left;position:sticky;left:0;z-index:2;border-right:1px solid #e2e8f0">Vendor</th>
          <?php foreach ($matrix_projects as $mp_col): ?>
          <th style="padding:8px 12px;font-size:10px;background:#f8faff;text-align:center;white-space:nowrap"><?= htmlspecialchars($mp_col['project_name'] ?: $mp_col['survey_id']) ?></th>
          <?php endforeach; ?>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($matrix_vendors as $mv_row): ?>
        <tr>
          <td style="padding:8px 12px;font-size:12px;font-weight:600;position:sticky;left:0;background:#fff;border-right:1px solid #e2e8f0;white-space:nowrap"><?= htmlspecialchars($mv_row['vendor_name']) ?></td>
          <?php foreach ($matrix_projects as $mp_col):
              $cell_key = $mv_row['id'] . '_' . $mp_col['survey_id'];
              $cell = $matrix_cells[$cell_key] ?? null;
          ?>
          <td style="padding:8px 12px;font-size:11px;text-align:center;white-space:nowrap">
            <?php if ($cell): ?>
            <a href="index.php?gs_query=&fVd=<?= $mv_row['id'] ?>&fPr=<?= urlencode($mp_col['survey_id']) ?>#tab-responses" style="color:var(--blue2);text-decoration:none">
              <?= number_format($cell['clicks']) ?> / <?= number_format($cell['completes']) ?>
            </a>
            <?php if (!empty($cell['paused'])): ?> <span title="Paused" style="color:#f59e0b">⏸</span><?php endif; ?>
            <?php else: ?>
            <span style="color:#cbd5e1">—</span>
            <?php endif; ?>
          </td>
          <?php endforeach; ?>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    </div>
    <?php endif; ?>
  </div>
</div><!-- /matrix -->

<!-- ════════ CLIENTS (MASTER DATA) TAB ════════ -->
<div class="tab-pane" id="tab-clientsmaster">
<div style="margin-top:16px;max-width:960px">
  <div class="sec-title">🏢 Clients (Project & Billing Master Data)</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">This is separate from "Client Accounts" (login portal) — this is the master record that gets linked in the Projects tab for CPI/billing.</div>

  <div style="display:flex;justify-content:flex-end;gap:8px;margin-bottom:12px">
    <?php if (exz_is_superadmin()): ?><button type="button" onclick="bulkDeleteClients()" style="background:rgba(239,68,68,.15);color:#dc2626;border:none;border-radius:8px;padding:10px 18px;font-size:12px;font-weight:600;cursor:pointer">🗑 Delete Selected</button><?php endif; ?>
    <button type="button" onclick="openClientModal()" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">+ Add Client</button>
  </div>

  <form id="clientBulkForm" method="POST">
    <input type="hidden" name="bulk_delete_clients" value="1">
    <input type="hidden" name="client_ids" id="clientIdsInput">
  </form>

  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">All Clients</div><div class="tbl-count"><?= count($master_clients) ?> clients</div></div>
    <div class="tbl-wrap">
      <table style="width:100%">
        <thead><tr>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left"><input type="checkbox" onclick="toggleAllClients(this)"></th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">#</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Client</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Contact</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Email</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Phone</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Total Proj</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Active Proj</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Total Traffic</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Completes</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Actions</th>
        </tr></thead>
        <tbody>
        <?php if(empty($master_clients)): ?>
        <tr><td colspan="11" style="text-align:center;padding:24px;color:#94a3b8">No clients yet. Add one above.</td></tr>
        <?php else: foreach($master_clients as $i=>$mc): $cst = $client_stats[$mc['id']] ?? null; ?>
        <tr>
          <td style="padding:8px 10px"><input type="checkbox" class="client-chk" value="<?= $mc['id'] ?>"></td>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px"><strong><a href="#" style="color:var(--blue2);text-decoration:none" onclick="openClientModal(<?= htmlspecialchars(json_encode($mc), ENT_QUOTES) ?>);return false"><?= htmlspecialchars($mc['client_name']) ?></a></strong></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($mc['contact_person'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($mc['email'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($mc['phone'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:600"><?= $cst['total_projects'] ?? 0 ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $cst['active_projects'] ?? 0 ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= $cst['total_traffic'] ?? 0 ?></td>
          <td style="padding:8px 10px;font-size:12px;color:#16a34a;font-weight:600"><?= $cst['total_completes'] ?? 0 ?></td>
          <td style="padding:8px 10px">
            <div style="display:flex;gap:5px">
              <button type="button" class="btn-sm" style="background:rgba(27,79,216,.12);color:var(--blue)" onclick="showClientRedirectUrls('<?= htmlspecialchars(addslashes($mc['client_name']), ENT_QUOTES) ?>','<?= htmlspecialchars($mc['client_uid'] ?? '') ?>')">🔗 Redirect URLs</button>
              <button type="button" class="btn-sm btn-blue" onclick="openClientModal(<?= htmlspecialchars(json_encode($mc), ENT_QUOTES) ?>)">Edit</button>
              <a href="?del_master_client=<?= $mc['id'] ?>#clientsmaster" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Delete <?= htmlspecialchars($mc['client_name']) ?>?')">Del</a>
            </div>
          </td>
        </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- ADD/EDIT CLIENT MODAL -->
<div class="modal-overlay" id="clientModal">
  <div class="modal" style="max-width:520px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <div style="font-family:'Bebas Neue',sans-serif;font-size:16px;letter-spacing:1px;color:var(--navy)">Add / Edit Client</div>
      <span onclick="closeClientModal()" style="cursor:pointer;font-size:18px;color:#94a3b8">✕</span>
    </div>
    <form method="POST">
      <input type="hidden" name="save_master_client" value="1">
      <input type="hidden" name="mc_id" id="cm_id" value="">
      <div style="margin-bottom:10px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Client Name *</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="mc_name" id="cm_name" placeholder="e.g. Kantar" required>
      </div>
      <div style="margin-bottom:10px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Contact Person</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="mc_contact" id="cm_contact" placeholder="e.g. Priya Sharma">
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Email</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="email" name="mc_email" id="cm_email" placeholder="client@example.com">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Phone</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="mc_phone" id="cm_phone" placeholder="+91...">
        </div>
      </div>
      <div style="margin-bottom:16px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Status</div>
        <select name="mc_status" id="cm_status" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
      </div>
      <hr>
      <div style="font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;color:var(--navy);margin-bottom:6px">🔐 Server-to-Server (S2S) Outbound</div>
      <div style="font-size:11px;color:#94a3b8;margin-bottom:10px">If this client (e.g. a marketplace like Cint/Lucid) wants final status reported via API call instead of/alongside browser redirect, configure here. Fires automatically on every project under this client.</div>
      <div style="margin-bottom:10px">
        <label style="font-size:12px"><input type="checkbox" name="mc_s2s_enabled" id="cm_s2s_enabled"> Enable S2S reporting</label>
      </div>
      <div style="margin-bottom:10px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">S2S Endpoint URL</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="mc_s2s_endpoint" id="cm_s2s_endpoint" placeholder="https://s2s.example.com/fulfillment/respondents">
      </div>
      <div style="margin-bottom:16px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Bearer Token</div>
        <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="mc_s2s_token" id="cm_s2s_token" placeholder="Token this client gave you">
      </div>
      <div style="display:flex;gap:8px">
        <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">Save Client</button>
        <button type="button" onclick="closeClientModal()" style="background:#f1f3f9;color:#475569;border:none;border-radius:8px;padding:10px 22px;font-size:13px;font-weight:600;cursor:pointer">Cancel</button>
      </div>
    </form>
  </div>
</div>
<script>
function editQuestion(q) {
  document.getElementById('qEditId').value = q.id;
  document.getElementById('qCountry').value = q.country || '';
  document.getElementById('qLanguage').value = q.language || '';
  document.getElementById('qControlType').value = q.control_type || 'text';
  document.getElementById('qTitle').value = q.title || '';
  document.getElementById('qText').value = q.question_text || '';
  document.getElementById('qMinLength').value = q.min_length || '';
  document.getElementById('qMaxLength').value = q.max_length || '';
  document.getElementById('qTextType').value = q.text_type || '';
  document.getElementById('qOptions').value = q.options || '';
  document.getElementById('qSubmitBtn').textContent = 'Save Changes';
  document.getElementById('qCancelBtn').style.display = 'inline-block';
  document.getElementById('qTitle').scrollIntoView({behavior:'smooth', block:'center'});
}
function resetQuestionForm() {
  document.getElementById('qEditId').value = '';
  ['qCountry','qLanguage','qTitle','qText','qMinLength','qMaxLength','qOptions'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('qControlType').value = 'text';
  document.getElementById('qTextType').value = '';
  document.getElementById('qSubmitBtn').textContent = '+ Add Question';
  document.getElementById('qCancelBtn').style.display = 'none';
}

function showVendorLinks(vendorName, sid, vid, shortCode) {
  document.getElementById('vendorLinksName').textContent = vendorName + ' — Project: ' + sid;
  const base = window.location.origin + window.location.pathname.replace(/index\.php$/, '');
  document.getElementById('vendorEntryLink').textContent = base + 'vendor.php?sid=' + encodeURIComponent(sid) + '&vid=' + vid + '&uid=[UID]';
  document.getElementById('vendorShortLink').textContent = shortCode ? (base + 'exaverify.php?c=' + encodeURIComponent(shortCode) + '&pid=[UID]') : '(short code not generated yet — try again after reloading the page)';
  document.getElementById('vendorLinksModal').style.display = 'flex';
}

function showClientRedirectUrls(clientName, clientUid) {
  document.getElementById('clientRedirectName').textContent = clientName + ' — Client Code: ' + clientUid;
  const base = window.location.origin + window.location.pathname.replace(/index\.php$/, '') + 'client_redirect.php';
  const types = {complete:'complete', terminate:'terminate', overquota:'quotafull', qualityfail:'qc'};
  for (const key in types) {
    const url = base + '?client=' + encodeURIComponent(clientUid) + '&type=' + types[key] + '&uid=[UID]';
    document.getElementById('clientRedirectUrl_' + key).textContent = url;
  }
  document.getElementById('clientRedirectModal').style.display = 'flex';
}
function copyClientUrl(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text);
  event.target.textContent = 'Copied!';
  setTimeout(() => { event.target.textContent = 'Copy'; }, 1500);
}

function openClientModal(mc){
  mc = mc || {};
  document.getElementById('cm_id').value = mc.id || '';
  document.getElementById('cm_name').value = mc.client_name || '';
  document.getElementById('cm_contact').value = mc.contact_person || '';
  document.getElementById('cm_email').value = mc.email || '';
  document.getElementById('cm_phone').value = mc.phone || '';
  document.getElementById('clientModal').classList.add('open');
}
function closeClientModal(){ document.getElementById('clientModal').classList.remove('open'); }

function toggleAllClients(cb){
  document.querySelectorAll('.client-chk').forEach(c => c.checked = cb.checked);
}
function bulkDeleteClients(){
  const ids = Array.from(document.querySelectorAll('.client-chk:checked')).map(c => c.value);
  if(ids.length === 0){ alert('Please select at least one client.'); return; }
  if(!confirm('Delete ' + ids.length + ' client(s)? This cannot be undone.')) return;
  document.getElementById('clientIdsInput').value = ids.join(',');
  document.getElementById('clientBulkForm').submit();
}
</script>
</div><!-- /clientsmaster -->

<!-- ════════ SCREENER DATA TAB ════════ -->
<div class="tab-pane" id="tab-screener">
<div style="margin-top:16px">
  <div class="sec-title">📄 Screener Data (Pre-Survey Answers)</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Demographic/screening questions the respondent answers before starting the survey are recorded here.</div>

  <form method="GET" action="index.php#screener" style="display:flex;gap:10px;margin-bottom:14px">
    <input type="hidden" name="page" value="">
    <select name="scr_sid" style="background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;flex:1">
      <option value="">All Projects</option>
      <?php foreach($projects_full as $pf): ?>
      <option value="<?= htmlspecialchars($pf['survey_id']) ?>" <?= $scr_filter_sid===$pf['survey_id']?'selected':'' ?>><?= htmlspecialchars($pf['project_name'] ?: $pf['survey_id']) ?></option>
      <?php endforeach; ?>
    </select>
    <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:9px 20px;font-size:12px;font-weight:600;cursor:pointer">Filter</button>
    <a href="?export_screener=1<?= $scr_filter_sid ? '&scr_sid='.urlencode($scr_filter_sid) : '' ?>" style="background:rgba(34,197,94,.12);color:#15803d;border-radius:8px;padding:9px 20px;font-size:12px;font-weight:600;text-decoration:none">⬇ Export CSV</a>
  </form>

  <div style="display:flex;justify-content:flex-end;margin-bottom:8px">
    <?php if (exz_is_superadmin()): ?><button type="button" onclick="bulkDeleteScreener()" style="background:rgba(239,68,68,.15);color:#dc2626;border:none;border-radius:8px;padding:9px 18px;font-size:12px;font-weight:600;cursor:pointer">🗑 Delete Selected</button><?php endif; ?>
  </div>
  <form id="screenerBulkForm" method="POST">
    <input type="hidden" name="bulk_delete_screener" value="1">
    <input type="hidden" name="screener_ids" id="screenerIdsInput">
  </form>

  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">Answers</div><div class="tbl-count"><?= $screener_total ?> total</div></div>
    <div class="tbl-wrap">
      <table style="width:100%">
        <thead><tr>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left"><input type="checkbox" onclick="toggleAllScreener(this)"></th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">#</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">UID</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">SID</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Gender</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Age</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Education</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Income</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Device</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Date</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Actions</th>
        </tr></thead>
        <tbody>
        <?php if(empty($screener_pivot)): ?>
        <tr><td colspan="11" style="text-align:center;padding:24px;color:#94a3b8">No screener answers captured yet.</td></tr>
        <?php else: foreach($screener_pivot as $i=>$sd): $rowkey = urlencode($sd['respondent'].'|'.$sd['survey_id']); ?>
        <tr>
          <td style="padding:8px 10px"><input type="checkbox" class="screener-chk" value="<?= htmlspecialchars($sd['respondent'].'|'.$sd['survey_id']) ?>"></td>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px;font-family:monospace;font-size:11px"><a href="respondent_view.php?uid=<?= urlencode($sd['respondent']) ?>&sid=<?= urlencode($sd['survey_id']) ?>" style="color:var(--blue2);text-decoration:none"><?= htmlspecialchars($sd['respondent']) ?></a></td>
          <td style="padding:8px 10px;font-size:11px"><b style="color:var(--blue)"><?= htmlspecialchars($sd['survey_id']) ?></b></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($sd['gender']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($sd['age_group']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($sd['education']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($sd['income']) ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($sd['device_self']) ?></td>
          <td style="padding:8px 10px;font-size:11px;color:#94a3b8"><?= date('d M H:i', strtotime($sd['created_at'].' UTC')) ?></td>
          <td style="padding:8px 10px"><a href="?del_screener=<?= $rowkey ?>#screener" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Delete all answers for this respondent?')">Del</a></td>
        </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
</div><!-- /screener -->

<!-- ════════ GLOBAL SEARCH TAB ════════ -->
<div class="tab-pane" id="tab-searchlookup">
<div style="margin-top:16px">
  <div class="sec-title">🔍 Search &amp; Lookup</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Both in one place — if you have partial info, use Quick Search; if you have an exact list of UIDs, use Bulk Check.</div>

  <div style="display:flex;gap:8px;margin-bottom:16px">
    <button type="button" id="modeQuickBtn" onclick="setSearchMode('quick')" class="btn-sm" style="padding:8px 18px;font-size:12px;background:var(--blue2);color:#fff">Quick Search</button>
    <button type="button" id="modeBulkBtn" onclick="setSearchMode('bulk')" class="btn-sm" style="padding:8px 18px;font-size:12px;background:#e2e8f0;color:#475569">Bulk Check</button>
  </div>

  <div id="modeQuickPane">
    <form id="quickSearchForm" onsubmit="return runQuickSearch(event)" style="display:flex;gap:10px;margin-bottom:16px">
      <input type="text" id="quickSearchInput" name="gs_query" placeholder="Type UID, SID, IP, or Country..." style="flex:1;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;color:#1e293b;outline:none">
      <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-size:13px;font-weight:600;cursor:pointer">Search</button>
    </form>
  </div>

  <div id="modeBulkPane" style="display:none">
    <form id="bulkCheckForm" onsubmit="return runBulkCheck(event)" class="tbl-card" style="padding:18px;margin-bottom:16px">
      <div style="margin-bottom:12px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Project (optional — filter by SID)</div>
        <select name="ul_sid" id="bulkSidSelect" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px">
          <option value="">All Projects</option>
          <?php foreach($projects_full as $pf): ?>
          <option value="<?= htmlspecialchars($pf['survey_id']) ?>"><?= htmlspecialchars($pf['project_name'] ?: $pf['survey_id']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div style="margin-bottom:12px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">UIDs — ek per line</div>
        <textarea name="ul_uids" id="bulkUidsInput" rows="6" placeholder="abc1&#10;abc2&#10;nomi312" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;font-family:monospace;resize:vertical"></textarea>
      </div>
      <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">Check UIDs →</button>
    </form>
  </div>

  <div id="slResultsArea">
    <div style="text-align:center;padding:40px;color:#94a3b8;font-size:13px">Type above to Quick Search, or switch to Bulk Check mode to paste multiple UIDs.</div>
  </div>
</div>
</div><!-- /searchlookup -->

<!-- ════════ BILLING / INVOICE TAB ════════ -->
<div class="tab-pane" id="tab-billing">
<div style="margin-top:16px">
  <div class="sec-title">🧾 Billing / Revenue Tracker</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Revenue/Cost/Margin is auto-calculated from Client CPI vs Vendor CPI. Manage each project's Paid/Invoiced/Unpaid status from here. <a href="Exazon_Invoice_Template.html" target="_blank" style="color:var(--blue2)">Open Invoice Template →</a></div>

  <?php
    $bill_total_rev = 0; $bill_total_cost = 0;
    foreach ($billing_rows as $b) { $bill_total_rev += $b['completes']*$b['cpi']; $bill_total_cost += $b['completes']*$b['vendor_cost']; }
  ?>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">
    <div class="stat-card"><div class="stat-num navy">$<?= number_format($bill_total_rev,2) ?></div><div class="stat-lbl">Total Revenue</div></div>
    <div class="stat-card"><div class="stat-num orange">$<?= number_format($bill_total_cost,2) ?></div><div class="stat-lbl">Total Vendor Cost</div></div>
    <div class="stat-card"><div class="stat-num green">$<?= number_format($bill_total_rev-$bill_total_cost,2) ?></div><div class="stat-lbl">Gross Margin</div></div>
  </div>

  <div style="display:flex;justify-content:flex-end;margin-bottom:10px">
    <button type="button" onclick="generateInvoiceFromBilling()" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 20px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">🧾 Generate Invoice From Selected</button>
  </div>

  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">Per-Project Billing</div><div class="tbl-count"><?= count($billing_rows) ?> projects</div></div>
    <div class="tbl-wrap">
      <table style="width:100%">
        <thead><tr>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left"><input type="checkbox" onclick="document.querySelectorAll('.bill-chk').forEach(c=>c.checked=this.checked)"></th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Project</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Client</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Completes</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Revenue</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Cost</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Margin</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Invoice Status</th>
        </tr></thead>
        <tbody>
        <?php if (empty($billing_rows)): ?>
        <tr><td colspan="8" style="text-align:center;padding:24px;color:#94a3b8">No projects yet.</td></tr>
        <?php else:
          $billing_parent_shown = [];
          foreach($billing_rows as $b):
          $rev = $b['completes']*$b['cpi']; $cost = $b['completes']*$b['vendor_cost']; $margin = $rev-$cost;
          $status_pill = ['unpaid'=>'terminate','invoiced'=>'qc','paid'=>'complete'];
          if (!empty($b['parent_sid']) && empty($billing_parent_shown[$b['parent_sid']])):
              $billing_parent_shown[$b['parent_sid']] = true;
              $roll = $billing_parent_rollup[$b['parent_sid']] ?? ['completes'=>0,'revenue'=>0,'cost'=>0,'child_count'=>0];
              $roll_margin = $roll['revenue'] - $roll['cost'];
        ?>
        <tr style="background:#f8faff">
          <td style="padding:8px 10px"></td>
          <td style="padding:8px 10px"><strong style="font-size:13px"><?= htmlspecialchars($b['parent_sid']) ?></strong>
            <span class="pill" style="background:rgba(59,130,246,.1);color:#1b4fd8;border:1px solid rgba(59,130,246,.25);font-size:9px;margin-left:4px">Parent rollup · <?= intval($roll['child_count']) ?> child projects</span>
          </td>
          <td style="padding:8px 10px;font-size:12px">—</td>
          <td style="padding:8px 10px;font-size:12px"><?= intval($roll['completes']) ?></td>
          <td style="padding:8px 10px;font-size:12px">$<?= number_format($roll['revenue'],2) ?></td>
          <td style="padding:8px 10px;font-size:12px">$<?= number_format($roll['cost'],2) ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:600;color:<?= $roll_margin>=0?'#16a34a':'#dc2626' ?>">$<?= number_format($roll_margin,2) ?></td>
          <td style="padding:8px 10px;font-size:10px;color:#94a3b8">Invoiced per child, below</td>
        </tr>
        <?php endif; ?>
        <tr<?= !empty($b['parent_sid']) ? ' style="background:#fcfdff"' : '' ?>>
          <td style="padding:8px 10px"><input type="checkbox" class="bill-chk"
            data-client="<?= htmlspecialchars($b['cname'] ?: 'Unknown Client', ENT_QUOTES) ?>"
            data-desc="<?= htmlspecialchars(($b['project_name'] ?: $b['survey_id']).' ('.$b['survey_id'].')', ENT_QUOTES) ?>"
            data-qty="<?= intval($b['completes']) ?>"
            data-rate="<?= number_format((float)$b['cpi'], 2, '.', '') ?>"
            data-sid="<?= htmlspecialchars($b['survey_id'], ENT_QUOTES) ?>"></td>
          <td style="padding:8px 10px"><?= !empty($b['parent_sid']) ? '<span style="color:#94a3b8;margin-right:4px">└─</span>' : '' ?><strong><?= htmlspecialchars($b['project_name'] ?: $b['survey_id']) ?></strong><div style="font-family:monospace;font-size:10px;color:#94a3b8"><?= htmlspecialchars($b['survey_id']) ?></div></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($b['cname'] ?: '—') ?></td>
          <td style="padding:8px 10px;font-size:12px"><?= intval($b['completes']) ?></td>
          <td style="padding:8px 10px;font-size:12px">$<?= number_format($rev,2) ?></td>
          <td style="padding:8px 10px;font-size:12px">$<?= number_format($cost,2) ?></td>
          <td style="padding:8px 10px;font-size:12px;font-weight:600;color:<?= $margin>=0?'#16a34a':'#dc2626' ?>">$<?= number_format($margin,2) ?></td>
          <td style="padding:8px 10px">
            <form method="POST" style="display:flex;gap:5px;align-items:center">
              <input type="hidden" name="save_invoice_status" value="1">
              <input type="hidden" name="bi_sid" value="<?= htmlspecialchars($b['survey_id']) ?>">
              <span class="pill <?= $status_pill[$b['invoice_status']] ?? 'terminate' ?>" style="margin-right:4px"><?= strtoupper($b['invoice_status']) ?></span>
              <select name="bi_status" onchange="this.form.submit()" style="font-size:10px;padding:3px">
                <option value="unpaid" <?= $b['invoice_status']==='unpaid'?'selected':'' ?>>Unpaid</option>
                <option value="invoiced" <?= $b['invoice_status']==='invoiced'?'selected':'' ?>>Invoiced</option>
                <option value="paid" <?= $b['invoice_status']==='paid'?'selected':'' ?>>Paid</option>
              </select>
              <input type="hidden" name="bi_invoice_no" value="<?= htmlspecialchars($b['invoice_no']) ?>">
              <input type="hidden" name="bi_notes" value="<?= htmlspecialchars($b['invoice_notes']) ?>">
            </form>
          </td>
        </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
<script>
function generateInvoiceFromBilling(){
  const checked = Array.from(document.querySelectorAll('.bill-chk:checked'));
  if(checked.length === 0){ alert('Please select at least one project to invoice.'); return; }

  const clients = [...new Set(checked.map(c => c.dataset.client))];
  if(clients.length > 1){
    alert('Selected projects belong to different clients (' + clients.join(', ') + '). Please generate one invoice per client — select only projects for a single client at a time.');
    return;
  }

  const items = checked.map(c => ({
    desc: c.dataset.desc,
    qty: c.dataset.qty,
    rate: c.dataset.rate
  }));

  const params = new URLSearchParams();
  params.set('client', clients[0]);
  params.set('items', JSON.stringify(items));
  window.open('Exazon_Invoice_Template.html?' + params.toString(), '_blank');
}
</script>
</div><!-- /billing -->





<!-- ════════ AUDIT LOG TAB ════════ -->
<div class="tab-pane" id="tab-auditlog">
<div style="margin-top:16px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <div class="sec-title" style="margin-bottom:0">📜 Audit Log</div>
    <a href="?clear_audit=1#auditlog" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Clear the ENTIRE audit log? This cannot be undone.')">Clear All</a>
  </div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Every delete/critical action is tracked here — who, what, when.</div>

  <?php if (exz_is_superadmin()): ?>
  <div class="tbl-card" style="padding:18px;margin-bottom:18px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
    <div>
      <div class="sec-title" style="margin-bottom:4px">💾 Database Backup</div>
      <div style="font-size:12px;color:#64748b">Full SQL dump of every table (structure + data) — download and store safely.</div>
    </div>
    <a href="?backup=1" class="btn-sm" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;text-decoration:none;border-radius:8px">⬇ Download Full Backup (.sql)</a>
  </div>

  <div class="tbl-card" style="padding:14px 18px;margin-bottom:18px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
    <div>
      <div class="sec-title" style="margin-bottom:4px">📊 Audit Log Export</div>
      <div style="font-size:12px;color:#64748b">Just the audit trail (who did what, when) as a spreadsheet — for sharing or record-keeping without a full DB dump.</div>
    </div>
    <a href="?audit_export=xlsx" class="btn-sm" style="background:#16a34a;color:#fff;padding:9px 18px;border-radius:8px;text-decoration:none;font-size:12px;font-weight:600">⬇ Download Audit Log (.xlsx)</a>
  </div>
  <?php endif; ?>

  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">Recent Actions</div><div class="tbl-count"><?= count($audit_log) ?> entries</div></div>
    <div class="tbl-wrap">
      <table style="width:100%">
        <thead><tr>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">#</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Action</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Detail</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Performed By</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Time</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Action</th>
        </tr></thead>
        <tbody>
        <?php if(empty($audit_log)): ?>
        <tr><td colspan="6" style="text-align:center;padding:24px;color:#94a3b8">No actions logged yet.</td></tr>
        <?php else: foreach($audit_log as $i=>$al): ?>
        <tr>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px"><span class="pill terminate"><?= htmlspecialchars($al['action']) ?></span></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($al['detail']) ?></td>
          <td style="padding:8px 10px;font-size:12px;color:#475569">👤 <?= htmlspecialchars($al['performed_by'] ?? 'Unknown') ?></td>
          <td style="padding:8px 10px;font-size:11px;color:#94a3b8"><?= date('d M Y H:i', strtotime($al['performed_at'].' UTC')) ?></td>
          <td style="padding:8px 10px"><a href="?del_audit=<?= $al['id'] ?>#auditlog" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Delete this log entry?')">Del</a></td>
        </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
</div><!-- /auditlog -->

<!-- ════════ TEAM MANAGEMENT TAB ════════ -->
<div class="tab-pane" id="tab-team">
<?php if (!exz_is_superadmin()): ?>
<div style="margin-top:16px;text-align:center;padding:32px;color:#94a3b8">🔒 Only a Superadmin can view Team Management.</div>
<?php else: ?>
<div style="margin-top:16px;max-width:960px">
  <div class="sec-title">👥 Team Members</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Each member logs in separately with their own email + password. Role is reserved for future permission-gating — right now only the Team tab is superadmin-only; let us know if you'd like role-based restrictions on other tabs/actions too, and we can add those.</div>

  <div class="tbl-card" style="padding:18px;margin-bottom:18px">
    <form method="POST">
      <input type="hidden" name="save_team_member" value="1">
      <input type="hidden" name="tm_id" value="">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;margin-bottom:12px">
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Name *</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="tm_name" placeholder="e.g. Priya Sharma" required>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Email * (login username)</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="email" name="tm_email" placeholder="name@exazonresearch.com" required>
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Password</div>
          <input style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none" type="text" name="tm_password" placeholder="Set / leave blank to keep">
        </div>
        <div>
          <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Role</div>
          <select name="tm_role" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:9px 12px;font-size:12px;color:#1e293b;outline:none">
            <option value="superadmin">Superadmin</option>
            <option value="manager">Manager</option>
            <option value="viewer" selected>Viewer</option>
          </select>
        </div>
      </div>
      <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">+ Add / Update Member</button>
    </form>
  </div>

  <div class="tbl-card">
    <div class="tbl-head"><div class="tbl-title">All Team Members</div><div class="tbl-count"><?= count($team_members) ?> members</div></div>
    <div class="tbl-wrap">
      <table style="width:100%">
        <thead><tr>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">#</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Name</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Email</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Role</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Status</th>
          <th style="padding:8px 10px;font-size:10px;background:#f8faff;text-align:left">Actions</th>
        </tr></thead>
        <tbody>
        <?php if(empty($team_members)): ?>
        <tr><td colspan="6" style="text-align:center;padding:24px;color:#94a3b8">No team members yet. Add one above.</td></tr>
        <?php else: foreach($team_members as $i=>$tm): ?>
        <tr>
          <td style="padding:8px 10px;color:#94a3b8"><?= $i+1 ?></td>
          <td style="padding:8px 10px"><strong><?= htmlspecialchars($tm['name']) ?></strong></td>
          <td style="padding:8px 10px;font-size:12px"><?= htmlspecialchars($tm['email'] ?: '—') ?></td>
          <td style="padding:8px 10px"><span class="pill <?= $tm['role']==='superadmin'?'qc':($tm['role']==='manager'?'quotafull':'terminate') ?>"><?= ucfirst($tm['role']) ?></span></td>
          <td style="padding:8px 10px">
            <?php if($tm['is_active']): ?><span class="pill complete">Active</span><?php else: ?><span class="pill terminate">Inactive</span><?php endif; ?>
          </td>
          <td style="padding:8px 10px">
            <div style="display:flex;gap:5px">
              <a href="?toggle_team=<?= $tm['id'] ?>#team" class="btn-sm" style="background:<?= $tm['is_active']?'rgba(245,158,11,0.1)':'rgba(34,197,94,0.1)' ?>;color:<?= $tm['is_active']?'#b45309':'#16a34a' ?>"><?= $tm['is_active']?'Disable':'Enable' ?></a>
              <a href="?del_team=<?= $tm['id'] ?>#team" class="btn-sm" style="background:rgba(239,68,68,.15);color:#dc2626" onclick="return confirm('Remove <?= htmlspecialchars($tm['name']) ?>?')">Remove</a>
            </div>
          </td>
        </tr>
        <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
<?php endif; ?>
</div><!-- /team -->

<!-- ════════ CHANGE PASSWORD TAB ════════ -->
<div class="tab-pane" id="tab-changepass">
<div style="margin-top:16px;max-width:480px">
  <div class="sec-title">⚙️ Account Settings</div>
  <div style="font-size:12px;color:#64748b;margin-bottom:14px">Manage your profile and password from here.</div>

  <?php
    $my_profile = ['name'=>$_SESSION['ex_team_name'] ?? '', 'email'=>''];
    try {
        $mp = $pdo->prepare("SELECT name, email FROM exz_team WHERE id=?");
        $mp->execute([$_SESSION['ex_team_id']]);
        $mp_row = $mp->fetch();
        if ($mp_row) $my_profile = $mp_row;
    } catch (Exception $e) {}
  ?>

  <div class="sec-title" style="font-size:13px">👤 My Profile</div>
  <?php if ($up_msg): ?>
  <div style="background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#15803d;border-radius:8px;padding:10px 16px;font-size:13px;margin-bottom:14px">✓ <?= htmlspecialchars($up_msg) ?></div>
  <?php endif; ?>
  <?php if ($up_err): ?>
  <div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#b91c1c;border-radius:8px;padding:10px 16px;font-size:13px;margin-bottom:14px">⚠ <?= htmlspecialchars($up_err) ?></div>
  <?php endif; ?>
  <div class="tbl-card" style="padding:22px;margin-bottom:24px">
    <form method="POST" action="index.php#changepass">
      <input type="hidden" name="update_profile" value="1">
      <div style="margin-bottom:14px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Name</div>
        <input type="text" name="up_name" value="<?= htmlspecialchars($my_profile['name']) ?>" required style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;outline:none">
      </div>
      <div style="margin-bottom:18px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Email (login username)</div>
        <input type="email" name="up_email" value="<?= htmlspecialchars($my_profile['email']) ?>" required style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;outline:none">
      </div>
      <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">Save Profile</button>
    </form>
  </div>

  <div class="sec-title" style="font-size:13px">🔑 Change Password</div>
  <?php if ($cp_msg): ?>
  <div style="background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#15803d;border-radius:8px;padding:10px 16px;font-size:13px;margin-bottom:14px">✓ <?= htmlspecialchars($cp_msg) ?></div>
  <?php endif; ?>
  <?php if ($cp_err): ?>
  <div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#b91c1c;border-radius:8px;padding:10px 16px;font-size:13px;margin-bottom:14px">⚠ <?= htmlspecialchars($cp_err) ?></div>
  <?php endif; ?>

  <div class="tbl-card" style="padding:22px">
    <form method="POST" action="index.php#changepass">
      <input type="hidden" name="change_password" value="1">
      <div style="margin-bottom:14px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Current Password</div>
        <input type="password" name="cp_current" required style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;outline:none">
      </div>
      <div style="margin-bottom:14px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">New Password</div>
        <input type="password" name="cp_new" required minlength="6" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;outline:none">
      </div>
      <div style="margin-bottom:18px">
        <div style="font-size:10px;font-weight:600;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Confirm New Password</div>
        <input type="password" name="cp_confirm" required minlength="6" style="width:100%;background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;font-size:13px;outline:none">
      </div>
      <button type="submit" style="background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:none;border-radius:8px;padding:10px 22px;font-family:'Bebas Neue',sans-serif;font-size:13px;letter-spacing:1px;cursor:pointer">Update Password</button>
    </form>
  </div>
</div>
</div><!-- /changepass -->

<div class="tab-pane" id="tab-feasibility">
<div style="margin-top:12px;background:#fff;border-radius:12px;border:1px solid #e2e8f0;overflow:hidden">
  <iframe src="Exazon_Feasibility_Calculator.html" style="width:100%;height:88vh;border:none;border-radius:12px" loading="lazy" title="MR Feasibility Pro Calculator"></iframe>
</div>
</div><!-- /feasibility -->

<div class="tab-pane" id="tab-qualityscore">
<div style="margin-top:12px;background:#fff;border-radius:12px;border:1px solid #e2e8f0;overflow:hidden">
  <iframe src="quality_score.php" style="width:100%;height:88vh;border:none;border-radius:12px" loading="lazy" title="Quality Score"></iframe>
</div>
</div><!-- /qualityscore -->

<div class="tab-pane" id="tab-reconciletab">
<div style="margin-top:12px;background:#fff;border-radius:12px;border:1px solid #e2e8f0;overflow:hidden">
  <iframe src="reconcile.php" style="width:100%;height:88vh;border:none;border-radius:12px" loading="lazy" title="Reconcile"></iframe>
</div>
</div><!-- /reconciletab -->

<div style="text-align:center;font-size:11px;color:#94a3b8;padding-bottom:20px">
  © 2026 Exazon Research LLP &nbsp;·&nbsp; Dashboard v5 Final &nbsp;·&nbsp; <?= date('d M Y H:i:s') ?> IST &nbsp;·&nbsp; Auto-refresh 60s
</div>
</div><!-- /main -->
</div><!-- /app-content -->
</div><!-- /app-layout -->

<script>
const trend    = <?= $trendJson ?>;
const hourly   = <?= $hourlyJson ?>;
const devices  = <?= $deviceJson ?>;
const countries= <?= $countryJson ?>;
const sources  = <?= json_encode($sources) ?>;

function mkChart(id,type,labels,datasets,opts={}){
  const el=document.getElementById(id); if(!el)return;
  // Wrapped in try-catch: if Chart.js's CDN failed to load (network-issue,
  // ad-blocker, slow-connection) "Chart" would be undefined, and calling
  // it would throw an UNCAUGHT exception — which halts the REST of this
  // entire script from executing (everything after this point in the same
  // <script> block, including tab-switching, filters, and the Matrix
  // deep-link fix). A missing chart is a minor visual gap; a broken
  // dashboard is not — so this must never be allowed to cascade.
  try {
    if (typeof Chart === 'undefined') { console.warn('Chart.js failed to load — skipping chart:', id); return; }
    new Chart(el,{type,data:{labels,datasets},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{font:{size:9},boxWidth:9}}},...opts}});
  } catch (e) {
    console.warn('Chart render failed for', id, e);
  }
}

const tDays=trend.length?trend.map(d=>d.day):['Today'];
const tC=trend.map(d=>parseInt(d.c)||0), tT=trend.map(d=>parseInt(d.t)||0),
      tQ=trend.map(d=>parseInt(d.q)||0), tQL=trend.map(d=>parseInt(d.ql)||0);

mkChart('trendChart','line',tDays,[
  {label:'Complete', data:tC, borderColor:'#22c55e',backgroundColor:'rgba(34,197,94,.1)',tension:.4,fill:true,pointRadius:3},
  {label:'Terminate',data:tT, borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.05)',tension:.4,fill:true,pointRadius:3},
  {label:'Quota',   data:tQ, borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,.05)',tension:.4,fill:true,pointRadius:3},
  {label:'Quality', data:tQL,borderColor:'#8b5cf6',backgroundColor:'rgba(139,92,246,.05)',tension:.4,fill:true,pointRadius:3},
],{scales:{x:{ticks:{font:{size:9}}},y:{beginAtZero:true,ticks:{font:{size:9}}}}});

const tots=[<?= intval($stats['completes']??0) ?>,<?= intval($stats['terminates']??0) ?>,<?= intval($stats['quotafull']??0) ?>,<?= intval($stats['quality']??0) ?>];
const tsum=tots.reduce((a,b)=>a+b,0);
mkChart('doughChart','doughnut',['Complete','Terminate','Quota','Quality/QC'],[
  {data:tsum?tots:[1,0,0,0],backgroundColor:['#22c55e','#ef4444','#f59e0b','#8b5cf6'],borderWidth:0}
],{cutout:'65%'});

mkChart('devChart','doughnut',
  devices.length?devices.map(d=>d.device):['No data'],
  [{data:devices.length?devices.map(d=>+d.cnt||0):[1],backgroundColor:['#1b4fd8','#3b82f6','#c8a84b','#8b5cf6'],borderWidth:0}],
  {cutout:'65%'});

const hd=new Array(24).fill(0);
hourly.forEach(h=>{hd[+h.hr]=+h.c||0});
const hLabels=Array.from({length:24},(_,i)=>i+'h');
mkChart('hrChart','bar',hLabels,[{label:'Completes',data:hd,backgroundColor:'rgba(27,79,216,.65)',borderRadius:3,borderSkipped:false}],
  {plugins:{legend:{display:false}},scales:{x:{ticks:{font:{size:8}}},y:{beginAtZero:true,ticks:{font:{size:9}}}}});

// Analytics tab charts
mkChart('trendChart2','line',tDays,[
  {label:'Complete', data:tC,borderColor:'#22c55e',backgroundColor:'rgba(34,197,94,.1)',tension:.4,fill:true,pointRadius:4},
  {label:'Terminate',data:tT,borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.05)',tension:.4,fill:true,pointRadius:4},
],{scales:{x:{ticks:{font:{size:10}}},y:{beginAtZero:true,ticks:{font:{size:10}}}}});

mkChart('hrChart2','bar',hLabels,[{label:'All',data:hd,backgroundColor:'rgba(27,79,216,.6)',borderRadius:3}],
  {plugins:{legend:{display:false}},scales:{x:{ticks:{font:{size:9}}},y:{beginAtZero:true,ticks:{font:{size:9}}}}});

mkChart('countryChart','bar',
  countries.length?countries.map(c=>c.country):['No data'],
  [{label:'Responses',data:countries.map(c=>+c.cnt||0),backgroundColor:'rgba(20,184,166,.7)',borderRadius:3}],
  {indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{font:{size:9}}},y:{ticks:{font:{size:9}}}}});

mkChart('sourceChart','bar',
  sources.length?sources.map(s=>s.source):['No data'],
  [{label:'Traffic',data:sources.map(s=>+s.cnt||0),backgroundColor:'rgba(200,168,75,.7)',borderRadius:3}],
  {indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{font:{size:9}}},y:{ticks:{font:{size:9}}}}});

// Tab switch — track activeTabName (for iframe refresh protection)
function sw(name,btn,skipHistory){
  activeTabName = name;
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  const pane = document.getElementById('tab-'+name);
  if(!pane) return; // unknown/hidden tab (e.g. Team when not superadmin) — stay put
  pane.classList.add('active');
  if(!btn){
    // find the matching nav button by its onclick attribute, so hash-restore
    // on page load highlights the right tab too
    btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => (b.getAttribute('onclick')||'').includes("sw('"+name+"'"));
  }
  if(btn) btn.classList.add('active');
  // Keep the URL hash in sync with the visible tab, as a real history entry
  // (so Back/Forward navigates between tabs) — unless this call itself came
  // from a Back/Forward action (skipHistory), to avoid a push loop.
  if (!skipHistory && window.location.hash !== '#'+name) {
    history.pushState(null, '', '#'+name);
  }
  resetRefreshTimer(); // naya tab khola = activity
}

function setSearchMode(mode){
  const quickPane = document.getElementById('modeQuickPane');
  const bulkPane = document.getElementById('modeBulkPane');
  const quickBtn = document.getElementById('modeQuickBtn');
  const bulkBtn = document.getElementById('modeBulkBtn');
  if (!quickPane) return;
  if (mode === 'bulk') {
    quickPane.style.display = 'none'; bulkPane.style.display = '';
    bulkBtn.style.background = 'var(--blue2)'; bulkBtn.style.color = '#fff';
    quickBtn.style.background = '#e2e8f0'; quickBtn.style.color = '#475569';
  } else {
    bulkPane.style.display = 'none'; quickPane.style.display = '';
    quickBtn.style.background = 'var(--blue2)'; quickBtn.style.color = '#fff';
    bulkBtn.style.background = '#e2e8f0'; bulkBtn.style.color = '#475569';
  }
}
function runQuickSearch(e){
  e.preventDefault();
  const q = document.getElementById('quickSearchInput').value.trim();
  const area = document.getElementById('slResultsArea');
  if (!q) { return false; }
  area.innerHTML = '<div style="text-align:center;padding:30px;color:#94a3b8">Searching...</div>';
  fetch('ajax_search.php?gs_query=' + encodeURIComponent(q))
    .then(r => r.text())
    .then(html => { area.innerHTML = html; })
    .catch(() => { area.innerHTML = '<div style="text-align:center;padding:30px;color:#dc2626">Search failed — try again.</div>'; });
  return false;
}
function runBulkCheck(e){
  e.preventDefault();
  const sid = document.getElementById('bulkSidSelect').value;
  const uids = document.getElementById('bulkUidsInput').value.trim();
  const area = document.getElementById('slResultsArea');
  if (!uids) { return false; }
  area.innerHTML = '<div style="text-align:center;padding:30px;color:#94a3b8">Checking...</div>';
  const body = new URLSearchParams({ check_uids: '1', ul_sid: sid, ul_uids: uids });
  fetch('ajax_search.php', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body })
    .then(r => r.text())
    .then(html => { area.innerHTML = html; })
    .catch(() => { area.innerHTML = '<div style="text-align:center;padding:30px;color:#dc2626">Check failed — try again.</div>'; });
  return false;
}
function toggleSidebar(){
  const sb = document.getElementById('appSidebar');
  const ac = document.getElementById('appContent');
  sb.classList.toggle('collapsed');
  ac.classList.toggle('sidebar-collapsed');
  localStorage.setItem('exz_sidebar_collapsed', sb.classList.contains('collapsed') ? '1' : '0');
}
(function(){
  if (localStorage.getItem('exz_sidebar_collapsed') === '1') {
    document.getElementById('appSidebar').classList.add('collapsed');
    document.getElementById('appContent').classList.add('sidebar-collapsed');
  }
})();

// Restore active tab from URL hash after any redirect (e.g. after Save/Delete)
window.addEventListener('DOMContentLoaded', function(){
  const hash = (window.location.hash || '').replace('#','');
  if(hash && document.getElementById('tab-'+hash)){
    sw(hash, null, true);
  }
});

// Browser Back/Forward — since tab switches now push history entries,
// listen for popstate and switch to whatever tab the hash now points to.
window.addEventListener('popstate', function(){
  const hash = (window.location.hash || '').replace('#','');
  if(hash && document.getElementById('tab-'+hash)){
    sw(hash, null, true);
  } else {
    sw('overview', null, true);
  }
});

// Auto-tag every form submit and GET-link click with the currently active
// tab, so server-side redirects (including permission errors) can bring
// the user back to where they were instead of defaulting to Overview.
document.addEventListener('submit', function(e){
  const form = e.target;
  if (form && form.tagName === 'FORM') {
    let retInput = form.querySelector('input[name="ret_tab"]');
    if (!retInput) {
      retInput = document.createElement('input');
      retInput.type = 'hidden';
      retInput.name = 'ret_tab';
      form.appendChild(retInput);
    }
    retInput.value = activeTabName || 'overview';
  }
}, true);

document.addEventListener('mousedown', function(e){
  // Runs on mousedown (before the click's default navigation begins) rather
  // than a capture-phase click listener — mutating an <a>'s href mid-click
  // (even in the capture phase) can cause the browser to silently drop the
  // pending navigation entirely in some engines, since the href it reads for
  // the default action and the href after this listener runs can end up out
  // of sync. mousedown always fires safely before that navigation starts.
  const a = e.target.closest ? e.target.closest('a[href^="?"]') : null;
  if (a && !a.href.includes('ret_tab=')) {
    const [base, hash] = a.getAttribute('href').split('#');
    const joiner = base.includes('?') ? '&' : '?';
    a.setAttribute('href', base + joiner + 'ret_tab=' + (activeTabName || 'overview') + (hash ? '#'+hash : ''));
  }
}, true);

// Filter
function ft(){
  const st  =document.getElementById('fSt').value.toLowerCase();
  const pr  =document.getElementById('fPr').value.toLowerCase();
  const dv  =document.getElementById('fDv').value.toLowerCase();
  const src =document.getElementById('fSrc').value.toLowerCase();
  const cl  =document.getElementById('fCl').value.toLowerCase();
  const vd  =document.getElementById('fVd').value;
  const srch=document.getElementById('fsrch').value.toLowerCase();
  const rows=document.querySelectorAll('#mainTbl tbody tr[data-st]');
  let vis=0;
  rows.forEach(r=>{
    const ok=(!st||r.dataset.st===st)
           &&(!pr||r.dataset.pr===pr)
           &&(!dv||r.dataset.dv===dv)
           &&(!src||r.dataset.srctype===src)
           &&(!cl||r.dataset.cl===cl)
           &&(!vd||r.dataset.vd===vd)
           &&(!srch||r.dataset.s.includes(srch));
    r.style.display=ok?'':'none';
    if(ok)vis++;
  });
  document.getElementById('rowCount').textContent=vis+' responses';
}

// Toggle projects
function toggleProj(btn){
  const ex=document.getElementById('extraProj');
  if(!ex)return;
  const open=ex.style.maxHeight&&ex.style.maxHeight!=='0px';
  if(!open){ex.style.maxHeight=ex.scrollHeight+300+'px';ex.style.opacity='1';btn.textContent='▲ Hide Older';}
  else{ex.style.maxHeight='0';ex.style.opacity='0';btn.textContent='▼ Show All (<?= max(0,count($projects)-4) ?> more)';}
}

// Modal
function openModal(sid,tgt,cpi,vcost){
  document.getElementById('modal_sid').value=sid;
  document.getElementById('modal_target').value=tgt||'';
  document.getElementById('modal_cpi').value=cpi||'';
  document.getElementById('modal_vcost').value=vcost||'';
  document.getElementById('settingsModal').classList.add('open');
}
function closeModal(){document.getElementById('settingsModal').classList.remove('open');}


// Select all checkboxes
function selAll(checked){
  document.querySelectorAll('.del-chk').forEach(c=>{ c.checked=checked; });
  const chkAll=document.getElementById('chkAll');
  if(chkAll)chkAll.checked=checked;
}

// Delete confirmation
function confirmDelete(){
  const checked=document.querySelectorAll('.del-chk:checked');
  if(checked.length===0){alert('Please select an entry first.');return;}
  const confirmMsg='⚠️ You are about to permanently delete '+checked.length+' entr'+(checked.length===1?'y':'ies')+'.\n\nThis action CANNOT be undone!\n\nAre you sure?';
  if(confirm(confirmMsg)){
    document.getElementById('delForm').submit();
  }
}

// Copy link
function cpLink(id,btn){
  navigator.clipboard.writeText(document.getElementById(id).textContent).then(()=>{
    btn.textContent='✓ Copied'; btn.style.background='#22c55e';
    setTimeout(()=>{btn.textContent='Copy';btn.style.background='';},2000);
  });
}

// Clocks
function clocks(){
  const n=new Date();
  document.getElementById('istClock').textContent=n.toLocaleTimeString('en-IN',{timeZone:'Asia/Kolkata',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
  document.getElementById('etClock').textContent =n.toLocaleTimeString('en-US',{timeZone:'America/New_York',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
  document.getElementById('utcClock').textContent=n.toLocaleTimeString('en-GB',{timeZone:'UTC',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
}
clocks(); setInterval(clocks,1000);

// ── Smart Idle Refresh ────────────────────────────────────────────
// 1. Input/Textarea/Select focus   -> PAUSED
// 2. Any checkbox ticked            -> PAUSED
// 3. Modal open                     -> PAUSED
// 4. TP or Feasibility tab active   -> PAUSED (iframe events don't reach parent)
// 5. Recent click on iframe (30s)   -> PAUSED
// 6. 120s genuine idle              -> refresh

const IDLE_SEC = 120;
let refreshDeadline = Date.now() + IDLE_SEC * 1000;
let idleTimer;
let activeTabName = 'overview';
let iframeLastActivity = 0;

function isUserBusy() {
  const el = document.activeElement;
  if (el) {
    const tag = el.tagName;
    if (['INPUT','TEXTAREA','SELECT'].includes(tag)) return true;
    if (el.isContentEditable) return true;
    if (tag === 'IFRAME') return true;
  }
  if (document.querySelectorAll('.del-chk:checked').length > 0) return true;
  if (document.querySelector('.modal-overlay.open')) return true;
  if (activeTabName === 'tp' || activeTabName === 'feasibility') return true;
  if (Date.now() - iframeLastActivity < 30000) return true;
  return false;
}

function resetRefreshTimer() {
  refreshDeadline = Date.now() + IDLE_SEC * 1000;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(tryRefresh, IDLE_SEC * 1000);
}

function tryRefresh() {
  if (isUserBusy()) { idleTimer = setTimeout(tryRefresh, 3000); return; }
  location.reload();
}

['click','keydown','keyup','scroll','touchstart','change','focusin','focusout','pointerdown']
  .forEach(ev => document.addEventListener(ev, resetRefreshTimer, { passive: true }));

// Iframe click detect: when the parent window blurs and the active element is an iframe
window.addEventListener('blur', function() {
  if (document.activeElement && document.activeElement.tagName === 'IFRAME') {
    iframeLastActivity = Date.now();
    resetRefreshTimer();
  }
});

resetRefreshTimer();

// ── Countdown display ──────────────────────────────────────────────
const liveEl = document.querySelector('.live-dot')?.parentElement;
setInterval(function() {
  if (isUserBusy()) {
    if (liveEl) liveEl.innerHTML = '<span class="live-dot" style="background:#f59e0b"></span>⏸ Paused';
    return;
  }
  const secsLeft = Math.max(0, Math.round((refreshDeadline - Date.now()) / 1000));
  if (liveEl) liveEl.innerHTML = '<span class="live-dot"></span>' + secsLeft + 's';
}, 1000);
</script>
<!-- Vendor Entry/Short Links Modal -->
<div class="modal-overlay" id="vendorLinksModal" style="display:none;position:fixed;inset:0;background:rgba(10,22,40,.6);align-items:center;justify-content:center;z-index:1000">
  <div class="modal" style="max-width:600px;background:#fff;border-radius:12px;padding:24px;width:100%">
    <button type="button" onclick="document.getElementById('vendorLinksModal').style.display='none'" style="float:right;background:none;border:none;font-size:20px;cursor:pointer;color:#94a3b8">×</button>
    <div style="font-family:'Bebas Neue',sans-serif;font-size:18px;letter-spacing:1px;color:var(--navy);margin-bottom:8px">Vendor Entry Links</div>
    <div id="vendorLinksName" style="font-size:12px;color:#64748b;margin-bottom:16px"></div>
    <div style="margin-bottom:12px">
      <div style="font-size:11px;font-weight:600;color:#334155;margin-bottom:4px">Entry Link (standard)</div>
      <div style="background:#f8faff;border:1px solid #e2e8f0;border-radius:6px;padding:8px 10px;font-family:monospace;font-size:11px;word-break:break-all;color:#1e293b" id="vendorEntryLink"></div>
      <button type="button" style="margin-top:4px;background:rgba(27,79,216,.1);color:var(--blue);border:none;border-radius:5px;padding:5px 12px;font-size:11px;cursor:pointer" onclick="copyClientUrl('vendorEntryLink')">Copy</button>
    </div>
    <div style="margin-bottom:4px">
      <div style="font-size:11px;font-weight:600;color:#334155;margin-bottom:4px">✂️ Short Link (optional, same destination)</div>
      <div style="background:#f8faff;border:1px solid #e2e8f0;border-radius:6px;padding:8px 10px;font-family:monospace;font-size:11px;word-break:break-all;color:#1e293b" id="vendorShortLink"></div>
      <button type="button" style="margin-top:4px;background:rgba(168,85,247,.12);color:#a855f7;border:none;border-radius:5px;padding:5px 12px;font-size:11px;cursor:pointer" onclick="copyClientUrl('vendorShortLink')">Copy</button>
    </div>
  </div>
</div>

<!-- Client Redirect URLs Modal -->
<div class="modal-overlay" id="clientRedirectModal" style="display:none;position:fixed;inset:0;background:rgba(10,22,40,.6);align-items:center;justify-content:center;z-index:1000">
  <div class="modal" style="max-width:600px;background:#fff;border-radius:12px;padding:24px;width:100%">
    <button type="button" onclick="document.getElementById('clientRedirectModal').style.display='none'" style="float:right;background:none;border:none;font-size:20px;cursor:pointer;color:#94a3b8">×</button>
    <div style="font-family:'Bebas Neue',sans-serif;font-size:18px;letter-spacing:1px;color:var(--navy);margin-bottom:8px">Client Redirect URLs</div>
    <div id="clientRedirectName" style="font-size:12px;color:#64748b;margin-bottom:4px"></div>
    <div style="font-size:12px;color:#64748b;margin-bottom:16px">
      Give these 4 URLs to this client ONCE — they'll keep working correctly for every future project you assign this client to, with no per-project edits ever needed.
    </div>
    <?php foreach (['Complete','Terminate','Overquota','Quality Fail'] as $label): ?>
    <div style="margin-bottom:12px">
      <div style="font-size:11px;font-weight:600;color:#334155;margin-bottom:4px"><?= $label ?></div>
      <div style="background:#f8faff;border:1px solid #e2e8f0;border-radius:6px;padding:8px 10px;font-family:monospace;font-size:11px;word-break:break-all;color:#1e293b" id="clientRedirectUrl_<?= strtolower(str_replace(' ','',$label)) ?>"></div>
      <button type="button" style="margin-top:4px;background:rgba(27,79,216,.1);color:var(--blue);border:none;border-radius:5px;padding:5px 12px;font-size:11px;cursor:pointer" onclick="copyClientUrl('clientRedirectUrl_<?= strtolower(str_replace(' ','',$label)) ?>')">Copy</button>
    </div>
    <?php endforeach; ?>
  </div>
</div>


</body>
</html>
<?php
function showLogin($error=false){?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Exazon Research — Dashboard Login</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'DM Sans',sans-serif;background:#0a1628;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#112040;border:1px solid rgba(59,130,246,.2);border-radius:16px;padding:40px 32px;max-width:360px;width:100%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.3)}
.logo{width:56px;height:56px;border-radius:50%;object-fit:cover;border:2px solid rgba(59,130,246,.4);margin:0 auto 16px}
h1{font-family:'Bebas Neue',sans-serif;font-size:24px;letter-spacing:3px;color:#fff;margin-bottom:4px}
.sub{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#c8a84b;margin-bottom:28px}
input[type=password]{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(59,130,246,.25);border-radius:8px;padding:12px 16px;font-family:'DM Sans',sans-serif;font-size:16px;color:#fff;outline:none;text-align:center;letter-spacing:6px;margin-bottom:14px}
input[type=password]:focus{border-color:#3b82f6}
button{width:100%;background:linear-gradient(135deg,#1b4fd8,#3b82f6);color:#fff;border:none;border-radius:8px;padding:13px;font-family:'Bebas Neue',sans-serif;font-size:16px;letter-spacing:3px;cursor:pointer}
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:6px;padding:8px;color:#fca5a5;font-size:12px;margin-bottom:14px}
.brand{margin-top:20px;font-size:10px;color:rgba(255,255,255,.2)}
</style>
</head>
<body>
<div class="card">
  <img src="logo.php" class="logo" alt="ExaVerify">
  <h1>Dashboard</h1>
  <div class="sub">Exazon Research · Secure Access</div>
  <?php if($error): ?><div class="err">Incorrect PIN. Try again.</div><?php endif; ?>
  <form method="POST">
    <input type="password" name="pin" placeholder="Enter PIN" autofocus>
    <button type="submit">Access Dashboard</button>
  </form>
  <div class="brand">© 2026 Exazon Research LLP</div>
</div>
</body>
</html>
<?php }

function showTeamLogin($error=false){?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Exazon Research — Team Login</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'DM Sans',sans-serif;background:#0a1628;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#112040;border:1px solid rgba(59,130,246,.2);border-radius:16px;padding:40px 32px;max-width:360px;width:100%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.3)}
.logo{width:56px;height:56px;border-radius:50%;object-fit:cover;border:2px solid rgba(59,130,246,.4);margin:0 auto 16px}
h1{font-family:'Bebas Neue',sans-serif;font-size:24px;letter-spacing:3px;color:#fff;margin-bottom:4px}
.sub{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#c8a84b;margin-bottom:28px}
input[type=text],input[type=password]{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(59,130,246,.25);border-radius:8px;padding:12px 16px;font-family:'DM Sans',sans-serif;font-size:14px;color:#fff;outline:none;margin-bottom:12px}
input:focus{border-color:#3b82f6}
button{width:100%;background:linear-gradient(135deg,#1b4fd8,#3b82f6);color:#fff;border:none;border-radius:8px;padding:13px;font-family:'Bebas Neue',sans-serif;font-size:16px;letter-spacing:3px;cursor:pointer;margin-top:4px}
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:6px;padding:8px;color:#fca5a5;font-size:12px;margin-bottom:14px}
.brand{margin-top:20px;font-size:10px;color:rgba(255,255,255,.2)}
label{display:block;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#94a3b8;text-align:left;margin-bottom:5px}
</style>
</head>
<body>
<div class="card">
  <img src="logo.php" class="logo" alt="ExaVerify">
  <h1>Team Login</h1>
  <div class="sub">Exazon Research · ExaVerify Panel</div>
  <?php if($error): ?><div class="err">Incorrect email or password.</div><?php endif; ?>
  <form method="POST">
    <input type="hidden" name="team_login" value="1">
    <label>Email</label>
    <input type="text" name="team_email" placeholder="you@exazonresearch.com" autofocus required>
    <label>Password</label>
    <input type="password" name="team_password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
  <div class="brand">© 2026 Exazon Research LLP</div>
</div>
</body>
</html>
<?php }

