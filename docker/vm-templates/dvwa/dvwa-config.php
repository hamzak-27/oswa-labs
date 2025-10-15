<?php

# CyberLab DVWA Configuration
# Modified for container-based VM deployment

# Database configuration
$_DVWA[ 'db_server' ]   = 'localhost';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'password123';

# Only allow to run over HTTPS
$_DVWA[ 'https' ] = false;

# Default security level
# Default: impossible
# Legal: low, medium, high, impossible
$_DVWA[ 'default_security_level' ] = 'low';

# Default PHPIDS status
# Default: disabled
# Legal: enabled, disabled
$_DVWA[ 'default_phpids_level' ] = 'disabled';

# Verbose PHPIDS messages
# Default: disabled
# Legal: enabled, disabled
$_DVWA[ 'default_phpids_verbose' ] = 'disabled';

# ReCAPTCHA settings
# Used for the 'Insecure CAPTCHA' module
# You'll need to generate your own keys at: https://www.google.com/recaptcha/admin/create
$_DVWA[ 'recaptcha_public_key' ]  = '';
$_DVWA[ 'recaptcha_private_key' ] = '';

# Default user credentials
# These will be created when DVWA is set up
$_DVWA[ 'default_user_id' ] = 'admin';
$_DVWA[ 'default_password' ] = 'password';

# CyberLab specific settings
$_DVWA[ 'cyberlab_mode' ] = true;
$_DVWA[ 'cyberlab_session_id' ] = getenv('CYBERLAB_SESSION_ID') ?: 'unknown';
$_DVWA[ 'cyberlab_user_id' ] = getenv('CYBERLAB_USER_ID') ?: 'unknown';

# Flag management
$_DVWA[ 'flag_user' ] = getenv('FLAG_USER') ?: 'HTB{default_user_flag}';
$_DVWA[ 'flag_root' ] = getenv('FLAG_ROOT') ?: 'HTB{default_root_flag}';

?>
