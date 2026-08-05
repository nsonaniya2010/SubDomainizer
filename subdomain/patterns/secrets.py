import re

# Substrings that mark a matched value as a placeholder, not a real secret.
# Checked in Python after a regex match — avoids an expensive lookahead in the
# regex itself and keeps the pattern simple.
_GENERIC_VALUE_BLACKLIST = frozenset([
    'proptypes.', 'process.', 'this.', 'config.', 'key.',
    'null', 'undefined', 'true', 'false', 'none', 'nan', 'empty',
    'example', 'sample', 'placeholder', 'changeme', 'replace',
    'your_', 'yoursecret', 'insert_', 'enter_', 'put_your',
    'xxxxxxx', 'aaaaaaa', '1111111', '0000000',
    '<your', '<api', '<token', '<key', '<secret',
    'todo', 'fixme', 'test', 'dummy', 'fake',
    # Known safe fetch/XHR credential values
    'same-origin', 'same_origin', 'include', 'omit', 'no-cors',
])

# Regex: pure human-readable identifier — only letters + underscore + hyphen,
# zero digits. Real secrets almost always contain at least one digit.
_PURE_IDENTIFIER_RE = re.compile(r'^[a-zA-Z][a-zA-Z_-]*$')


def is_generic_placeholder(value: str) -> bool:
    """Return True when a generic-regex match value is clearly a non-secret.

    Covers five broad categories:
      1. Too short to be a real secret (<6 chars)
      2. Property access chains  (obj.prop, t.getMpConfig)
      3. JS boolean/negation prefix  (!!, ~)
      4. Pure human-readable identifier with no digits  (same-origin, first_name)
      5. URL path (starts with / and has 2+ slashes)
      6. Known blacklist substrings
    """
    if len(value) < 6:
        return True
    # Property access — real secrets don't contain a dot that isn't a URL
    if '.' in value and not value.startswith(('http://', 'https://', 'ftp://')):
        return True
    # JS negation / bitwise-not expression
    if value[0] in ('!', '~'):
        return True
    # Pure identifier: only letters + _ + -, no digits → variable/field name
    if _PURE_IDENTIFIER_RE.match(value):
        return True
    # Relative URL path
    if value.startswith('/') and value.count('/') >= 2:
        return True
    v = value.lower()
    for token in _GENERIC_VALUE_BLACKLIST:
        if token in v:
            return True
    return False


def compile_generic_secret_regex():
    """Generic keyword=value pattern with Shannon entropy filtering.

    Catches custom/unknown credential names that named patterns miss.
    Placeholder filtering is done separately via is_generic_placeholder().
    """
    seclst = [
        'secret', 'secret[_-]?key', 'secret[_-]?token', 'token',
        'password', 'passwd', 'pass', 'pwd', 'pword', 'pass_?word',
        'aws[_-]?access[_-]?key[_-]?id', 'aws[_-]?secret[_-]?access[_-]?key',
        'auth[-_]?token', 'access[-_]?token', 'auth[-_]?key', 'access[-_]?key',
        'client[-_]?secret', 'client[_-]?key', 'client[_-]?id',
        'api[_-]?key', 'api[-_]?secret', 'api[-_]?token',
        'encryption[-_]?key', 'private[_-]?key', 'consumer[_-]?key',
        'consumer[_-]?secret', 'ssh[-_]?key', 'id_dsa',
        'authorization', 'bearer',
        'credential', 'credentials', 'service[_-]?account',
        'GITHUB[_-]?TOKEN', 'SLACK_BOT_TOKEN',
        'irc_pass', 'xoxa-2', 'xoxr',
        'session[_-]?token', 'session[_-]?key', 'session[_-]?secret',
        'slack[_-]?token', 'database[_-]?url', 'db[_-]?pass(?:word)?',
        'webhook[_-]?(?:url|secret|token)',
        'refresh[_-]?token', 'id[_-]?token', 'oauth[_-]?(?:token|secret)',
        'jwt[_-]?(?:secret|token|key)?', 'app[_-]?(?:secret|key)',
        'master[_-]?(?:key|secret)', 'connection[_-]?string',
        'private', 'priv[_-]?key', 'signing[_-]?(?:key|secret)',
        'encryption[_-]?(?:key|secret)', 'hmac[_-]?(?:key|secret)',
    ]
    equal = ['=', ':', '=>', '=:', '==']
    regex = (
        r'(["\']?[\w\-]*(?:' + '|'.join(seclst) + r')[\w\-]*[\s]*["\']?[\s]*(?:'
        + '|'.join(equal) + r')[\s]*["\']?([\w\-/~!@#$%^*+.]+=*)["\']?)'
    )
    return re.compile(regex, re.MULTILINE | re.IGNORECASE)


def compile_specific_secret_patterns():
    """Named high-confidence patterns for well-known credential formats.

    Sources: TruffleHog v3 detectors + detect-secrets (Yelp) plugins.
    No entropy filtering needed — format specificity is sufficient signal.

    Returns a list of (service_name, compiled_regex) tuples where
    group(1) of each match is the credential value.
    """
    return [
        # ── AWS ──────────────────────────────────────────────────────────
        ("AWS Access Key ID",
         re.compile(r'\b((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\b')),
        ("AWS Secret Access Key",
         re.compile(r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[\s]*[=:"\'\s]+([A-Za-z0-9/+=]{40})\b')),

        # ── Google / GCP ─────────────────────────────────────────────────
        ("Google API Key",
         re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b')),
        ("Google OAuth Token",
         re.compile(r'\b(ya29\.[0-9A-Za-z\-_]{20,})\b')),
        ("Google Service Account",
         re.compile(r'"type"\s*:\s*"service_account"')),

        # ── Azure ────────────────────────────────────────────────────────
        ("Azure Storage Account Key",
         re.compile(r'AccountKey=([a-zA-Z0-9+/=]{88})', re.IGNORECASE)),
        ("Azure Connection String",
         re.compile(r'(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;"\'\s]+)', re.IGNORECASE)),
        ("Azure SAS Token",
         re.compile(r'(?i)(sv=\d{4}-\d{2}-\d{2}[^"\'\s]*sig=[A-Za-z0-9%/+=]{20,})')),

        # ── Cloudflare ───────────────────────────────────────────────────
        ("Cloudflare API Key",
         re.compile(r'(?i)cloudflare[^\n]{0,40}([0-9a-f]{37})\b')),

        # ── Source Control ───────────────────────────────────────────────
        ("GitHub Token",
         re.compile(r'\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59})\b')),
        ("GitLab Token",
         re.compile(
             r'\b((?:glpat|gldt|glft|glsoat|glrt|glcbt)-[A-Za-z0-9_\-]{20,300}'
             r'|GR1348941[A-Za-z0-9_\-]{20,50}'
             r'|glimt-[A-Za-z0-9_\-]{25}'
             r'|glptt-[A-Za-z0-9_\-]{40}'
             r'|glagent-[A-Za-z0-9_\-]{50,1024}'
             r'|gloas-[A-Za-z0-9_\-]{64})\b'
         )),
        ("Bitbucket App Password",
         re.compile(r'\b(ATBB[A-Za-z0-9]{32,})\b')),

        # ── Communication / Messaging ────────────────────────────────────
        ("Slack Token",
         re.compile(r'(xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-zA-Z0-9]+)', re.IGNORECASE)),
        ("Slack Webhook URL",
         re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{24,})')),
        ("Discord Bot Token",
         re.compile(r'\b([MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})\b')),
        ("Telegram Bot Token",
         re.compile(r'(?<![A-Za-z0-9_\-])([0-9]{8,10}:[0-9A-Za-z_\-]{35})(?![A-Za-z0-9_\-])')),

        # ── Payments ─────────────────────────────────────────────────────
        ("Stripe Key",
         re.compile(r'\b([rs]k_(?:live|test)_[a-zA-Z0-9]{20,247})\b')),
        ("Stripe Webhook Secret",
         re.compile(r'\b(whsec_[a-zA-Z0-9]{32,})\b')),
        ("Square Access Token",
         re.compile(r'\b(sq0atp-[0-9A-Za-z\-_]{22})\b')),
        ("Square OAuth Secret",
         re.compile(r'\b(sq0csp-[0-9A-Za-z\-_]{43})\b')),
        ("Shopify Token",
         re.compile(r'\b(shp(?:pa|ss|at|ca|rc)_[0-9a-fA-F]{32})\b')),
        ("Braintree Access Token",
         re.compile(r'\b(access_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32})\b')),
        ("PayPal Secret",
         re.compile(r'(?i)paypal[^\n]{0,30}(?:secret|key|token)[^\n]{0,10}[=:"\'\s]+([A-Za-z0-9\-_]{16,64})')),

        # ── Email / SMS ──────────────────────────────────────────────────
        ("Twilio Account SID",
         re.compile(r'\b(AC[0-9a-f]{32})\b')),
        ("Twilio Auth Token",
         re.compile(r'\b(SK[0-9a-f]{32})\b')),
        ("SendGrid API Key",
         re.compile(r'\b(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})\b')),
        ("Mailchimp API Key",
         re.compile(r'\b([0-9a-f]{32}-us[0-9]{1,2})\b')),
        ("Mailgun API Key",
         re.compile(r'\b(key-[0-9a-z]{32})\b')),

        # ── Monitoring / Observability ────────────────────────────────────
        ("New Relic License Key",
         re.compile(r'\b(NRJS-[a-f0-9]{39}|eu01xx[a-f0-9]{32}|[a-f0-9]{32}NRAL)\b', re.IGNORECASE)),
        ("New Relic Ingest Key",
         re.compile(r'\b([A-Za-z0-9]{32}NRAL)\b')),
        ("Datadog API Key",
         re.compile(r'(?i)(?:datadog|dd)[^\n]{0,30}(?:api[_\-\s]*key|secret)[^\n]{0,10}[=:"\'\s]+([a-f0-9]{32})\b')),
        ("Sentry DSN",
         re.compile(r'\b(https://[0-9a-f]{32}@o[0-9]+\.ingest(?:\.us)?\.sentry\.io/[0-9]+)\b', re.IGNORECASE)),

        # ── AI / ML ──────────────────────────────────────────────────────
        ("Anthropic API Key",
         re.compile(r'\b(sk-ant-(?:api03-)?[A-Za-z0-9\-_]{93,})\b')),
        ("OpenAI API Key (legacy)",
         re.compile(r'\b(sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,})\b')),
        ("OpenAI API Key",
         re.compile(r'\b(sk-(?:proj|svcacct)-[A-Za-z0-9\-_]{40,})\b')),
        ("HuggingFace Token",
         re.compile(r'\b(hf_[a-zA-Z0-9]{34})\b')),

        # ── Dev / CI / Package Registries / Platforms ────────────────────
        ("npm Token",
         re.compile(r'\b(npm_[0-9a-zA-Z]{36})\b')),
        ("npm Registry Auth Token",
         re.compile(r'//.+/:_authToken=\s*((npm_[a-zA-Z0-9]+)|([A-Fa-f0-9\-]{36}))')),
        ("PyPI Token",
         re.compile(r'\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{70,}|pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9\-_]{70,})\b')),
        ("Databricks Token",
         re.compile(r'\b(dapi[a-h0-9]{32})\b')),
        ("HashiCorp Vault Token",
         re.compile(r'\b(hvs\.[A-Za-z0-9_\-]{90,}|hvb\.[A-Za-z0-9_\-]{138,})\b')),
        ("Terraform Cloud Token",
         re.compile(r'\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,})\b')),
        ("Linear API Key",
         re.compile(r'\b(lin_api_[0-9a-zA-Z]{40})\b')),
        ("Figma Token",
         re.compile(r'\b(figd_[0-9a-zA-Z_\-]{43})\b')),
        ("Postman API Key",
         re.compile(r'\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b')),
        ("Vercel Token",
         re.compile(r'\b(vercel_[a-zA-Z0-9]{24,})\b', re.IGNORECASE)),
        ("Render API Key",
         re.compile(r'\b(rnd_[A-Za-z0-9]{32,})\b')),
        ("Doppler Token",
         re.compile(r'\b(dp\.(?:pt|ct|st)\.[A-Za-z0-9]{40,})\b')),
        ("JFrog Artifactory Token",
         re.compile(r'(?:^|[\s=:"\'`])((AKC[a-zA-Z0-9]{10,}|AP[0-9A-F][a-zA-Z0-9]{8,}))(?:[\s"\'`]|$)')),
        ("IBM Cloud IAM Key",
         re.compile(r'(?i)(?:ibm|iam|cloud)[^\n]{0,30}(?:api[_\-\s]*)?(?:key|password|token)[^\n]{0,10}[=:"\'\s]+([a-zA-Z0-9_\-]{44})(?![a-zA-Z0-9_\-])')),
        ("IBM COS HMAC Key",
         re.compile(r'(?i)(?:ibm|cos|hmac)[^\n]{0,20}secret[_\-\s]*(?:access[_\-\s]*)?key[^\n]{0,10}[=:"\'\s]+([a-f0-9]{48})(?![a-f0-9])')),
        ("SoftLayer Credentials",
         re.compile(r'(?i)(?:softlayer|sl)[^\n]{0,20}(?:api[_\-\s]*)?(?:key|password|token)[^\n]{0,10}[=:"\'\s]+([a-z0-9]{64})(?![a-z0-9])')),
        ("DigitalOcean Token",
         re.compile(r'(?i)digital[_\-\s]*ocean[^\n]{0,30}(?:token|key)[^\n]{0,10}[=:"\'\s]+([0-9a-f]{64})\b')),
        ("Mapbox Token",
         re.compile(r'\b((?:pk|sk)\.eyJ1[A-Za-z0-9\-_=.]{30,})\b')),

        # ── Social / Identity ─────────────────────────────────────────────
        ("Facebook OAuth Token",
         re.compile(r'\b(EAA[A-Za-z0-9]{20,})\b')),
        ("Okta API Token",
         re.compile(r'(?i)okta[^\n]{0,30}(?:api[_\-\s]*token|ssws)[^\n]{0,10}[=:"\'\s]+(SSWS[A-Za-z0-9_\-]{32,}|[A-Za-z0-9_\-]{42})')),

        # ── Auth / Cryptographic ──────────────────────────────────────────
        ("JSON Web Token",
         re.compile(r'\b(eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,})\b')),
        ("Private Key",
         re.compile(
             r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |SSH2 ENCRYPTED )?PRIVATE KEY(?:[^\-]*)-----'
             r'|BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |SSH2 ENCRYPTED )?PRIVATE KEY'
             r'|BEGIN PGP PRIVATE KEY BLOCK'
             r'|PuTTY-User-Key-File-2)'
         )),

        # ── Credentials embedded in URLs ─────────────────────────────────
        ("Credentials in URL",
         re.compile(r'\b(https?://[^:\s/?#]{3,}:[^@\s/?#]{3,}@[^\s/?#]+)\b')),
    ]
