"""
Parametrised tests for every named specific pattern and cloud URL pattern.
Each test provides a canonical sample that must be matched by the regex.
"""
import pytest
from subdomain.patterns.secrets import compile_specific_secret_patterns
from subdomain.patterns.cloud import compile_cloud_patterns


# ── Specific secrets ────────────────────────────────────────────────────────

_SPECIFIC_SAMPLES = [
    ("AWS Access Key ID",            "AKIAIOSFODNN7EXAMPLE"),
    ("AWS Secret Access Key",        "aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("Google API Key",               "AIzaSyD-9tSrke72I6e8BqbsD_oKXPpF3sGZ1xU"),
    ("Google OAuth Token",           "ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ("Google Service Account",       '"type": "service_account"'),
    ("Azure Storage Account Key",    "AccountKey=" + "A" * 86 + "=="),
    ("Azure Connection String",      "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc123"),
    ("Azure SAS Token",              "sv=2020-08-04&ss=b&srt=sco&sp=rwdlacupiytfx&se=2022-01-01T00:00:00Z&st=2021-01-01T00:00:00Z&spr=https&sig=abcdefghijklmnopqrstuvwxyz"),
    ("Cloudflare API Key",           "cloudflare api_key: " + "a" * 37),
    ("GitHub Token",                 "ghp_1234567890abcdefghijklmnopqrstuvwx12"),
    ("GitLab Token",                 "glpat-abcdefghij1234567890"),
    ("Bitbucket App Password",       "ATBBabcdefghijklmnopqrstuvwxyz123456"),
    ("Slack Token",                  "xoxb-111111111111-222222222222-abcdefghijklmnopqrstuvwx"),
    ("Slack Webhook URL",            "https://hooks.slack.com/services/TABC1234/BABC5678/abcdefghijklmnopqrstuvwxyz"),
    ("Discord Bot Token",            "MTk4NjIyNDgzNDcxOTI1MjQ4.YMnxvA.vYxTOIrG7N1igATvi_xcd31CiOo"),
    ("Telegram Bot Token",           "123456789:ABCdefGhIjKlMnOpQrStUvWxYzAbCdEfGh1"),
    ("Stripe Key",                   "sk_live_abcdefghijklmnopqrstu12345"),
    ("Stripe Webhook Secret",        "whsec_abcdefghijklmnopqrstuvwxyz12345678"),
    ("Square Access Token",          "sq0atp-abcdefghijklmnopqrstuv"),
    ("Square OAuth Secret",          "sq0csp-abcdefghijklmnopqrstuvwxyz12345678901234567"),
    ("Shopify Token",                "shppa_12345678901234567890123456789012"),
    ("Braintree Access Token",       "access_token$production$abc1234567890abc$abcdef1234567890abcdef1234567890"),
    ("Twilio Account SID",           "ACabcdef1234567890abcdef1234567890"),
    ("Twilio Auth Token",            "SKabcdef1234567890abcdef1234567890"),
    ("SendGrid API Key",             "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz12345678901234567"),
    ("Mailchimp API Key",            "abcdef1234567890abcdef1234567890-us12"),
    ("Mailgun API Key",              "key-abcdefghijklmnopqrstuvwxyz123456"),
    ("New Relic License Key",        "abcdef1234567890abcdef1234567890NRAL"),
    ("New Relic Ingest Key",         "abcdef1234567890abcdef1234567890NRAL"),
    ("Datadog API Key",              "datadog api_key: abcdef1234567890abcdef1234567890"),
    ("Sentry DSN",                   "https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/789"),
    ("Anthropic API Key",            "sk-ant-api03-" + "A" * 93),
    ("OpenAI API Key (legacy)",      "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20),
    ("OpenAI API Key",               "sk-proj-" + "A" * 40),
    ("HuggingFace Token",            "hf_" + "A" * 34),
    ("npm Token",                    "npm_" + "A" * 36),
    ("PyPI Token",                   "pypi-AgEIcHlwaS5vcmc" + "A" * 70),
    ("Databricks Token",             "dapi" + "a" * 32),
    ("HashiCorp Vault Token",        "hvs." + "A" * 90),
    ("Terraform Cloud Token",        "A" * 14 + ".atlasv1." + "B" * 60),
    ("Linear API Key",               "lin_api_" + "A" * 40),
    ("Figma Token",                  "figd_" + "A" * 43),
    ("Postman API Key",              "PMAK-" + "a" * 24 + "-" + "b" * 34),
    ("Render API Key",               "rnd_" + "A" * 32),
    ("Doppler Token",                "dp.pt." + "A" * 40),
    ("JFrog Artifactory Token",      " AKCabc1234567890 "),
    ("Mapbox Token",                 "pk.eyJ1" + "A" * 30),
    ("Facebook OAuth Token",         "EAA" + "A" * 20),
    ("JSON Web Token",               "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("Private Key",                  "-----BEGIN RSA PRIVATE KEY-----"),
    ("Credentials in URL",           "https://user:passw0rd@internal.example.com/api"),
]


@pytest.mark.parametrize("name,sample", _SPECIFIC_SAMPLES, ids=[s[0] for s in _SPECIFIC_SAMPLES])
def test_specific_pattern_matches(name, sample):
    patterns = dict(compile_specific_secret_patterns())
    assert name in patterns, f"Pattern '{name}' not found in compile_specific_secret_patterns()"
    pat = patterns[name]
    assert pat.search(sample) is not None, (
        f"Pattern '{name}' did not match sample: {sample!r}"
    )


# ── Cloud URL patterns ───────────────────────────────────────────────────────

_CLOUD_SAMPLES = [
    "s3.amazonaws.com/mybucket",
    "mybucket.s3.amazonaws.com/",
    "d1234abcdef.cloudfront.net",
    "abcde12345.execute-api.us-east-1.amazonaws.com/prod",
    "abcde12345.appsync-api.us-east-1.amazonaws.com",
    "myapp.us-east-1.elasticbeanstalk.com",
    "mypool.auth.us-east-1.amazoncognito.com",
    "123456789012.dkr.ecr.us-east-1.amazonaws.com",
    "myindex.us-east-1.es.amazonaws.com",
    "abc123.iot.us-east-1.amazonaws.com",
    "abc123xyz789.lambda-url.us-east-1.on.aws",
    "myalb-1234.elb.us-east-1.amazonaws.com",
    "myapp.appspot.com",
    "storage.cloud.google.com/mybucket",
    "storage.googleapis.com/mybucket",
    "myapp.run.app",
    "myfunction.cloudfunctions.net",
    "myproject.firebaseio.com",
    "firebasestorage.googleapis.com/v0/b/myproject",
    "myapp.web.app",
    "myaccount.blob.core.windows.net/container",
    "myapp.azurewebsites.net",
    "mycdn.azureedge.net",
    "myserver.database.windows.net",
    "myregistry.azurecr.io",
    "myapp.azurestaticapps.net",
    "myresource.openai.azure.com",
    "myaccount.servicebus.windows.net",
    "mybucket.nyc3.digitaloceanspaces.com",
    "myapp.ondigitalocean.app",
    "myapp.herokuapp.com",
    "myapp.vercel.app",
    "myapp.netlify.app",
    "myapp.onrender.com",
    "myapp.fly.dev",
    "myapp.up.railway.app",
    "myproject.supabase.co",
    "myuser.github.io",
    "myworker.workers.dev",
    "mysite.pages.dev",
    "myfiles.rackcdn.com",
    # AWS additions
    "myapp.amplifyapp.com",
    "mydb.cluster-abc123.us-east-1.rds.amazonaws.com",
    "myendpoint.sagemaker.aws",
    # GCP additions
    "maps.googleapis.com",
    "maps.google.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "www.googletagmanager.com",
    "www.google-analytics.com",
    "analytics.google.com",
    "translation.googleapis.com",
    # Azure additions
    "myapp.azurefd.net",
    "myvault.vault.azure.net",
    "dev.azure.com/myorg",
    "mydb.documents.azure.com",
    # Hosting additions
    "myapp.repl.co",
    "myapp.glitch.me",
    # CDNs
    "cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",
    "unpkg.com/react@18.0.0/index.js",
    "cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
    "myapp.fastly.net",
    "myapp.akamaihd.net",
    "myapp.akamaized.net",
    "myapp.edgekey.net",
    "myfiles.b-cdn.net",
    "maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css",
    "myimages.imgix.net",
    # Monitoring
    "o123456.ingest.sentry.io",
    "myorg.datadoghq.com",
    "myapp.newrelic.com",
    "api.segment.io",
    "api.mixpanel.com",
    "api2.amplitude.com",
    "static.hotjar.com",
    "cdn.logrocket.io",
    "myorg.grafana.net",
    # Auth
    "myapp.auth0.com",
    "mycompany.okta.com",
    "clerk.dev",
    "mycompany.onelogin.com",
    # Search
    "myapp-dsn.algolia.net",
    "myapp.algolianet.com",
    "myindex.es.io",
    "myapp.a1.typesense.net",
    # Database SaaS
    "mycluster.mongodb.net",
    "mydb.psdb.cloud",
    "mydb.neon.tech",
    "mydb.turso.io",
    "myredis.upstash.io",
    # Maps
    "api.mapbox.com",
    "geocoder.ls.hereapi.com",
    "api.here.com",
    "api.tomtom.com",
    # Communication
    "api.twilio.com",
    "api.sendgrid.com",
    "api.mailgun.net",
    "widget.intercom.io",
    "mycompany.zendesk.com",
    # Payment
    "api.stripe.com",
    "api.razorpay.com",
    "api.braintreegateway.com",
]


@pytest.mark.parametrize("sample", _CLOUD_SAMPLES)
def test_cloud_pattern_matches(sample):
    patterns = compile_cloud_patterns()
    matched = any(pat.search(sample) for pat in patterns)
    assert matched, f"No cloud pattern matched: {sample!r}"


# ── Generic regex ────────────────────────────────────────────────────────────

def test_generic_regex_matches_real_value(generic_pat):
    content = 'api_key = "realvalue123abc"'
    matches = list(generic_pat.finditer(content))
    assert len(matches) >= 1


def test_generic_regex_placeholder_blocked_by_filter(generic_pat):
    from subdomain.patterns.secrets import is_generic_placeholder
    content = 'api_key = "your_api_key_here"'
    for m in generic_pat.finditer(content):
        val = m.group(2)
        assert is_generic_placeholder(val), f"Placeholder should be blocked: {val!r}"
