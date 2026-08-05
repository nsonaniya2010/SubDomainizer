import re


def compile_cloud_patterns():
    """Precompiled regexes to detect cloud/PaaS service URLs in scanned content.

    Grouped by provider. Each pattern captures the full hostname (+ path where
    it forms part of the resource identifier).
    Returns a list of compiled regex objects.
    """
    F = re.MULTILINE | re.IGNORECASE

    # ── AWS ──────────────────────────────────────────────────────────────────
    aws_s3         = re.compile(r'(s3[\w\-.]*\.amazonaws\.com/?[\w\-.]*)', F)
    aws_s3_vhost   = re.compile(r'([\w\-]+\.s3[\w\-.]*\.amazonaws\.com/?)', F)
    aws_cf         = re.compile(r'([\w\-]+\.cloudfront\.net)', F)
    aws_apigw      = re.compile(r'([\w\-]+\.execute-api\.[\w\-]+\.amazonaws\.com(?:/[\w\-/]*)?)', F)
    aws_appsync    = re.compile(r'([\w\-]+\.appsync-api\.[\w\-]+\.amazonaws\.com)', F)
    aws_beanstalk  = re.compile(r'([\w\-]+\.[\w\-]+\.elasticbeanstalk\.com)', F)
    aws_cognito    = re.compile(r'([\w\-]+\.auth\.[\w\-]+\.amazoncognito\.com)', F)
    aws_ecr        = re.compile(r'([0-9]{12}\.dkr\.ecr\.[\w\-]+\.amazonaws\.com)', F)
    aws_opensearch = re.compile(r'([\w\-]+\.[\w\-]+\.(?:es|aoss)\.amazonaws\.com)', F)
    aws_iot        = re.compile(r'([\w\-]+\.iot\.[\w\-]+\.amazonaws\.com)', F)
    aws_lambda_url = re.compile(r'([\w\-]+\.lambda-url\.[\w\-]+\.on\.aws)', F)
    aws_elb        = re.compile(r'([\w\-]+\.(?:elb|alb|nlb)\.[\w\-]+\.amazonaws\.com)', F)

    # ── Google Cloud / Firebase ───────────────────────────────────────────────
    gcp_appengine  = re.compile(r'([\w\-.]+\.appspot\.com)', F)
    gcp_gcs1       = re.compile(r'(storage\.cloud\.google\.com/[\w\-.]+)', F)
    gcp_gcs2       = re.compile(r'([\w\-.]*\.?storage\.googleapis\.com/?[\w\-.]*)', F)
    gcp_gcs3       = re.compile(r'([\w\-.]*\.?storage-download\.googleapis\.com/?[\w\-.]*)', F)
    gcp_gcs4       = re.compile(r'([\w\-.]*\.?content-storage-upload\.googleapis\.com/?[\w\-.]*)', F)
    gcp_gcs5       = re.compile(r'([\w\-.]*\.?content-storage-download\.googleapis\.com/?[\w\-.]*)', F)
    gcp_cloudrun   = re.compile(r'([\w\-]+\.run\.app)', F)
    gcp_functions  = re.compile(r'([\w\-]+\.cloudfunctions\.net)', F)
    firebase_db    = re.compile(r'([\w\-.]+\.firebaseio\.com)', F)
    firebase_store = re.compile(r'(firebasestorage\.googleapis\.com/v0/b/[\w\-.]+)', F)
    firebase_host  = re.compile(r'([\w\-]+\.web\.app|[\w\-]+\.firebaseapp\.com)', F)

    # ── Azure ────────────────────────────────────────────────────────────────
    az_blob        = re.compile(r'([\w\-.]+\.blob\.core\.windows\.net(?:/[\w\-./]*)?)', F)
    az_webapp      = re.compile(r'([\w\-.]+\.azurewebsites\.net)', F)
    az_cdn         = re.compile(r'([\w\-.]+\.azureedge\.net)', F)
    az_sql         = re.compile(r'([\w\-.]+\.database\.windows\.net)', F)
    az_acr         = re.compile(r'([\w\-.]+\.azurecr\.io)', F)
    az_static      = re.compile(r'([\w\-.]+\.azurestaticapps\.net)', F)
    az_openai      = re.compile(r'([\w\-.]+\.openai\.azure\.com)', F)
    az_onedrive1   = re.compile(r'([\w\-.]+\.1drv\.com/?[\w\-.]*)', F)
    az_onedrive2   = re.compile(r'(onedrive\.live\.com/[\w.\-]+)', F)
    az_servicebus  = re.compile(r'([\w\-.]+\.servicebus\.windows\.net)', F)

    # ── DigitalOcean ──────────────────────────────────────────────────────────
    do_spaces      = re.compile(r'([\w\-.]+\.digitaloceanspaces\.com(?:/[\w\-.]*)?)', F)
    do_app         = re.compile(r'([\w\-]+\.ondigitalocean\.app)', F)

    # ── Hosting / PaaS platforms ──────────────────────────────────────────────
    heroku         = re.compile(r'([\w\-]+\.herokuapp\.com)', F)
    vercel         = re.compile(r'([\w\-]+\.vercel\.app|[\w\-]+\.now\.sh)', F)
    netlify        = re.compile(r'([\w\-]+\.netlify\.app|[\w\-]+\.netlify\.com)', F)
    render         = re.compile(r'([\w\-]+\.onrender\.com)', F)
    fly_io         = re.compile(r'([\w\-]+\.fly\.dev)', F)
    railway        = re.compile(r'([\w\-]+\.up\.railway\.app)', F)
    supabase       = re.compile(r'([\w\-]+\.supabase\.(?:co|in))', F)
    github_pages   = re.compile(r'([\w\-]+\.github\.io)', F)
    cf_workers     = re.compile(r'([\w\-]+\.workers\.dev)', F)
    cf_pages       = re.compile(r'([\w\-]+\.pages\.dev)', F)

    # ── Legacy / Other CDN ────────────────────────────────────────────────────
    rackcdn        = re.compile(r'([\w\-.]+\.rackcdn\.com(?:/[\w\-.]*)?)', F)
    dreamhost1     = re.compile(r'([\w\-.]+\.objects\.cdn\.dream\.io(?:/[\w\-.]*)?)', F)
    dreamhost2     = re.compile(r'([\w\-.]+\.objects-us-west-1\.dream\.io(?:/[\w\-.]*)?)', F)

    return [
        aws_s3, aws_s3_vhost, aws_cf, aws_apigw, aws_appsync, aws_beanstalk,
        aws_cognito, aws_ecr, aws_opensearch, aws_iot, aws_lambda_url, aws_elb,
        gcp_appengine, gcp_gcs1, gcp_gcs2, gcp_gcs3, gcp_gcs4, gcp_gcs5,
        gcp_cloudrun, gcp_functions,
        firebase_db, firebase_store, firebase_host,
        az_blob, az_webapp, az_cdn, az_sql, az_acr, az_static, az_openai,
        az_onedrive1, az_onedrive2, az_servicebus,
        do_spaces, do_app,
        heroku, vercel, netlify, render, fly_io, railway, supabase,
        github_pages, cf_workers, cf_pages,
        rackcdn, dreamhost1, dreamhost2,
    ]
