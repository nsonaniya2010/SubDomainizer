import re


def compile_cloud_patterns():
    """Precompiled regexes to detect cloud/PaaS/SaaS service URLs in scanned content.

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
    aws_amplify    = re.compile(r'([\w\-]+\.amplifyapp\.com)', F)
    aws_rds        = re.compile(r'([\w\-]+\.[\w\-]+\.rds\.amazonaws\.com)', F)
    aws_sagemaker  = re.compile(r'([\w\-]+\.sagemaker\.aws)', F)
    aws_transfer   = re.compile(r'([\w\-]+\.transfer\.amazonaws\.com)', F)

    # ── Google Cloud / Firebase ───────────────────────────────────────────────
    gcp_appengine  = re.compile(r'([\w\-.]+\.appspot\.com)', F)
    gcp_gcs1       = re.compile(r'(storage\.cloud\.google\.com/[\w\-.]+)', F)
    gcp_gcs2       = re.compile(r'([\w\-.]*\.?storage\.googleapis\.com/?[\w\-.]*)', F)
    gcp_gcs3       = re.compile(r'([\w\-.]*\.?storage-download\.googleapis\.com/?[\w\-.]*)', F)
    gcp_gcs4       = re.compile(r'([\w\-.]*\.?content-storage-upload\.googleapis\.com/?[\w\-.]*)', F)
    gcp_gcs5       = re.compile(r'([\w\-.]*\.?content-storage-download\.googleapis\.com/?[\w\-.]*)', F)
    gcp_cloudrun   = re.compile(r'([\w\-]+\.run\.app)', F)
    gcp_functions  = re.compile(r'([\w\-]+\.cloudfunctions\.net)', F)
    gcp_apis       = re.compile(r'([\w\-]+\.googleapis\.com)', F)
    gcp_maps       = re.compile(r'(maps\.google(?:apis)?\.com)', F)
    gcp_fonts      = re.compile(r'(fonts\.(?:googleapis|gstatic)\.com)', F)
    gcp_gtm        = re.compile(r'((?:www\.)?googletagmanager\.com)', F)
    gcp_analytics  = re.compile(r'((?:www\.)?google-analytics\.com|analytics\.google\.com)', F)
    firebase_db    = re.compile(r'([\w\-.]+\.firebaseio\.com)', F)
    firebase_store = re.compile(r'(firebasestorage\.googleapis\.com/v0/b/[\w\-.]+)', F)
    firebase_host  = re.compile(r'([\w\-]+\.web\.app|[\w\-]+\.firebaseapp\.com)', F)

    # ── Azure ─────────────────────────────────────────────────────────────────
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
    az_frontdoor   = re.compile(r'([\w\-.]+\.azurefd\.net)', F)
    az_keyvault    = re.compile(r'([\w\-.]+\.vault\.azure\.net)', F)
    az_devops      = re.compile(r'(dev\.azure\.com/[\w\-]+)', F)
    az_cosmos      = re.compile(r'([\w\-.]+\.documents\.azure\.com)', F)

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
    replit         = re.compile(r'([\w\-]+\.repl\.co)', F)
    glitch         = re.compile(r'([\w\-]+\.glitch\.me)', F)

    # ── CDN providers ─────────────────────────────────────────────────────────
    jsdelivr       = re.compile(r'(cdn\.jsdelivr\.net(?:/[\w\-.@/]*)?)', F)
    unpkg          = re.compile(r'(unpkg\.com/[\w\-.@/]*)', F)
    cdnjs          = re.compile(r'(cdnjs\.cloudflare\.com(?:/[\w\-.@/]*)?)', F)
    fastly         = re.compile(r'([\w\-.]+\.fastly\.net)', F)
    akamai         = re.compile(r'([\w\-.]+\.akamai(?:hd|zed)?\.net|[\w\-.]+\.(?:edgekey|edgesuite)\.net)', F)
    bunny_cdn      = re.compile(r'([\w\-.]+\.b-cdn\.net)', F)
    bootstrapcdn   = re.compile(r'([\w\-.]*bootstrapcdn\.com(?:/[\w\-.@/]*)?)', F)
    imgix          = re.compile(r'([\w\-]+\.imgix\.net)', F)
    cloudimage     = re.compile(r'([\w\-]+\.cloudimg\.io)', F)

    # ── Monitoring / Observability ────────────────────────────────────────────
    sentry         = re.compile(r'([\w\-]+\.(?:ingest\.)?sentry\.io)', F)
    datadog        = re.compile(r'([\w\-.]+\.datadoghq\.(?:com|eu))', F)
    newrelic       = re.compile(r'([\w\-.]+\.newrelic\.com)', F)
    segment        = re.compile(r'([\w\-.]+\.segment\.(?:com|io))', F)
    mixpanel       = re.compile(r'([\w\-.]+\.mixpanel\.com)', F)
    amplitude      = re.compile(r'([\w\-.]+\.amplitude\.com)', F)
    hotjar         = re.compile(r'([\w\-.]+\.hotjar\.com)', F)
    logrocket      = re.compile(r'([\w\-.]+\.logrocket\.io)', F)
    elastic_apm    = re.compile(r'([\w\-.]+\.apm\.(?:us|eu)-[\w\-]+\.aws\.elastic\.cloud)', F)
    grafana_cloud  = re.compile(r'([\w\-.]+\.grafana\.net)', F)

    # ── Auth / Identity ───────────────────────────────────────────────────────
    auth0          = re.compile(r'([\w\-]+\.auth0\.com)', F)
    okta           = re.compile(r'([\w\-]+\.okta(?:preview)?\.com)', F)
    clerk          = re.compile(r'([\w\-]+\.clerk\.(?:accounts|dev|app)|clerk\.dev)', F)
    onelogin       = re.compile(r'([\w\-]+\.onelogin\.com)', F)
    pingidentity   = re.compile(r'([\w\-]+\.pingone\.com)', F)

    # ── Search ────────────────────────────────────────────────────────────────
    algolia        = re.compile(r'([\w\-]+\.algolia\.net|[\w\-]+\.algolianet\.com)', F)
    elasticsearch  = re.compile(r'([\w\-]+\.es\.io|[\w\-]+\.found\.io|[\w\-]+\.elastic\.co)', F)
    typesense      = re.compile(r'([\w\-]+\.a1\.typesense\.net)', F)

    # ── Database-as-a-service ─────────────────────────────────────────────────
    mongodb_atlas  = re.compile(r'([\w\-]+\.mongodb\.net)', F)
    planetscale    = re.compile(r'([\w\-]+\.psdb\.cloud)', F)
    neon_db        = re.compile(r'([\w\-]+\.neon\.tech)', F)
    turso          = re.compile(r'([\w\-]+\.turso\.io)', F)
    upstash        = re.compile(r'([\w\-]+\.upstash\.io)', F)
    cockroachdb    = re.compile(r'([\w\-]+\.cockroachlabs\.cloud)', F)

    # ── Maps ──────────────────────────────────────────────────────────────────
    mapbox         = re.compile(r'([\w\-]+\.api\.mapbox\.com|api\.mapbox\.com)', F)
    here_maps      = re.compile(r'([\w\-.]+\.hereapi\.com|[\w\-.]+\.api\.here\.com|api\.here\.com)', F)
    tomtom         = re.compile(r'(api\.tomtom\.com)', F)

    # ── Communication / Messaging ─────────────────────────────────────────────
    twilio         = re.compile(r'([\w\-]+\.twilio\.com)', F)
    sendgrid_api   = re.compile(r'(api\.sendgrid\.com)', F)
    mailgun_api    = re.compile(r'(api\.mailgun\.net)', F)
    intercom       = re.compile(r'([\w\-]+\.intercom(?:cdn)?\.(?:io|com))', F)
    zendesk        = re.compile(r'([\w\-]+\.zendesk\.com)', F)
    freshdesk      = re.compile(r'([\w\-]+\.freshdesk\.com)', F)

    # ── Payment ───────────────────────────────────────────────────────────────
    stripe_api     = re.compile(r'(api\.stripe\.com)', F)
    razorpay       = re.compile(r'(api\.razorpay\.com|checkout\.razorpay\.com)', F)
    braintree_api  = re.compile(r'(api\.braintreegateway\.com)', F)

    # ── Legacy / Other CDN ────────────────────────────────────────────────────
    rackcdn        = re.compile(r'([\w\-.]+\.rackcdn\.com(?:/[\w\-.]*)?)', F)
    dreamhost1     = re.compile(r'([\w\-.]+\.objects\.cdn\.dream\.io(?:/[\w\-.]*)?)', F)
    dreamhost2     = re.compile(r'([\w\-.]+\.objects-us-west-1\.dream\.io(?:/[\w\-.]*)?)', F)

    return [
        # AWS
        aws_s3, aws_s3_vhost, aws_cf, aws_apigw, aws_appsync, aws_beanstalk,
        aws_cognito, aws_ecr, aws_opensearch, aws_iot, aws_lambda_url, aws_elb,
        aws_amplify, aws_rds, aws_sagemaker, aws_transfer,
        # GCP / Firebase
        gcp_appengine, gcp_gcs1, gcp_gcs2, gcp_gcs3, gcp_gcs4, gcp_gcs5,
        gcp_cloudrun, gcp_functions, gcp_apis, gcp_maps, gcp_fonts,
        gcp_gtm, gcp_analytics,
        firebase_db, firebase_store, firebase_host,
        # Azure
        az_blob, az_webapp, az_cdn, az_sql, az_acr, az_static, az_openai,
        az_onedrive1, az_onedrive2, az_servicebus, az_frontdoor, az_keyvault,
        az_devops, az_cosmos,
        # DigitalOcean
        do_spaces, do_app,
        # Hosting / PaaS
        heroku, vercel, netlify, render, fly_io, railway, supabase,
        github_pages, cf_workers, cf_pages, replit, glitch,
        # CDNs
        jsdelivr, unpkg, cdnjs, fastly, akamai, bunny_cdn, bootstrapcdn,
        imgix, cloudimage,
        # Monitoring
        sentry, datadog, newrelic, segment, mixpanel, amplitude, hotjar,
        logrocket, elastic_apm, grafana_cloud,
        # Auth
        auth0, okta, clerk, onelogin, pingidentity,
        # Search
        algolia, elasticsearch, typesense,
        # Database SaaS
        mongodb_atlas, planetscale, neon_db, turso, upstash, cockroachdb,
        # Maps
        mapbox, here_maps, tomtom,
        # Communication
        twilio, sendgrid_api, mailgun_api, intercom, zendesk, freshdesk,
        # Payment
        stripe_api, razorpay, braintree_api,
        # Legacy CDN
        rackcdn, dreamhost1, dreamhost2,
    ]
