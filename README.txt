IZEL - upload every file in this zip to the TOP LEVEL of a fresh GitHub repo (no folders).
Then create ONE folder on GitHub: api/index.js  -> paste the text from api-code.txt.
Vercel: Framework Preset "Other", build + output empty.
Env vars: AUTH_SECRET, SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_EMAILS (your email), RESEND_API_KEY, CRON_SECRET
Optional: MAIL_FROM (needs a verified domain), PAYSTACK_SECRET_KEY, PAYSTACK_PUBLIC_KEY, GOOGLE_CLIENT_ID, APPLE_CLIENT_ID
Testing only: OTP_DEV=1, OVERRIDE_CODE=JAY (type JAY as email and as code). Remove both before launch.
Admin: after signing in as an admin, add #review (review queue) or #dev (developer side) to the address.
