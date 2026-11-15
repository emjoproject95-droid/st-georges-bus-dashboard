# St George's encrypted collections site

Upload `index.html` and `cloud-app.js` to the root of a GitHub repository. Then open Settings > Pages, choose Deploy from a branch, select your default branch and `/ (root)`, and save. GitHub publishes the static site from that branch and folder. Official guide: https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site

The Supabase Project URL and publishable key are preconfigured in `cloud-app.js`. The publishable key is intended for browser use; never add a secret or service-role key to the repository. Configure the database by running `st-georges-database-setup.sql` separately, then create admin and driver Auth users. The site's public page requires sign-in, and row-level database policies restrict who can read reports.
