XCAD

xbox clip auto downloader

- auto downloads uploaded Xbox Live clips
- auto uploads them to your Google Drive account

Setup:

1. Create an OAuth credentials for your Google Drive account: https://developers.google.com/adwords/api/docs/guides/authentication (choose desktop app as type)
2. Rename sample_settings.yaml to settings.yaml
3. Navigate to the destination folder in Google Drive and copy the ID from the end of the URL, insert that into settings.yaml (and change any other settings you want)

Usage:

python xcad.py -t gamertag -g "game name"

Options:

-l LIMIT: limit to X download/uploads
-a: process all videos (default is last two months)