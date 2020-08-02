#!/usr/bin/env python

import argparse
import pickle
import requests
import yaml

from bs4 import BeautifulSoup
from datetime import datetime
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.http import MediaFileUpload
from os import remove
from os.path import exists


month_numbers = {
    'Jan': '01',
    'Feb': '02',
    'Mar': '03',
    'Apr': '04',
    'May': '05',
    'Jun': '06',
    'Jul': '07',
    'Aug': '08',
    'Sep': '09',
    'Oct': '10',
    'Nov': '11',
    'Dec': '12',
}


def get_setting(setting_name):
    """
    Get a setting from the settings.yaml file
    :param setting_name: name of the setting
    :return: value of the setting
    """

    if not exists('settings.yaml'):
        print('settings.yaml not found\n')
        return None

    file = open('settings.yaml', 'r')

    yaml_data = yaml.safe_load(file)

    return yaml_data.get(setting_name)


def authenticate_google_drive():
    """
    Authenticate to Google drive
    :return: authenticated drive object
    """

    scopes = ['https://www.googleapis.com/auth/drive']

    credentials = None

    if exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            credentials = pickle.load(token)

    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', scopes)
            credentials = flow.run_local_server(port=0)

        with open('token.pickle', 'wb') as token:
            pickle.dump(credentials, token)

    service = build('drive', 'v3', credentials=credentials)

    return service


def build_folder_tree(drive, folder_name, folder_id):
    """
    Build a folder tree dictionary from Google Drive
    :param drive: google drive object
    :return: dict folder tree
    """

    tree = {'name': folder_name, 'id': folder_id, 'contents': []}

    page_token = None

    while True:
        response = drive.files().list(q="'{}' in parents and trashed=false".format(folder_id),
                                      spaces='drive', fields='nextPageToken, files(id, name, mimeType, parents, trashed)',
                                      pageToken=page_token).execute()

        for file in response.get('files', []):

            if file.get('mimeType') == 'application/vnd.google-apps.folder':
                tree['contents'].append(build_folder_tree(drive, file.get('name'), file.get('id')))
            else:
                tree['contents'].append(file.get('name'))

        page_token = response.get('nextPageToken', None)

        if page_token is None:
            break

    return tree


def find_home_folder(tree, filename):
    """
    Find the home folder for a filename in the folder tree
    :param tree: google drive folder tree
    :param filename: video file name
    :return: home folder id
    """

    month, year = month_numbers.get(filename.split('-')[1]), filename.split('-')[2]

    for check_year in tree.get('contents'):
        if check_year.get('name') != year:
            continue
        for check_month in check_year.get('contents'):
            if check_month.get('name') == month:
                if filename in check_month.get('contents'):
                    return 'exists'
                else:
                    return check_month.get('id')

    return year, month


def get_video_links(gamertag, game_name=None, all_videos=False, limit=0):
    """
    Pull a list of video page URLs from an index page
    :param gamertag: gamertag
    :param game_name: game name filter (default: None)
    :param all_videos: scan/upload all videos instead of recent (default: False)
    :param limit: number to download (default: 0/unlimited)
    :return: list of individual video page URLs
    """

    videos = []

    count = 0

    index_url = get_setting('index_url').replace('%USER%', gamertag)
    base_url = get_setting('base_url')

    index = BeautifulSoup(requests.get(index_url).text, 'html.parser')

    for entry in index.find_all('div', {'class': 'large-3'}):

        name = entry.find_next('b').text

        if game_name and game_name.lower() not in name.lower():
            continue

        video_url = entry.find_next('a').get('href')

        new_page = BeautifulSoup(requests.get(base_url + video_url).text, 'html.parser')

        date = new_page.find_all('li')[0].text.split('Recorded: ')[1].replace(':', '-').replace(' ', '-')

        month, year = month_numbers.get(date.split('-')[1]), date.split('-')[2]
        current_month, current_year = datetime.today().month, datetime.today().year

        skip = False

        if current_month == 1:
            if int(year) < (current_year - 1) or int(year) == (current_year - 1) and int(month) < 12:
                skip = True
        else:
            if int(year) < current_year or int(month) < (current_month - 1):
                skip = True

        if skip:
            continue

        link = new_page.find_all('source')[0].get('src')

        strip_chars = [' ', ':', '®', '™']

        for char in strip_chars:
            name = name.replace(char, '') if char in name else name

        filename = '{}_{}_{}'.format(gamertag.capitalize(), name, date)

        if (filename, link) not in videos:
            videos.append((filename, link))

        count += 1

        if limit and count >= limit:
            break

    return videos


def download_video(video_link, video_name):
    """
    Download a video locally
    :param video_link: URL to the video
    :param video_name: name of the video (used for filename)
    :return: True if file exists after download, False if not
    """

    print('downloading: {}'.format(video_name))

    if exists('{}{}'.format(get_setting('temp_dir'), video_name)):
        return True

    dl = requests.get(video_link, stream=True)

    with open('{}{}'.format(get_setting('temp_dir'), video_name), "wb") as download:
        for chunk in dl.iter_content(chunk_size=1024 * 1024):
            if chunk:
                download.write(chunk)

    if exists('{}{}'.format(get_setting('temp_dir'), video_name)):
        return True

    else:
        print('failure')
        return False


def upload_video_to_google_drive(google_drive, folder_id, filename):
    """
    Upload a video to Google Drive
    :param google_drive: Google Drive API object
    :param folder_id: folder to upload to
    :param filename: name of the file to upload
    :return: True if file exists after upload, False if not
    """

    print('{}: uploading to drive... '.format(filename), end='')

    file_metadata = {'name': filename, 'parents': [folder_id], 'mimeType': 'video/mp4'}
    media = MediaFileUpload('{}{}'.format(get_setting('temp_dir'), filename), mimetype='video/mp4', resumable=True)
    file = google_drive.files().create(body=file_metadata, media_body=media, fields='id').execute()

    return True if file.get('id') else False


def create_folder(google_drive, tree, year, month):
    """
    Create a folder for a new year and/or month
    :param google_drive: google drive object
    :param tree: existing folder tree
    :param year: year
    :param month: month
    :return: folder ID
    """

    year_folder = None

    i = 0

    for check_year in tree.get('contents'):
        if check_year.get('name') == year:
            year_folder = i
        else:
            i += 1

    if not year_folder:
        print('creating year {}'.format(year))
        new_id = google_drive.files().create(
            body={
                'name': year,
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [tree.get('id')],
            },
            fields='id').execute().get('id')
        tree['contents'].append({'name': year, 'id': new_id, 'contents': []})
        year_folder = i

    for check_month in tree.get('contents')[year_folder]:
        if check_month == month:
            return check_month.get('id')

    print('creating month {} (parent: {})'.format(month, tree.get('contents')[year_folder].get('id')))
    new_id = google_drive.files().create(
        body={
            'name': month,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [tree.get('contents')[year_folder].get('id')],
        },
        fields='id').execute().get('id')

    tree.get('contents')[i]['contents'].append({'name': month, 'id': new_id, 'contents': []})

    return tree, new_id


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='argument parser')

    parser.add_argument('-t', '--tag',
                        help='gamertag to download',
                        action='store',
                        type=str,
                        required=True)

    parser.add_argument('-g', '--game',
                        help='game name',
                        action='store',
                        type=str,
                        default=None)

    parser.add_argument('-l', '--limit',
                        help='number to download',
                        action='store',
                        type=int,
                        default=0)

    parser.add_argument('-a', '--all',
                        help='process all videos instead of last two months',
                        action='store_true')

    parser.add_argument('-v', '--verbose',
                        help='show extra messaging',
                        action='store_true')

    args = parser.parse_args()

    folder_id = get_setting('drive_folder_id')

    if args.verbose:
        print('Authenticating to Google Drive...')

    drive = authenticate_google_drive()

    if args.verbose:
        print('Building existing folder tree...')

    folder_tree = build_folder_tree(drive, get_setting('drive_folder_name'), get_setting('drive_folder_id'))

    if args.verbose:
        print('Building video list...')

    video_links = get_video_links(args.tag, args.game, args.all, args.limit)

    for video in video_links:

        home = find_home_folder(folder_tree, video[0])

        if isinstance(home, tuple):
            folder_tree, home = create_folder(drive, folder_tree, home[0], home[1])

        elif home == 'exists':
            if args.verbose:
                print('{}: already exists in drive, skipping'.format(video[0]))
            continue

        print('downloading: {}'.format(video[0]))

        downloaded = download_video(video[1], video[0])

        if downloaded:
            print('uploading: {}'.format(video[0]))
            uploaded = upload_video_to_google_drive(drive, home, video[0])

            if uploaded:
                print('deleting: {}{}'.format(get_setting('temp_dir'), video[0]))
                remove('{}{}'.format(get_setting('temp_dir'), video[0]))

        else:
            continue

