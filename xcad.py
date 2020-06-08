#!/usr/bin/env python

import argparse
import yaml
import requests

from bs4 import BeautifulSoup
from os import remove
from os.path import exists

from pydrive.drive import GoogleDrive
from pydrive.auth import GoogleAuth


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

    return yaml_data.get('xcad_settings').get(setting_name)


def write_to_log(data, print_to_screen=False):
    """
    Write data to log file
    :param data: data to log (string)
    :param print_to_screen: print to screen also? (boolean)
    :return: nothing
    """

    log = open(get_setting('log_file'), 'a')
    log.write(data)
    log.close()

    if print_to_screen:
        print(data)


def authenticate_google_drive():
    """
    Authenticate to Google drive
    :return: authenticated drive object
    """

    gauth = GoogleAuth()

    gauth.LoadCredentialsFile(get_setting('credentials_file'))

    if gauth.credentials is None:
        print('Credentials not found. Please click this link to authenticate:\n')
        print(gauth.GetAuthUrl())
        code = input('Code: ')
        gauth.Auth(code)

    elif gauth.access_token_expired:
        gauth.Refresh()

    else:
        gauth.Authorize()

    gauth.SaveCredentialsFile(get_setting('credentials_file'))

    google_drive = GoogleDrive(gauth)

    return google_drive


def check_file_exists_in_drive_folder(google_drive, filename):
    """
    Check if a filename exists in Google Drive
    :param google_drive: Google Drive object
    :param filename: filename to check for
    :return: True if exists, False if not
    """

    drive_folder_id = get_setting('drive_folder_id')

    file_list = google_drive.ListFile({'q': "'{}' in parents and trashed=false".format(drive_folder_id)}).GetList()

    file_names = [f['title'] for f in file_list]

    return filename in file_names


def get_video_links(gamertag, game_name=None, limit=0):
    """
    Pull a list of video page URLs from an index page
    :param gamertag: gamertag
    :param game_name: game name filter (optional)
    :param limit: number to download (optional)
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
        link = new_page.find_all('source')[0].get('src')

        strip_chars = [' ', ':', '®', '™']

        for char in strip_chars:
            name = name.replace(char, '') if char in name else name

        filename = '{}_{}_{}'.format(gamertag.capitalize(), name, date)

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

    tmp_dir = get_setting('tmp_dir')

    print('{}: downloading to local... '.format(video_name), end='')

    if exists('{}{}'.format(get_setting('tmp_dir'), video_name)):
        print('already exists')
        return True

    dl = requests.get(video_link, stream=True)

    with open('{}{}'.format(tmp_dir, video_name), "wb") as download:
        for chunk in dl.iter_content(chunk_size=1024 * 1024):
            if chunk:
                download.write(chunk)

    if exists('{}{}'.format(tmp_dir, video_name)):
        print('success')
        return True

    else:
        print('failure')
        return False


def upload_video_to_google_drive(video_name, google_drive):
    """
    Upload a video to Google Drive
    :param video_name: video filename
    :param google_drive: Google Drive API object
    :return: True if file exists after upload, False if not
    """

    tmp_dir = get_setting('tmp_dir')

    print('{}: uploading to drive... '.format(video_name), end='')

    if check_file_exists_in_drive_folder(google_drive, video_name):
        print('already exists')
        return True

    f = drive.CreateFile({
        'title': video_name,
        'parents': [{"kind": "drive#fileLink", "id": '16PmXsoNmWL8i2AdG5O3QgKS4VzhCBlg3'}]
    })

    f.SetContentFile('{}{}'.format(tmp_dir, video_name))
    f.Upload()
    f = None

    if check_file_exists_in_drive_folder(google_drive, video_name):
        print('success')
        if exists('{}{}'.format(tmp_dir, video[0])):
            remove('{}{}'.format(tmp_dir, video[0]))
        return True

    else:
        print('failure')
        return False


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

    args = parser.parse_args()

    folder_id = get_setting('drive_folder_id')

    drive = authenticate_google_drive()

    video_links = get_video_links(args.tag, args.game, args.limit)

    print(video_links)

    list_data = drive.ListFile({'q': "'{}' in parents and trashed=false".format(folder_id)}).GetList()

    for video in video_links:

        if check_file_exists_in_drive_folder(drive, video[0]):
            print('{}: already exists in drive, skipping'.format(video[0]))
            continue

        downloaded = download_video(video[1], video[0])

        if downloaded:
            uploaded = upload_video_to_google_drive(video[0], drive)

        else:
            continue

        write_to_log('file: {} downloaded: {} uploaded: {}'.format(video[0], downloaded, uploaded))
