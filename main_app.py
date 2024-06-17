# -*- coding: utf-8 -*-
import base64
import os
import flask
import requests
import urllib.parse
import yt_dlp

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'REPLACE ME - this value is here as a placeholder.'
CLIENT = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
CALLBACK_URL = os.getenv("CALLBACK_URL")
import logging

logging.basicConfig(level=logging.INFO)




@app.route("/sync_songs",methods=["GET","POST"])
def sync_songs():
    if flask.request.method == "GET":

        if 'credentials' not in flask.session:
            return flask.redirect('authorize')
        if 'spotify_credentials' not in flask.session:
            return flask.redirect('spotify_authorize')

        return flask.render_template('index.html')

    elif flask.request.method == "POST":

        data = flask.request.form
        spotify_playlist_id = data['spotify_url'].split("/")[-1]
        youtube_playlist_id = data['youtube_url'].split("=")[1]
        return start_sync_process(youtube_playlist_id, spotify_playlist_id)


def start_sync_process(youtube_playlist, spotify_playlist):
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    youtube = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    channel = youtube.playlistItems().list(
        part="snippet,contentDetails",
        maxResults=25,
        playlistId=youtube_playlist
    ).execute()
    # Save credentials back to session in case access token was refreshed.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    flask.session['credentials'] = credentials_to_dict(credentials)

    new_spotify_ids = []
    for item in channel["items"]:
        newid = search_song_id_in_spotify(item["snippet"]["title"])["tracks"]["items"][0]["id"]
        new_spotify_id = f"spotify:track:{str(newid)}"
        new_spotify_ids.append(new_spotify_id)


    return add_new_songs_in_spotify_playlist(new_spotify_ids, spotify_playlist)

@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  youtube = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

  channel = youtube.playlistItems().list(
        part="snippet,contentDetails",
        maxResults=25,
        playlistId="PLxVeBpsv6PhJ29MiNZmIp2o0rrmKDesIV"
    ).execute()
  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)

  new_spotify_ids = []
  for item in channel["items"]:
      newid = search_song_id_in_spotify(item["snippet"]["title"])["tracks"]["items"][0]["id"]
      new_spotify_id = f"spotify:track:{str(newid)}"
      new_spotify_ids.append(new_spotify_id)

  return add_new_songs_in_spotify_playlist(new_spotify_ids,"5FkdrkCxkF2C6HsMFk2t9V")



def add_new_songs_in_spotify_playlist(songs_list, spotify_playlist):
    body = {"uris": songs_list}
    headers = {'Authorization': f'Bearer {flask.session["spotify_credentials"]["access_token"]}'}
    playlist_url = f"https://api.spotify.com/v1/playlists/{spotify_playlist}/tracks"
    newrequest = requests.post(playlist_url, json=body, headers=headers)
    if newrequest.status_code == 200:
        return "success"
    else:
        return "failed"


def refresh_spotify_token():
    try:
        flask.session.modified = True
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': flask.session["spotify_credentials"]['refresh_token']
        }
        encoded_credentials = base64.b64encode(f"{CLIENT}:{CLIENT_SECRET}".encode('utf-8')).decode("utf-8")
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {encoded_credentials}'
        }
        response = requests.post("https://accounts.spotify.com/api/token", data=data, headers=headers)
        logging.info(f'Refresh token response status code: {response.status_code}')

        if response.status_code == 200:
            new_credentials = response.json()
            flask.session["spotify_credentials"]['access_token'] = new_credentials['access_token']
            logging.info(f'Access token refreshed successfully. New token: {new_credentials["access_token"]}')
        else:
            logging.error(f'Failed to refresh token: {response.json()}')
            raise Exception('Failed to refresh token')

    except Exception as e:
        logging.error(f"An error occurred while refreshing the token: {e}")
        raise


def search_song_id_in_spotify(song):
    try:
        if "-" in song:
            track = song.split("-")[1].strip()
            artist = song.split("-")[0].strip()
            data = {"q": urllib.parse.quote(f'track:{track} artist:{artist}'), "type": "track", "limit": 1}
            headers = {"Authorization": f"Bearer {flask.session['spotify_credentials']['access_token']}"}
            url = 'https://api.spotify.com/v1/search'

            response = requests.get(url, params=data, headers=headers)
            logging.info(f'The status code is {response.status_code}')

            if response.status_code == 401:  # specifically check for unauthorized status
                logging.info("Token might be expired. Attempting to refresh the token.")
                refresh_spotify_token()
                # Fetch the updated token
                new_access_token = flask.session['spotify_credentials']['access_token']
                logging.info(f'Updated access token: {new_access_token}')
                headers = {"Authorization": f"Bearer {new_access_token}"}
                response = requests.get(url, params=data, headers=headers)
                logging.info(f'New response status code after token refresh: {response.status_code}')

            return response.json()
        else:
            logging.error("Song format is incorrect. It should be 'Artist - Track'.")
            return None

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return None


@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.')
  else:
    return('An error occurred.' )


@app.route('/clear')
def clear_credentials():
  if 'spotify_credentials' in flask.session:
    del flask.session['spotify_credentials']
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return 'Credentials have been cleared'


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}



# spotify code


@app.route("/spotify_authorize")
def spotify_authorize():
    scopes = 'playlist-modify-private playlist-modify-public'
    params = {"client_id":CLIENT, "response_type":"code",
              "redirect_uri": CALLBACK_URL,
              "show_dialog" : True,
              "scope": scopes
              }
    params_encoded = urllib.parse.urlencode(params)

    return flask.redirect(f'https://accounts.spotify.com/authorize?{params_encoded}')

@app.route("/spotify_callback")
def spotify_callback():
    newcode = flask.request.args.get("code")
    newtoken = request_access_token(newcode)
    flask.session["spotify_credentials"] = newtoken
    return flask.redirect(flask.url_for("sync_songs"))

@app.route("/spotify_after_callback")
def spotify_after_callback():
    return dict(flask.session)



def request_access_token(code):
    params = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": CALLBACK_URL

    }

    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        "Authorization": "Basic "+ base64.b64encode(f"{CLIENT}:{CLIENT_SECRET}".encode('utf-8')).decode('utf-8')


    }
    newpost_url = "https://accounts.spotify.com/api/token"
    newpost_request = requests.post(newpost_url,data=params, headers=headers)
    return newpost_request.json()





if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('0.0.0.0', 5000, debug=True)