import configparser


global MQTT_HOST, MQTT_PORT, server_host, server_port

config = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
config.read('config.ini',encoding='utf-8')

MQTT_HOST = config.get('Mqtt', 'broker')
MQTT_PORT = config.getint('Mqtt', 'port')

server_host = config.get('Server', 'host')
server_port = config.getint('Server', 'port')