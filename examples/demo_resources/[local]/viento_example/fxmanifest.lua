fx_version 'cerulean'
game 'gta5'
author 'cant0x'
description 'Example with intentional warnings and errors'
client_scripts {
    'client/*.lua',
    'missing.lua'
}
server_script 'server.lua'
ui_page 'html/index.html'
files { 'html/assets/*.css' }
dependency 'sample_utils'
