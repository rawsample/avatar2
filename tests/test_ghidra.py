from avatar2 import GhidraTarget
from avatar2 import Avatar
from avatar2.archs import ARM


import logging

#from nose.tools import *


import shutil
from time import sleep



EXE='/home/sampl/tools/ghidra_9.2.4_PUBLIC/support/analyzeHeadless'
PROJECT_PATH='/tmp/ghidravatar/'
PROJECT_NAME='project-test'
SCRIPT_PATH ='~/ghidra_scripts'
FIRMWARE='/home/sampl/tools/avatartwo_avatar2/tests/binaries/hello_world'
FIRMWARE_2='hello_world'


# Clean the project
shutil.rmtree('/tmp/ghidravatar')


avatar = Avatar(arch=ARM, output_directory='/tmp/ghidravatar')
l = logging.getLogger('avatar')
l.setLevel('DEBUG')


ghidra = GhidraTarget(avatar, name='ghidra_test',
                      executable=EXE,
                      project_path=PROJECT_PATH,
                      project_name=PROJECT_NAME,
                      script_path=SCRIPT_PATH,
                      firmware=FIRMWARE,
                      to_import=True,
                      #firmware=FIRMWARE_2,
                      )
avatar.targets[ghidra.name] = ghidra

'''
home/sampl/tools/ghidra_9.2.4_PUBLIC/support/analyzeHeadless /tmp/ghidra ghidra-test \
        -import /home/sampl/tools/avatartwo_avatar2/tests/binaries/hello_world \
        -processor "x86:LE:64:default" \
        -scriptPath /home/sampl/ghidra_scripts/ \
        -postScript ghidra_bridge_server.py

        
        -processor "ARM:LE:32:Cortex" \
'''

print(avatar.targets)
avatar.init_targets()
print('Target init')
sleep(5)

avatar.shutdown()
sleep(5)

