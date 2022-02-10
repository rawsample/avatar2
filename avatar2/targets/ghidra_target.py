from subprocess import Popen
from time import sleep


from avatar2.targets import Target, TargetStates
from avatar2.protocols.ghidra import GhidraBridgeProtocol

from avatar2.watchmen import watch



class GhidraTarget(Target):
    """
        TODO:
            - add remote server
            - save config to a file?
    """

    def __init__(self, avatar, 
            executable=None,
            project_path=None,
            project_name=None, 
            script_path='~/ghidra_scripts',
            firmware=None,
            to_import=False,
            additional_args=[],
            **kwargs,
        ):

        super(GhidraTarget, self).__init__(avatar, **kwargs)

        self.executable = executable
        self.project_path = project_path
        self.project_name = project_name
        self.script_path = script_path
        self.firmware = firmware
        self.to_import = to_import
        self.additional_args = additional_args

        self._process = None


    def assemble_cmd_line(self):

        # Mandatory args
        cmd_line = [self.executable, 
                    self.project_path, 
                    self.project_name,
                    '-scriptPath', self.script_path,
                    '-postScript', 'ghidra_bridge_server.py',
                    '-processor', self.avatar.arch.ghidra_arch
                    ]

        cmd_line += ['-import'] if self.to_import else ['-process']
        cmd_line += [self.firmware]

        # Optional args
        cmd_line += self.additional_args


        return cmd_line

    @watch("TargetInit")
    def init(self, cmd_line=None):

        if cmd_line is None:
            cmd_line = self.assemble_cmd_line()

        # TODO Save config?

        with open(
            "%s/%s_out.txt" % (self.avatar.output_directory, self.name), "wb"
        ) as out, open(
            "%s/%s_err.txt" % (self.avatar.output_directory, self.name), "wb"
        ) as err:
            self._process = Popen(cmd_line, stdout=out, stderr=err)
        self.log.debug("Ghidra command line: %s" % " ".join(cmd_line))
        self.log.info("Ghidra process running")

        # Must wait for the Ghidra process to finish init and start the ghidra bridge before connecting to it
        sleep(15)    
        gb = GhidraBridgeProtocol(self.avatar)

        #self.protocols.set_all(gb)
        self.protocols.bridge = gb

    def shutdown(self):
        if self._process is not None:
            self._process.terminate()
            self._process.wait()
            self._process = None
        super(GhidraTarget, self).shutdown()

