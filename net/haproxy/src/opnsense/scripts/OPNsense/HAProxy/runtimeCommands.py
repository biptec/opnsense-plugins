"""HAProxy Runtime API command wrappers used by the OPNsense plugin scripts."""

from haproxy import cmds


class UpdateSslCrt(cmds.updateSslCrt):
    """Upload an SSL certificate using HAProxy's multiline payload framing."""

    def getCmd(self):
        payload = self.args["payload"].rstrip("\r\n")
        return (
            f"set ssl cert {self.args['certfile']} <<\n"
            f"{payload}\n\n"
        )
