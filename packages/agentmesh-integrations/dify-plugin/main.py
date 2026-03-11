import logging

logging.basicConfig(level=logging.INFO)

from dify_plugin import DifyPluginEnv, Plugin

plugin = Plugin(DifyPluginEnv())
plugin.run()
