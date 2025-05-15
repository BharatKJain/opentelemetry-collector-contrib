import logging
import wf_logging

wf_logging.configure('my_application', gelf_receiver="127.0.0.1")  # Only needs to be called once in the application's lifetime
logger = logging.getLogger(__name__)
logger.warning('uh oh spaghettios, this is gonna get logged to the Kibana short_message field!')
