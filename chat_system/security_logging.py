"""Internal metadata-only tracing; never attach content or credentials."""
from contextvars import ContextVar
import logging

attempt_id = ContextVar('security_attempt_id', default='standalone')
url_request = ContextVar('security_url_request', default=None)
llm_failure = ContextVar('security_llm_failure', default='none')
log = logging.getLogger('chat.security')


def stage(name, **metadata):
    log.info('security attempt_id=%s stage=%s %s', attempt_id.get(), name,
             ' '.join(f'{key}={value}' for key, value in metadata.items()))
