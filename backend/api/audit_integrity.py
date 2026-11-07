import hashlib
import hmac
import json
import os

from django.conf import settings


GENESIS_HASH = '0' * 64


def audit_payload(event, previous_hash):
    return json.dumps(
        {
            'id': event.pk,
            'user_id': event.user_id,
            'actor_username': event.actor_username,
            'file_id': event.file_id,
            'file_title': event.file_title,
            'file_owner_id': event.file_owner_id,
            'file_owner_username': event.file_owner_username,
            'action': event.action,
            'outcome': event.outcome,
            'ip_address': event.ip_address,
            'timestamp': event.timestamp.isoformat(),
            'details': event.details,
            'previous_hash': previous_hash,
        },
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    )


def sign_audit_event(event, previous_hash):
    key = settings.AUDIT_LOG_HMAC_KEY.encode('utf-8')
    return hmac.new(
        key,
        audit_payload(event, previous_hash).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


def checkpoint_entry(event):
    return {
        'id': event.pk,
        'previous_hash': event.previous_hash,
        'integrity_hash': event.integrity_hash,
    }


def append_audit_checkpoint(event):
    path = settings.AUDIT_CHECKPOINT_PATH
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'a', encoding='utf-8', newline='\n') as checkpoint:
        checkpoint.write(
            json.dumps(checkpoint_entry(event), sort_keys=True, separators=(',', ':'))
            + '\n'
        )
        checkpoint.flush()
        os.fsync(checkpoint.fileno())


def write_audit_checkpoint_snapshot():
    from .models import AuditLog

    path = settings.AUDIT_CHECKPOINT_PATH
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as checkpoint:
        for event in AuditLog.objects.order_by('pk').iterator():
            checkpoint.write(
                json.dumps(
                    checkpoint_entry(event),
                    sort_keys=True,
                    separators=(',', ':'),
                )
                + '\n'
            )
        checkpoint.flush()
        os.fsync(checkpoint.fileno())


def verify_audit_chain():
    from .models import AuditChainState, AuditLog

    previous_hash = GENESIS_HASH
    event_count = 0
    try:
        checkpoint = open(settings.AUDIT_CHECKPOINT_PATH, encoding='utf-8')
    except FileNotFoundError:
        return False, 'Independent audit checkpoint is missing.'

    with checkpoint:
        for event in AuditLog.objects.order_by('pk').iterator():
            if event.previous_hash != previous_hash:
                return False, f'Audit event {event.pk} has an invalid predecessor hash.'
            expected_hash = sign_audit_event(event, previous_hash)
            if not hmac.compare_digest(event.integrity_hash, expected_hash):
                return False, f'Audit event {event.pk} failed its integrity check.'
            checkpoint_line = checkpoint.readline()
            try:
                checkpoint_event = json.loads(checkpoint_line)
            except json.JSONDecodeError:
                return False, f'Audit checkpoint is missing or malformed at event {event.pk}.'
            if checkpoint_event != checkpoint_entry(event):
                return False, f'Audit checkpoint does not match event {event.pk}.'
            previous_hash = event.integrity_hash
            event_count += 1

        if checkpoint.readline():
            return False, 'Audit checkpoint contains events missing from the database.'

    state = AuditChainState.objects.filter(pk=1).first()
    expected_head = state.last_hash if state else GENESIS_HASH
    if not hmac.compare_digest(expected_head, previous_hash):
        return False, 'Audit chain head does not match the final event.'
    return True, f'Verified {event_count} audit events and the independent checkpoint.'
