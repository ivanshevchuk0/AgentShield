"""Validate the supported text-only chat protocol and expose metadata for inspection.

JSON argument strings are decoded before scanning and re-encoded after redaction;
JSON keys and protocol identifiers cannot be safely renamed and fail closed.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

REQUEST_FIELDS = {
    'model', 'messages', 'tools', 'tool_choice', 'functions', 'function_call',
    'parallel_tool_calls', 'response_format', 'max_tokens', 'max_completion_tokens',
    'n', 'temperature', 'top_p', 'frequency_penalty', 'presence_penalty', 'seed',
    'stop', 'stream', 'stream_options', 'user', 'logprobs', 'top_logprobs',
    'logit_bias', 'service_tier',
}
MESSAGE_FIELDS = {'role', 'content', 'name', 'tool_call_id', 'tool_calls', 'function_call', 'refusal'}
IDENTIFIERS = {'name', 'id', 'tool_call_id', 'role', 'type', 'model'}


def _fields(value, allowed, label):
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError(f'{label} contains unsupported fields or is not an object')


def _string(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(f'{label} must be non-empty text')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON argument key')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-finite JSON argument constant')


def _function(value, *, call=False):
    _fields(value, {'name', 'arguments'} if call else {'name', 'description', 'parameters', 'strict'}, 'function')
    _string(value.get('name'), 'function name')
    if call:
        raw = value.get('arguments')
        if not isinstance(raw, str):
            raise ValueError('function arguments must be a JSON object string')
        try:
            parsed = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        except (ValueError, RecursionError) as exc:
            raise ValueError('invalid function argument JSON') from exc
        if not isinstance(parsed, dict):
            raise ValueError('function arguments must encode an object')
        value['arguments'] = parsed  # internal copy only; restored by encode_arguments
    else:
        if 'description' in value and not isinstance(value['description'], str):
            raise ValueError('function description must be text')
        if 'parameters' in value and not isinstance(value['parameters'], dict):
            raise ValueError('function parameters must be an object')
        if 'strict' in value and type(value['strict']) is not bool:
            raise ValueError('function strict must be boolean')


def validate(body: dict) -> None:
    """Validate and decode historical arguments, mutating only a forwarded copy."""
    _fields(body, REQUEST_FIELDS, 'request')
    _string(body.get('model'), 'model')
    for message in body['messages']:
        _fields(message, MESSAGE_FIELDS, 'message')
        role = message.get('role')
        if role not in {'system', 'developer', 'user', 'assistant', 'tool', 'function'}:
            raise ValueError('unsupported message role')
        content = message.get('content')
        if isinstance(content, list):
            for part in content:
                if isinstance(part, str):
                    continue
                _fields(part, {'type', 'text'}, 'content part')
                if part.get('type') != 'text' or not isinstance(part.get('text'), str):
                    raise ValueError('only text content parts are supported')
        elif content is not None and not isinstance(content, str):
            raise ValueError('message content must be text, text parts, or null')
        for key in ('name', 'tool_call_id'):
            if key in message:
                _string(message[key], key)
        if 'refusal' in message and message['refusal'] is not None and not isinstance(message['refusal'], str):
            raise ValueError('refusal must be text or null')
        if 'tool_calls' in message:
            calls = message['tool_calls']
            if role != 'assistant' or not isinstance(calls, list) or not calls:
                raise ValueError('tool_calls must be a nonempty assistant call list')
            for call in calls:
                _fields(call, {'id', 'type', 'function'}, 'tool call')
                _string(call.get('id'), 'tool call id')
                if call.get('type') != 'function':
                    raise ValueError('unsupported tool call type')
                _function(call.get('function'), call=True)
        if 'function_call' in message:
            if role != 'assistant':
                raise ValueError('function_call requires assistant role')
            _function(message['function_call'], call=True)
    for key in ('tools', 'functions'):
        if key not in body:
            continue
        if not isinstance(body[key], list):
            raise ValueError(f'{key} must be a list')
        for item in body[key]:
            if key == 'tools':
                _fields(item, {'type', 'function'}, 'tool')
                if item.get('type') != 'function':
                    raise ValueError('unsupported tool type')
                item = item.get('function')
            _function(item)
    for key in ('tool_choice', 'function_call'):
        if key not in body:
            continue
        value = body[key]
        if isinstance(value, str):
            if value not in {'auto', 'none', 'required'}:
                raise ValueError(f'unsupported {key}')
        else:
            if key == 'tool_choice':
                _fields(value, {'type', 'function'}, key)
                if value.get('type') != 'function':
                    raise ValueError('unsupported tool choice type')
                value = value.get('function')
            _fields(value, {'name'}, key)
            _string(value.get('name'), key)
    if 'response_format' in body:
        fmt = body['response_format']
        _fields(fmt, {'type', 'json_schema'}, 'response_format')
        if fmt.get('type') not in {'text', 'json_object', 'json_schema'}:
            raise ValueError('unsupported response format')
        if (fmt.get('type') == 'json_schema') != ('json_schema' in fmt):
            raise ValueError('json_schema format requires a schema envelope')
        if 'json_schema' in fmt:
            _fields(fmt['json_schema'], {'name', 'description', 'schema', 'strict'}, 'json_schema')
            _string(fmt['json_schema'].get('name'), 'json_schema name')
            for key in ('description',):
                if key in fmt['json_schema'] and not isinstance(fmt['json_schema'][key], str):
                    raise ValueError('json_schema description must be text')
            if 'strict' in fmt['json_schema'] and type(fmt['json_schema']['strict']) is not bool:
                raise ValueError('json_schema strict must be boolean')
            if not isinstance(fmt['json_schema'].get('schema'), dict):
                raise ValueError('json_schema schema must be an object')
    if 'stream_options' in body:
        _fields(body['stream_options'], {'include_usage'}, 'stream_options')
        if type(body['stream_options'].get('include_usage', False)) is not bool:
            raise ValueError('include_usage must be boolean')
    for key in ('parallel_tool_calls', 'stream', 'logprobs'):
        if key in body and type(body[key]) is not bool:
            raise ValueError(f'{key} must be boolean')
    for key in ('temperature', 'top_p', 'frequency_penalty', 'presence_penalty', 'seed', 'top_logprobs'):
        if key in body and (type(body[key]) not in (int, float) or not math.isfinite(body[key])):
            raise ValueError(f'{key} must be finite numeric data')
    if 'stop' in body and not (isinstance(body['stop'], str) or isinstance(body['stop'], list)
                              and all(isinstance(s, str) for s in body['stop'])):
        raise ValueError('stop must contain text')
    for key in ('user', 'service_tier'):
        if key in body and not isinstance(body[key], str):
            raise ValueError(f'{key} must be text')
    if 'logit_bias' in body and (not isinstance(body['logit_bias'], dict) or any(
            type(v) not in (int, float) or not math.isfinite(v) for v in body['logit_bias'].values())):
        raise ValueError('logit_bias must contain finite numeric values')
    # Bound recursion independently of provider schema/argument complexity.
    list(metadata(body))


@dataclass
class TextField:
    parent: Any
    key: Any
    text: str
    immutable: bool = False

    def rewrite(self, text: str) -> None:
        self.parent[self.key] = text


SCHEMA_KEYWORDS = {
    '$schema', '$id', '$ref', '$defs', '$anchor', '$comment', 'type', 'properties',
    'patternProperties', 'additionalProperties', 'required', 'items', 'prefixItems',
    'additionalItems', 'contains', 'minContains', 'maxContains', 'allOf', 'anyOf',
    'oneOf', 'not', 'if', 'then', 'else', 'dependentRequired', 'dependentSchemas',
    'unevaluatedProperties', 'unevaluatedItems', 'propertyNames', 'enum', 'const',
    'default', 'examples', 'description', 'title', 'format', 'pattern', 'minimum',
    'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'minLength',
    'maxLength', 'minItems', 'maxItems', 'uniqueItems', 'minProperties', 'maxProperties',
    'readOnly', 'writeOnly', 'deprecated', 'contentEncoding', 'contentMediaType',
}
SCHEMA_TYPES = {'object', 'array', 'string', 'number', 'integer', 'boolean', 'null'}


def metadata(body: dict):
    """Yield actual model-facing text and arbitrary keys, excluding fixed syntax."""
    def walk(value, depth=0, skip_content=False, channel=None):
        if depth > 32:
            raise ValueError('request metadata nesting exceeds 32 levels')
        if isinstance(value, dict):
            for key, item in value.items():
                if skip_content and key == 'content':
                    continue
                if not isinstance(key, str):
                    raise ValueError('JSON keys must be text')
                # Schema property names and JSON argument keys are model-facing.
                # Known JSON Schema keywords and protocol keys are fixed syntax.
                if channel == 'arguments' or channel == 'properties' or (
                        channel == 'schema' and key not in SCHEMA_KEYWORDS):
                    yield TextField(value, key, key, True)
                child_channel = channel
                if channel is None and key in {'schema', 'parameters', 'arguments'}:
                    child_channel = 'arguments' if key == 'arguments' else 'schema'
                elif channel in {'schema', 'properties'}:
                    child_channel = 'properties' if key in {'properties', 'patternProperties', '$defs', 'dependentSchemas'} else 'schema'
                if isinstance(item, str):
                    if channel is None and key in {'role', 'type'}:
                        continue
                    if channel in {'schema', 'properties'} and key == 'type' and item in SCHEMA_TYPES:
                        continue
                    yield TextField(value, key, item, key in IDENTIFIERS)
                else:
                    yield from walk(item, depth + 1, channel=child_channel)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, str):
                    yield TextField(value, i, item)
                else:
                    yield from walk(item, depth + 1, channel=channel)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError('non-finite metadata value')
    for key, value in body.items():
        if key == 'messages':
            for message in value:
                yield from walk(message, skip_content=True)
        elif key not in {'stream', 'stream_options', 'model'}:
            if isinstance(value, str):
                if key in {'tool_choice', 'function_call'}:
                    continue  # validated fixed literals: auto/none/required
                yield TextField(body, key, value)
            else:
                yield from walk(value)


def encode_arguments(body: dict) -> None:
    for message in body['messages']:
        functions = [c['function'] for c in message.get('tool_calls', [])]
        if 'function_call' in message:
            functions.append(message['function_call'])
        for function in functions:
            function['arguments'] = json.dumps(function['arguments'], ensure_ascii=False, separators=(',', ':'))
