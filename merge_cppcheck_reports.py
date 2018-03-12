#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
Merge XML files that use the cppcheck xml format.
"""

import argparse
import base64
import os
import sys
from xml.etree import ElementTree


class _Global:
    # Constants
    CURRENT_PATH = os.getcwd()
    HANDLER_NODE = None
    # Variables
    cache_nodes = {}
    new_xml = None
    xml_obj = None


class _Exit:
    Success = 0
    Failure = 1


class _ParserException(Exception):
    pass


def _setup_parser():
    arg_parser = argparse.ArgumentParser(description='Merge cppcheck XML reports.')
    arg_parser.add_argument(
        'files', metavar='file', type=str, nargs='+', help='list of XML files'
    )
    arg_parser.add_argument(
        '-r', help='remove duplicates', action='store_true', required=False
    )

    return arg_parser


def _get_child_nodes(parent_node, parent_node_name, predicate_on_size):
    children = parent_node.findall(parent_node_name)
    error_prefix = 'node "{0}"'.format(parent_node_name)

    if children is None or not children:
        return None, '{0} does not exist'.format(error_prefix)
    if not predicate_on_size(len(children)):
        return None, '{0} unsatisfied predicate'.format(error_prefix)

    return children, None


def _cache_contains_node(nodes, node):
    return any(len(n) == 2 and node['msg'] == n[0] and node['verbose'] == n[1] for n in nodes)


def _get_missing_attributes(node, attribute_list):
    try:
        node.attrib
    except AttributeError:
        return attribute_list

    return [attr for attr in attribute_list if attr not in node.attrib]


def _encode_string(s):
    return base64.b64encode(s.encode())


def _get_node_key(error_node, location_node):
    e, l = error_node, location_node
    error_message = 'missing attributes "{0}" for node "{1}"'

    missing_attrs = _get_missing_attributes(e, ['id', 'msg', 'severity', 'verbose'])
    if missing_attrs:
        raise _ParserException(error_message.format(', '.join(missing_attrs), 'error'))

    missing_attrs = _get_missing_attributes(l, ['file', 'line'])
    if missing_attrs:
        raise _ParserException(error_message.format(', '.join(missing_attrs), 'location'))

    return '{0}{1}{2}{3}'.format(
        _encode_string(l.attrib['file']),
        l.attrib['line'],
        e.attrib['id'],
        e.attrib['severity']
    )


def _default_node_handler(node, is_first_iter):
    # Just add the node to the list
    if not is_first_iter:
        _Global.xml_obj.append(node)


def _remove_node_handler(node, is_first_iter):
    location_nodes, error_message = _get_child_nodes(
        node, 'location', lambda p: p > 0
    )
    if error_message is not None:
        raise _ParserException(error_message)

    assert(location_nodes) # |location_nodes| > 0

    location_node = location_nodes[0]
    key = _get_node_key(node, location_node)
    msg, verbose = _encode_string(node.attrib['msg']), _encode_string(node.attrib['verbose'])
    if key in _Global.cache_nodes:
        node = {
            'msg': msg,
            'verbose': verbose
        }
        if _cache_contains_node(_Global.cache_nodes[key], node):
            return True
    else:
        _Global.cache_nodes[key] = []
    _Global.cache_nodes[key].append([msg, verbose])

    _default_node_handler(node, is_first_iter)


def _process_xml_file(xml_file):
    root = ElementTree.parse(xml_file).getroot()

    errors_node, error_message = _get_child_nodes(
        root, 'errors', lambda p: p == 1
    )
    if error_message is not None:
        raise _ParserException(error_message)

    assert(len(errors_node) == 1)

    error_nodes, error_message = _get_child_nodes(
        errors_node[0], 'error', lambda p: True
    )
    if error_message is not None:
        raise _ParserException(error_message)

    is_first_iter = False
    if _Global.new_xml is None:
        _Global.new_xml = root
        _Global.xml_obj = errors_node[0]
        is_first_iter = True

    for err_node in error_nodes:
        _Global.HANDLER_NODE(err_node, is_first_iter)


def _process_xml_files(xml_files):
    for xml_file in xml_files:
        if not os.path.isfile(xml_file):
            raise Exception('File "{0}" does not exist'.format(xml_file))

        _process_xml_file(xml_file)


def _main():
    def _fix_path(p):
        return p if os.path.isabs(p) else os.path.join(_Global.CURRENT_PATH, p)

    try:
        args = _setup_parser().parse_args()
        xml_files = [_fix_path(f) for f in args.files]
        _Global.HANDLER_NODE = _remove_node_handler if args.r else _default_node_handler
        _process_xml_files(xml_files)

        sys.stdout.write(ElementTree.tostring(_Global.new_xml).decode('utf8'))
    except _ParserException as pe:
        sys.stderr.write('Error during parsing: {0}'.format(str(pe)))
        return _Exit.Failure
    except Exception as e:
        sys.stderr.write('Error: {0}'.format(str(e)))
        return _Exit.Failure

    return _Exit.Success


if __name__ == '__main__':
    sys.exit(_main())
