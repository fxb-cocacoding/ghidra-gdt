import collections
import csv
import io
import re


COVERAGE = (
    'LLVM: named C-style struct/class/union sizes, member byte offsets and bitfields. '
    'Anonymous and C++-qualified names are excluded. Ghidra separately checks all '
    'exported types and dependencies when reopening each archive.'
)


def parse_llvm_types(raw):
    count = re.search(r'Showing ([\d,]+) records', raw)
    if not count:
        raise ValueError('Unrecognized llvm-pdbutil type dump')
    records = {}
    for record in re.split(r'(?=^ +0x[0-9A-Fa-f]+ \|)', raw, flags=re.M):
        match = re.match(r' +(0x[0-9A-Fa-f]+) \|', record)
        if match:
            records[int(match[1], 16)] = record
    if len(records) != int(count[1].replace(',', '')):
        raise ValueError('Incomplete llvm-pdbutil type dump')
    aggregates = []
    total = excluded = 0
    for record in records.values():
        match = re.match(r' +0x[0-9A-Fa-f]+ \| LF_(STRUCTURE|UNION|CLASS).*?`([^`]+)`', record)
        if not match or 'forward ref' in record:
            continue
        total += 1
        name = match[2]
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name):
            excluded += 1
            continue
        size = re.search(r'sizeof (\d+)', record)
        if not size:
            raise ValueError(f'Missing aggregate size: {name}')
        field_id = re.search(r'field list: (0x[0-9A-Fa-f]+)', record)
        field_index = int(field_id[1], 16) if field_id else 0
        if field_index and field_index not in records:
            raise ValueError(f'Missing LLVM field list for {name}: {field_index:#x}')
        fields = records[field_index] if field_index else ''
        if 'LF_INDEX' in fields:
            raise ValueError(f'Unsupported LLVM field-list continuation: {name}')
        expected = []
        for field in re.finditer(r'LF_MEMBER \[name = `([^`]+)`, Type = (0x[0-9A-Fa-f]+).*?offset = (\d+)', fields):
            field_name, type_id, offset = field[1], int(field[2], 16), int(field[3])
            bit = re.search(r'bit offset = (\d+), # bits = (\d+)', records.get(type_id, ''))
            expected.append({'name': field_name, 'offset': offset,
                             'bit_position': offset * 8 + int(bit[1]) if bit else -1,
                             'bit_size': int(bit[2]) if bit else -1})
        if len(expected) != fields.count('LF_MEMBER '):
            raise ValueError(f'Unrecognized LLVM member record: {name}')
        aggregates.append({'name': name, 'size': int(size[1]), 'fields': expected})
    return {'aggregate_definitions': total, 'excluded_aggregates': excluded,
            'named_aggregates': aggregates}


def compare_layouts(parsed, layout):
    sizes = {}
    fields = collections.defaultdict(list)
    for row in csv.reader(io.StringIO(layout), delimiter='\t'):
        if row and row[0] == 'T':
            sizes[row[1]] = int(row[2])
        elif row and row[0] == 'F':
            fields[(row[1], row[2])].append(tuple(map(int, row[3:6])))
    failures = []
    field_count = bit_count = 0
    for aggregate in parsed['named_aggregates']:
        name = aggregate['name']
        field_count += len(aggregate['fields'])
        bit_count += sum(f['bit_size'] >= 0 for f in aggregate['fields'])
        variants = [candidate for candidate in sizes if candidate == name or
                    re.fullmatch(re.escape(name) + r'\.conflict\d*', candidate)]
        attempts = []
        for variant in variants or [name]:
            errors = []
            if sizes.get(variant) != aggregate['size']:
                errors.append({'type': name, 'variant': variant, 'expected_size': aggregate['size'],
                               'actual_size': sizes.get(variant)})
            for field in aggregate['fields']:
                actual = fields[(variant, field['name'])]
                if field['bit_size'] >= 0:
                    found = any(a[1:] == (field['bit_position'], field['bit_size']) for a in actual)
                else:
                    found = any(a[0] == field['offset'] and a[1] == -1 for a in actual)
                if not found:
                    errors.append({'type': name, 'variant': variant, 'field': field, 'actual': actual})
            attempts.append(errors)
        failures.extend(min(attempts, key=len))
    return {'coverage': COVERAGE, 'aggregate_definitions': parsed['aggregate_definitions'],
            'excluded_aggregates': parsed['excluded_aggregates'],
            'types_checked': len(parsed['named_aggregates']), 'fields_checked': field_count,
            'bitfields_checked': bit_count, 'failures': failures}
