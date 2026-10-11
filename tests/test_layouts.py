import unittest

from gdt_pipeline.layouts import compare_layouts, parse_llvm_types


DUMP = '''
  Showing 3 records
  0x1000 | LF_BITFIELD [size = 12]
           type = 0x0075, bit offset = 3, # bits = 2
  0x1001 | LF_FIELDLIST [size = 20]
           - LF_MEMBER [name = `Flags`, Type = 0x1000, offset = 0, attrs = public]
  0x1002 | LF_STRUCTURE [size = 40] `_TEST`
           field list: 0x1001
           options: has unique name, sizeof 4
'''


class LayoutTests(unittest.TestCase):
    def test_named_bitfields_are_compared(self):
        report = compare_layouts(parse_llvm_types(DUMP), 'T\t_TEST\t4\nF\t_TEST\tFlags\t0\t3\t2\n')
        self.assertEqual(report['failures'], [])
        self.assertEqual(report['bitfields_checked'], 1)

    def test_incorrect_bitfield_fails(self):
        report = compare_layouts(parse_llvm_types(DUMP), 'T\t_TEST\t4\nF\t_TEST\tFlags\t0\t2\t2\n')
        self.assertTrue(report['failures'])

    def test_missing_type_fails(self):
        self.assertTrue(compare_layouts(parse_llvm_types(DUMP), '')['failures'])

    def test_conflict_variant_must_match_whole_layout(self):
        good = 'T\t_TEST\t0\nT\t_TEST.conflict\t4\nF\t_TEST.conflict\tFlags\t0\t3\t2\n'
        self.assertFalse(compare_layouts(parse_llvm_types(DUMP), good)['failures'])

    def test_unrecognized_dump_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_llvm_types('a tool changed its output')

    def test_empty_pdb_is_recognized(self):
        self.assertEqual(parse_llvm_types('Showing 0 records')['aggregate_definitions'], 0)

    def test_continuation_fails_explicitly(self):
        with self.assertRaisesRegex(ValueError, 'continuation'):
            parse_llvm_types(DUMP.replace('- LF_MEMBER', '- LF_INDEX\n           - LF_MEMBER'))

    def test_cpp_coverage_is_reported(self):
        info = parse_llvm_types(DUMP.replace('`_TEST`', '`NS::TEST`'))
        self.assertEqual(info['aggregate_definitions'], 1)
        self.assertEqual(info['excluded_aggregates'], 1)
        self.assertEqual(info['named_aggregates'], [])

    def test_zero_field_list_is_empty(self):
        raw = '''Showing 1 records
  0x1000 | LF_STRUCTURE [size = 40] `_EMPTY`
           field list: 0x0000
           options: has unique name, sizeof 1
'''
        self.assertFalse(compare_layouts(parse_llvm_types(raw), 'T\t_EMPTY\t1\n')['failures'])


if __name__ == '__main__':
    unittest.main()
