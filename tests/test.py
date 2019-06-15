import lz4
import sys


import unittest
import os

class TestLZ4(unittest.TestCase):

    def test_random(self):
      DATA = os.urandom(128 * 1024)  # Read 128kb
      self.assertEqual(DATA, lz4.loads(lz4.dumps(DATA)))

    def test_random_ns(self):
      DATA = os.urandom(128 * 1024)  # Read 128kb
      self.assertEqual(DATA, lz4.loads(lz4.dumps(DATA, head_type = 0), head_type = 0))

    def test_random_ns_4096kb(self):
      DATA = os.urandom(4096 * 1024)  # Read 5096kb
      self.assertEqual(DATA, lz4.loads(lz4.dumps(DATA, head_type = 0), head_type = 0))

    def test_random_varint(self):
      DATA = os.urandom(128 * 1024)  # Read 128kb
      self.assertEqual(DATA, lz4.loads(lz4.dumps(DATA, head_type = 3), head_type = 3))

    def test_random_be32(self):
      DATA = os.urandom(128 * 1024)  # Read 128kb
      self.assertEqual(DATA, lz4.loads(lz4.dumps(DATA, head_type = 2), head_type = 2))

    def test_random_le32(self):
      DATA = os.urandom(128 * 1024)  # Read 128kb
      self.assertEqual(DATA, lz4.loads(lz4.dumps(DATA, head_type = 1), head_type = 1))

if __name__ == '__main__':
    unittest.main()

