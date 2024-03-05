# Copyright 2024 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Unit test for command line module."""
import contextlib
import io
import os
import pathlib
import shutil
import struct
import tempfile
import unittest
import unittest.mock
import uuid

import oscg.cli

THIS_DIR = pathlib.Path(__file__).parent


class TestOutputEnum(unittest.TestCase):
    """Check the enumeration of output pathlib objects."""

    def setUp(self):
        """Instantiate the enum class."""
        self.op = oscg.cli._Output

    def test_xml_name(self):
        """Test the name of the XML path object."""
        self.assertEqual(self.op.XML.value.name, 'config.xml', 'XML filename not as expected.')

    def test_iso_name(self):
        """Test the name of the ISO path object."""
        self.assertEqual(self.op.ISO.value.name, 'config.iso', 'ISO filename not as expected.')

    def test_wireguard_name(self):
        """Test the name of the WireGuard path object."""
        self.assertEqual(self.op.WG.value.name, 'WGBootstrap.conf', 'WireGuard client config filename not as expected.')

    def test_shorcut_name(self):
        """Test the name of the macOS shortcut path object."""
        self.assertEqual(self.op.URL.value.name, 'WGBootstrap.url', 'Shortcut filename not as expected.')

    def test_example_name(self):
        """Test the name of the example ini path object."""
        self.assertEqual(self.op.EX.value.name, 'opnsense_config_example.ini', 'Example INI filename not as expected.')


class TestCleanup(unittest.TestCase):
    """Check that the cleanup function works as expected."""

    def setUp(self):
        """Prepare temporary directory."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        for path in list(oscg.cli._Output):
            path.value.write_text('DUMMYDATA')

    @unittest.mock.patch('builtins.input', side_effect=['no'])
    def test_exit_on_no(self, mock_inputs):
        """Test that user entry of 'no' exits."""
        with self.assertRaises(SystemExit, msg='Exit check failed when answer is no.'):
            oscg.cli._cleanup()

    @unittest.mock.patch('builtins.input', side_effect=[str()])
    def test_exit_on_empty(self, mock_inputs):
        """Test that missing user entry exits."""
        with self.assertRaises(SystemExit, msg='Exit check failed when answer is blank.'):
            oscg.cli._cleanup()

    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_exit_on_yes(self, mock_inputs):
        """Test that user entry of 'yes' exits."""
        with self.assertRaises(SystemExit, msg='Exit check failed when answer is yes.'):
            oscg.cli._cleanup()

    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_delete_output(self, mock_inputs):
        """Test that output files are deleted."""
        with contextlib.suppress(SystemExit):
            oscg.cli._cleanup()

        for path in list(oscg.cli._Output):
            with self.subTest(filename=path.value.name):
                self.assertFalse(path.value.exists(), 'File not deleted.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestWriteExample(unittest.TestCase):
    """Check that the example is written correctly."""

    def setUp(self):
        """Prepare temporary directory."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)

    def test_exit(self):
        """Test that function exits on completion."""
        with self.assertRaises(SystemExit, msg='Exit check failed.'):
            with contextlib.redirect_stdout(io.StringIO()):
                oscg.cli._write_example()

    def test_stdout(self):
        """Check that the message written to stdout is as expected."""
        message = 'Example configuration file written to: opnsense_config_example.ini\n'

        with contextlib.redirect_stdout(io.StringIO()) as f:
            with contextlib.suppress(SystemExit):
                oscg.cli._write_example()
        stdout = f.getvalue()

        self.assertEqual(stdout, message, 'Console message not as expected.')

    def test_write_example(self):
        """Test the file output is as expected."""
        with contextlib.redirect_stdout(io.StringIO()):
            with contextlib.suppress(SystemExit):
                oscg.cli._write_example()
        example_path = oscg.cli._Output.EX.value

        self.assertTrue(example_path.exists(), 'Example file not created.')

    def test_example_content(self):
        """Test the file content is as expected."""
        example_ref = THIS_DIR.joinpath('data').joinpath('ini_example.txt').read_text()

        with contextlib.redirect_stdout(io.StringIO()):
            with contextlib.suppress(SystemExit):
                oscg.cli._write_example()

        example = oscg.cli._Output.EX.value.read_text()

        self.assertEqual(example, example_ref, 'Example file content not as expected.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestPathCheck(unittest.TestCase):
    """Check that the path checker function works."""

    def setUp(self):
        """Instantiate pathlib object."""
        self.td = tempfile.TemporaryDirectory()
        self.test_path = pathlib.Path(self.td.name).joinpath(str(uuid.uuid4()))

    def test_no_file(self):
        """Check with the condition of no file."""
        checked_path = oscg.cli._check_path(self.test_path)

        self.assertTrue(checked_path, 'Path check failed when file does not exist.')

    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_with_file_answer_yes(self, mock_inputs):
        """Check with the condition of a file existing and the answer as yes."""
        self.test_path.write_text('DUMMYDATA')
        checked_path = oscg.cli._check_path(self.test_path)

        self.assertTrue(checked_path, 'Check failed when file exists and answer is yes.')

    @unittest.mock.patch('builtins.input', side_effect=['no'])
    def test_with_file_answer_no(self, mock_inputs):
        """Check with the condition of a file existing and the answer as no."""
        self.test_path.write_text('DUMMYDATA')
        checked_path = oscg.cli._check_path(self.test_path)

        self.assertFalse(checked_path, 'Check failed when file exists and answer is no.')

    @unittest.mock.patch('builtins.input', side_effect=[str()])
    def test_with_file_answer_empty(self, mock_inputs):
        """Check with the condition of a file existing and the answer is empty."""
        self.test_path.write_text('DUMMYDATA')
        checked_path = oscg.cli._check_path(self.test_path)

        self.assertFalse(checked_path, 'Check failed when file exists and answer is empty.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestGetPath(unittest.TestCase):
    """Check that the filename string is converted to a pathlib object."""

    def setUp(self):
        """Instantiate pathlib object."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        self.test_path = pathlib.Path(self.td.name).joinpath('opnsense_config.ini')

    def test_ini_missing(self):
        """Test if exit when INI is missing."""
        with self.assertRaises(SystemExit, msg='Exit check failed.'):
            oscg.cli._get_path('opnsense_config.ini')

    def test_ini_present(self):
        """Test if function returns pathlib object if INI file is present."""
        self.test_path.write_text('DUMMYDATA')
        ini_path = oscg.cli._get_path('opnsense_config.ini')

        self.assertIsInstance(ini_path, pathlib.Path, 'Returned object is not pathlib.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestGenConfigs(unittest.TestCase):
    """Check that the configuration generation function returns the correct objects."""

    def test_os_config_obj_with_wg(self):
        """Test that the returned OPNsense configuration object is the correct type with WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        os_config, _, _, _ = oscg.cli._generate_configs(ini_path)

        self.assertIsInstance(os_config, str, 'Returned object is not a string with WireGuard.')

    def test_os_config_obj_without_wg(self):
        """Test that the returned OPNsense configuration object is the correct type without WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_full.txt')
        os_config, _, _, _ = oscg.cli._generate_configs(ini_path)

        self.assertIsInstance(os_config, str, 'Returned object is not a string without WireGuard.')

    def test_wg_config_obj_with_wg(self):
        """Test that the returned WireGuard configuration object is the correct type with WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        _, wg_config, _, _ = oscg.cli._generate_configs(ini_path)

        self.assertIsInstance(wg_config, str, 'String not returned when expected.')

    def test_wg_config_obj_without_wg(self):
        """Test that the returned WireGuard configuration object is the correct type without WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_full.txt')
        _, wg_config, _, _ = oscg.cli._generate_configs(ini_path)

        self.assertIsNone(wg_config, 'None type not returned when expected.')

    def test_shortcut_obj_with_wg(self):
        """Test that the returned macOS shortcut object is the correct type with WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_full.txt')
        _, _, mac_shortcut, _ = oscg.cli._generate_configs(ini_path)

        self.assertIsInstance(mac_shortcut, str, 'String not returned when expected.')

    def test_shortcut_obj_without_wg(self):
        """Test that the returned macOS shortcut object is the correct type without WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_wg.txt')
        _, _, mac_shortcut, _ = oscg.cli._generate_configs(ini_path)

        self.assertIsNone(mac_shortcut, 'None type not returned when expected.')

    def test_console_url_obj_with_wg(self):
        """Test that the returned console URL object is the correct type with WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_full.txt')
        _, _, _, console_url = oscg.cli._generate_configs(ini_path)

        self.assertIsInstance(console_url, str, 'String not returned when expected.')

    def test_console_url_obj_without_wg(self):
        """Test that the returned console URL object is the correct type without WireGuard."""
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_wg.txt')
        _, _, _, console_url = oscg.cli._generate_configs(ini_path)

        self.assertIsNone(console_url, 'None type not returned when expected.')

    def test_debug_output_with_wg(self):
        """Test that the debug output text is correct with WireGuard."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub.re').read_text().strip()
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')

        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli._generate_configs(ini_path, debug=True)
        debug_output = f.getvalue()

        self.assertRegex(debug_output, config_re, 'Expected debug output not emitted when WireGuard generated.')

    def test_debug_output_without_wg(self):
        """Test that the debug output text is correct without WireGuard."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_stat_keys.re').read_text().strip()
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_full.txt')

        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli._generate_configs(ini_path, debug=True)
        debug_output = f.getvalue()

        self.assertRegex(debug_output, config_re, 'Expected debug output not emitted when WireGuard not generated.')


class TestWriteXML(unittest.TestCase):
    """Test that the XML config file is written properly."""

    def setUp(self):
        """Prepare temporary directory."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        self.config, _, _, _ = oscg.cli._generate_configs(ini_path)
        self.output_path = oscg.cli._Output.XML.value

    def test_xml_write(self):
        """Test that the XML configuration file is created correctly."""
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_xml(self.config)

        self.assertTrue(self.output_path.exists(), 'XML configuration not created.')

    def test_xml_write_content(self):
        """Test that the XML configuration file content is created correctly."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub_with_decl.re').read_text().strip()
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_xml(self.config)
        output = self.output_path.read_text()

        self.assertRegex(output, config_re, 'XML config file content incorrect.')

    def test_xml_write_stdout(self):
        """Test that the stdout message is correct."""
        message = 'OPNsense configuration written to: config.xml\n'
        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli._write_xml(self.config)
        stdout = f.getvalue()

        self.assertEqual(stdout, message, 'Message not as expected.')

    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_xml_overwrite(self, mock_inputs):
        """Test XML configuration file creation when file exists already."""
        dummy_data = 'DUMMYDATA'
        self.output_path.write_text(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_xml(self.config)
        file_data = self.output_path.read_text()

        self.assertNotEqual(file_data, dummy_data, 'XML configuration not overwritten.')

    @unittest.mock.patch('builtins.input', side_effect=['no'])
    def test_xml_no_overwrite(self, mock_inputs):
        """Test XML configuration file not overwritten when file exists already."""
        dummy_data = 'DUMMYDATA'
        self.output_path.write_text(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_xml(self.config)
        file_data = self.output_path.read_text()

        self.assertEqual(file_data, dummy_data, 'XML configuration overwritten.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestWriteWireGuard(unittest.TestCase):
    """Test that the WireGuard client config file is written properly."""

    def setUp(self):
        """Prepare temporary directory."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        _, self.config, _, _ = oscg.cli._generate_configs(ini_path)
        self.output_path = oscg.cli._Output.WG.value

    def test_wg_write(self):
        """Test that the WireGuard client configuration file is created correctly."""
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_wg(self.config)

        self.assertTrue(self.output_path.exists(), 'WireGuard client configuration not created.')

    def test_wg_write_stdout(self):
        """Test that the stdout message is correct."""
        message = 'WireGuard client configuration written to: WGBootstrap.conf\n'
        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli._write_wg(self.config)
        stdout = f.getvalue()

        self.assertEqual(stdout, message, 'Message not as expected.')

    def test_wg_write_content(self):
        """Test that the WireGuard client configuration file content is created correctly."""
        config_re = THIS_DIR.joinpath('data').joinpath('wg_client_config_fqdn.re').read_text().strip()
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_wg(self.config)
        output = self.output_path.read_text()

        self.assertRegex(output, config_re, 'WireGuard client config file content incorrect.')

    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_wg_overwrite(self, mock_inputs):
        """Test WireGuard client configuration file creation when file exists already."""
        dummy_data = 'DUMMYDATA'
        self.output_path.write_text(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_wg(self.config)
        file_data = self.output_path.read_text()

        self.assertNotEqual(file_data, dummy_data, 'WireGuard client configuration not overwritten.')

    @unittest.mock.patch('builtins.input', side_effect=['no'])
    def test_wg_no_overwrite(self, mock_inputs):
        """Test WireGuard client configuration file not overwritten when file exists already."""
        dummy_data = 'DUMMYDATA'
        self.output_path.write_text(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_wg(self.config)
        file_data = self.output_path.read_text()

        self.assertEqual(file_data, dummy_data, 'WireGuard client configuration overwritten.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestWriteISO(unittest.TestCase):
    """Test that the ISO config file is written properly."""

    def setUp(self):
        """Prepare temporary directory."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        self.config, _, _, _ = oscg.cli._generate_configs(ini_path)
        self.output_path = oscg.cli._Output.ISO.value

    def test_iso_write(self):
        """Test that the ISO configuration file is created correctly."""
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_iso(self.config)

        self.assertTrue(self.output_path.exists(), 'ISO configuration not created.')

    def test_iso_write_content(self):
        """Test that the ISO configuration file content is created correctly."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub_with_decl.re').read_bytes().strip()
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_iso(self.config)
        output = self.output_path.read_bytes()

        self.assertRegex(output, config_re, 'ISO config file content incorrect.')

    def test_iso_write_magic(self):
        """Test that the ISO configuration file has the correct ISO9660 volume descriptor magic number."""
        iso9660 = (1, b'CD001', 1)  # https://en.wikipedia.org/wiki/ISO_9660#Volume_descriptor_set
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_iso(self.config)
        output = self.output_path.read_bytes()
        magic = struct.unpack_from('B5sBx', buffer=output, offset=0x8000)

        self.assertTupleEqual(magic, iso9660, 'ISO config file volume descriptor magic number is incorrect.')

    def test_iso_write_stdout(self):
        """Test that the stdout message is correct."""
        message = 'OPNsense configuration written to: config.iso\n'
        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli._write_iso(self.config)
        stdout = f.getvalue()

        self.assertEqual(stdout, message, 'Message not as expected.')

    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_iso_overwrite(self, mock_inputs):
        """Test ISO configuration file creation when file exists already."""
        dummy_data = b'DUMMYDATA'
        self.output_path.write_bytes(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_iso(self.config)
        file_data = self.output_path.read_bytes()

        self.assertNotEqual(file_data, dummy_data, 'ISO configuration not overwritten.')

    @unittest.mock.patch('builtins.input', side_effect=['no'])
    def test_iso_no_overwrite(self, mock_inputs):
        """Test ISO configuration file not overwritten when file exists already."""
        dummy_data = b'DUMMYDATA'
        self.output_path.write_bytes(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_iso(self.config)
        file_data = self.output_path.read_bytes()

        self.assertEqual(file_data, dummy_data, 'ISO configuration overwritten.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestWriteShortcut(unittest.TestCase):
    """Test that the macOS shortcut file is written properly."""

    def setUp(self):
        """Prepare temporary directory."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        ini_path = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        _, _, self.shortcut, _ = oscg.cli._generate_configs(ini_path)
        self.output_path = oscg.cli._Output.URL.value

    def test_sc_write(self):
        """Test that the macOS shortcut file is created correctly."""
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_mac_shortcut(self.shortcut)

        self.assertTrue(self.output_path.exists(), 'Shortcut not created.')

    def test_sc_write_stdout(self):
        """Test that the stdout message is correct."""
        message = 'Console URL macOS internet shortcut written to: WGBootstrap.url\n'
        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli._write_mac_shortcut(self.shortcut)
        stdout = f.getvalue()

        self.assertEqual(stdout, message, 'Message not as expected.')

    def test_sc_write_content(self):
        """Test that the macOS shortcut file content is created correctly."""
        expected = '[InternetShortcut]\nURL=https://172.19.0.1/\n'
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_mac_shortcut(self.shortcut)
        output = self.output_path.read_text()

        self.assertEqual(output, expected, 'Shortcut file content incorrect.')

    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_sc_overwrite(self, mock_inputs):
        """Test macOS shortcut file creation when file exists already."""
        dummy_data = 'DUMMYDATA'
        self.output_path.write_text(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_mac_shortcut(self.shortcut)
        file_data = self.output_path.read_text()

        self.assertNotEqual(file_data, dummy_data, 'Shortcut not overwritten.')

    @unittest.mock.patch('builtins.input', side_effect=['no'])
    def test_sc_no_overwrite(self, mock_inputs):
        """Test macOS shortcut file not overwritten when file exists already."""
        dummy_data = 'DUMMYDATA'
        self.output_path.write_text(dummy_data)
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli._write_mac_shortcut(self.shortcut)
        file_data = self.output_path.read_text()

        self.assertEqual(file_data, dummy_data, 'Shortcut overwritten.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


class TestMainArguments(unittest.TestCase):
    """Check that command line arguments work as expected."""

    def setUp(self):
        """Prepare temporary directory."""
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-c'])
    @unittest.mock.patch('builtins.input', side_effect=['yes'])
    def test_arg_cleanup(self, mock_inputs):
        """Test that output files are deleted."""
        for path in list(oscg.cli._Output):
            path.value.write_text('DUMMYDATA')

        with contextlib.suppress(SystemExit):
            oscg.cli.main()

        for path in list(oscg.cli._Output):
            with self.subTest(filename=path.value.name):
                self.assertFalse(path.value.exists(), 'File not deleted.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-e'])
    def test_arg_example(self):
        """Test the example file content is as expected."""
        example_ref = THIS_DIR.joinpath('data').joinpath('ini_example.txt').read_text()

        with contextlib.redirect_stdout(io.StringIO()):
            with contextlib.suppress(SystemExit):
                oscg.cli.main()

        example = oscg.cli._Output.EX.value.read_text()

        self.assertEqual(example, example_ref, 'Example file content not as expected.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-d'])
    def test_arg_debug(self):
        """Test that the debug output text is correct."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub.re').read_text().strip()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)

        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli.main()
        debug_output = f.getvalue()

        self.assertRegex(debug_output, config_re, 'Expected debug output not emitted.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-f', 'xml'])
    def test_arg_xml(self):
        """Test that the XML configuration file content is created correctly."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub_with_decl.re').read_text().strip()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        output_path = oscg.cli._Output.XML.value

        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()
        output = output_path.read_text()

        self.assertRegex(output, config_re, 'XML config file content incorrect.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-f', 'xml'])
    def test_arg_xml_no_keys(self):
        """Test that the XML configuration file content is created correctly when no keys are provided."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_keys_with_decl.re').read_text().strip()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_keys.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        output_path = oscg.cli._Output.XML.value

        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()
        output = output_path.read_text()

        self.assertRegex(output, config_re, 'XML config file content incorrect, no keys provided.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-f', 'xml'])
    def test_arg_xml_no_spriv(self):
        """Test that the XML configuration file content is created correctly when no server private key is provided."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_spriv_with_decl.re').read_text().strip()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_spriv.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        output_path = oscg.cli._Output.XML.value

        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()
        output = output_path.read_text()

        self.assertRegex(output, config_re, 'XML config file content incorrect, no server private key provided.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-f', 'iso'])
    def test_arg_iso(self):
        """Test that the ISO configuration file content is created correctly."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub_with_decl.re').read_bytes().strip()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        output_path = oscg.cli._Output.ISO.value

        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()
        output = output_path.read_bytes()

        self.assertRegex(output, config_re, 'ISO config file content incorrect.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-f', 'both'])
    def test_arg_both(self):
        """Test that the ISO configuration file content is created correctly."""
        config_re = THIS_DIR.joinpath('data').joinpath('config_xml_dyn_cpub_with_decl.re').read_bytes().strip()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        xml_path = oscg.cli._Output.XML
        iso_path = oscg.cli._Output.ISO

        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()

        for output_path in [xml_path, iso_path]:
            with self.subTest(format=output_path.name):
                output = output_path.value.read_bytes()

                self.assertRegex(output, config_re, f'{output_path.name} config file content incorrect.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-s'])
    def test_sc(self):
        """Test that the macOS file content is created correctly."""
        expected = '[InternetShortcut]\nURL=https://172.19.0.1/\n'
        src = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        output_path = oscg.cli._Output.URL.value
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()
        output = output_path.read_text()

        self.assertEqual(output, expected, 'Shortcut file content incorrect.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg', '-u'])
    def test_url(self):
        """Test that the console url output text is correct."""
        expected = THIS_DIR.joinpath('data').joinpath('url_console_output.txt').read_text()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)

        with contextlib.redirect_stdout(io.StringIO()) as f:
            oscg.cli.main()
        output = f.getvalue()

        self.assertEqual(output, expected, 'Expected console output with URL not emitted.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg'])
    def test_wg(self):
        """Test that the WireGuard client configuration file content is created correctly."""
        config_re = THIS_DIR.joinpath('data').joinpath('wg_client_config_fqdn.re').read_text().strip()
        src = THIS_DIR.joinpath('data').joinpath('ini_no_cpub.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        output_path = oscg.cli._Output.WG.value
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()
        output = output_path.read_text()

        self.assertRegex(output, config_re, 'WireGuard client config file content incorrect.')

    @unittest.mock.patch('argparse._sys.argv', ['oscg'])
    def test_no_wg(self):
        """Test that the WireGuard client configuration file content is not created."""
        src = THIS_DIR.joinpath('data').joinpath('ini_full.txt')
        dst = pathlib.Path('opnsense_config.ini')
        shutil.copy(src, dst)
        output_path = oscg.cli._Output.WG.value
        with contextlib.redirect_stdout(io.StringIO()):
            oscg.cli.main()

        self.assertFalse(output_path.exists(), 'WireGuard client config was created.')

    def tearDown(self):
        """Cleanup the temporary directory."""
        self.td.cleanup()


if __name__ == '__main__':
    unittest.main(verbosity=2)
