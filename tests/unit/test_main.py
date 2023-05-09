"""
Test __main__ cli entrypoints / functions
"""
from subprocess import PIPE
from subprocess import Popen


def test_help():
    with Popen("bits -h".split(), stdout=PIPE) as proc:
        ret = proc.communicate()
        assert proc.returncode == 0, "retcode non-zero"


def test_base_command():
    """
    Test base command's help examples
    """
    random_bytes = bytes.fromhex("696f6906eeb509e9")
    with Popen("bits -1 -0x".split(), stdin=PIPE, stdout=PIPE) as proc:
        stdout, stderr = proc.communicate(random_bytes)
        assert stdout.decode("utf8").strip() == "696f6906eeb509e9", "stdout unexpected"
        assert proc.returncode == 0, "retcode non-zero"

    nibble = "1001\n"
    with Popen("bits -1b -0b".split(), stdin=PIPE, stdout=PIPE) as proc:
        stdout, _ = proc.communicate(nibble.encode("utf8"))
        assert stdout.decode("utf8").strip() == "00001001", "stdout unexpected"
        assert proc.returncode == 0, "retcode non-zero"

    hello_world = "hello world\n"
    with Popen("bits -1 -0".split(), stdin=PIPE, stdout=PIPE) as proc:
        stdout, _ = proc.communicate(hello_world.encode("utf8"))
        assert stdout.decode("utf8") == "hello world\n", "stdout unexpected"
        assert proc.returncode == 0, "retcode non-zero"


def test_key():
    with Popen("bits key -0".split(), stdout=PIPE) as proc:
        stdout, _ = proc.communicate()
        assert len(stdout) == 32, "stdout unexpected - key length != 32"
        assert proc.returncode == 0, "retcode non-zero"


def test_pubkey():
    test_key = bytes.fromhex(
        "3a0a3ff6ae19d221c7ddfd3157d83ff9bc25fa28911e682f95fe5d0ac657ff3c"
    )
    with Popen("bits pubkey -X -1 -0x".split(), stdin=PIPE, stdout=PIPE) as proc:
        stdout, _ = proc.communicate(test_key)
        assert (
            stdout.decode("utf8").strip()
            == "0355e917de55a0aed9dbdafd2516f5b110c3d3a306a09ff705e2530ca5bbe07199"
        ), "stdout unexpected - pubkey"
        assert proc.returncode == 0, "retcode non-zero"
