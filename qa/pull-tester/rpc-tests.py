#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Run Regression Test Suite

This module calls down into individual test cases via subprocess. It will
forward all unrecognized arguments onto the individual test scripts, other
than:

    - `-h` or '--help': print help about all options
    - `-extended`: run the "extended" test suite in addition to the basic one.
    - `-extended-only`: run ONLY the "extended" test suite
    - `-list`: only list the test scripts, do not run. Works in combination
      with '-extended' and '-extended-only' too, to print subsets.
    - `-win`: signal that this is running in a Windows environment, and we
      should run the tests.
    - `--coverage`: this generates a basic coverage report for the RPC
      interface.

For more detailed help on options, run with '--help'.

For a description of arguments recognized by test scripts, see
`qa/pull-tester/test_framework/test_framework.py:BitcoinTestFramework.main`.

"""
import pdb
import os
import time
import shutil
import signal
import sys
import subprocess
import tempfile
import re

# to support out-of-source builds, we need to add both the source directory to the path, and the out-of-source directory
# because tests_config is a generated file
sourcePath = os.path.dirname(os.path.realpath(__file__))
outOfSourceBuildPath = os.path.dirname(os.path.abspath(__file__))
sys.path.append(sourcePath)
if sourcePath != outOfSourceBuildPath:
    sys.path.append(outOfSourceBuildPath)

from tests_config import *
from test_classes import RpcTest, Disabled, Skip

def inTravis():
    return (os.environ.get("TRAVIS", None) == "true")

def inGitLabCI():
    # https://docs.gitlab.com/ee/ci/variables/
    return (os.environ.get("CI_SERVER", None) == "yes")


BOLD = ("","")
if os.name == 'posix':
    # primitive formatting on supported
    # terminal via ANSI escape sequences:
    BOLD = ('\033[0m', '\033[1m')

RPC_TESTS_DIR = SRCDIR + '/qa/rpc-tests/'

CORE_ANALYSIS_SCRIPT = SRCDIR + '/contrib/devtools/coreanalysis.gdb'
CORE_ANALYSIS_TIMEOUT = 60

#If imported values are not defined then set to zero (or disabled)
if 'ENABLE_WALLET' not in vars():
    ENABLE_WALLET=0
if 'ENABLE_NEXAD' not in vars():
    ENABLE_NEXAD=0
if 'ENABLE_UTILS' not in vars():
    ENABLE_UTILS=0
if 'ENABLE_ZMQ' not in vars():
    ENABLE_ZMQ=0

ENABLE_COVERAGE=0
CUSTOM_ELECTRUM_PATH = None

#Create a set to store arguments and create the passOn string
opts = set()
double_opts = set()  # BU: added for checking validity of -- opts
passOn = ""
showHelp = False  # if we need to print help
p = re.compile("^--")
p_parallel = re.compile('^-parallel=')
p_shard = re.compile('^-shard=')
run_parallel = 2
run_shard_index = 1
run_shard_count = 1

# some of the single-dash options applicable only to this runner script
# are also allowed in double-dash format (but are not passed on to the
# test scripts themselves)
private_single_opts = ('-h',
                       '-f',    # equivalent to -force-enable
                       '-help',
                       '-list',
                       '-extended',
                       '-extended-only',
                       '-only-extended',
                       '-force-enable',
                       '-win')
private_double_opts = ('--list',
                       '--extended',
                       '--extended-only',
                       '--only-extended',
                       '--force-enable',
                       '--win')
framework_opts = ('--tracerpc',
                  '--help',
                  '--noshutdown',
                  '--nocleanup',
                  '--no-ipv6-rpc-listen',
                  '--gitlab',
                  '--srcdir',
                  '--tmppfx',
                  '--coveragedir',
                  '--randomseed',
                  '--testbinary',
                  '--refbinary')
test_script_opts = ('--mineblock',
                    '--extensive')

def option_passed(option_without_dashes):
    """check if option was specified in single-dash or double-dash format"""
    return ('-' + option_without_dashes in opts
            or '--' + option_without_dashes in double_opts)

bold = ("","")
if (os.name == 'posix'):
    bold = ('\033[0m', '\033[1m')

for arg in sys.argv[1:]:
    if arg == '--coverage':
        ENABLE_COVERAGE = 1
    elif (p.match(arg) or arg in ('-h', '-help')):
        if arg not in private_double_opts:
            if arg == '--help' or arg == '-help' or arg == '-h':
                passOn = '--help'
                showHelp = True
            else:
                if passOn != '--help':
                    passOn += " " + arg
        # add it to double_opts only for validation
        double_opts.add(arg)
    elif p_parallel.match(arg):
        run_parallel = int(arg.split(sep='=', maxsplit=1)[1])
    elif p_shard.match(arg):
        shard = arg.split(sep='=', maxsplit=1)[1].split('/')
        if len(shard) != 2:
            print("Invalid shard, expected -shard=index/count")
            sys.exit(1)
        try:
            run_shard_index, run_shard_count = map(int, shard)
        except ValueError:
            print("Invalid shard, index and count must be integers")
            sys.exit(1)
        if run_shard_count < 1 or not 1 <= run_shard_index <= run_shard_count:
            print("Invalid shard, index must be between one and count")
            sys.exit(1)

    else:
        # this is for single-dash options only
        # they are interpreted only by this script
        opts.add(arg)

# check for unrecognized options
bad_opts_found = []
bad_opt_str="Unrecognized option: %s"
for o in opts | double_opts:
    if o.startswith('--'):
        if o.split("=")[0] not in framework_opts + test_script_opts + private_double_opts:
            print(bad_opt_str % o)
            bad_opts_found.append(o)
    elif o.startswith('-'):
        if o not in private_single_opts:
            print(bad_opt_str % o)
            bad_opts_found.append(o)
            print("Run with -h to get help on usage.")
            sys.exit(1)

#Set env vars
if "NEXAD" not in os.environ:
    os.environ["NEXAD"] = BUILDDIR + '/src/nexad' + EXEEXT
if "NEXACLI" not in os.environ:
    os.environ["NEXACLI"] = BUILDDIR + '/src/nexa-cli' + EXEEXT

#Disable Windows tests by default
if EXEEXT == ".exe" and not option_passed('win'):
    print("Win tests currently disabled.  Use -win option to enable")
    sys.exit(0)

if not (ENABLE_WALLET == 1 and ENABLE_UTILS == 1 and ENABLE_NEXAD == 1):
    print("No rpc tests to run. Wallet, utils, and nexad must all be enabled")
    sys.exit(0)

# python3-zmq may not be installed. Handle this gracefully and with some helpful info
if ENABLE_ZMQ:
    try:
        import zmq
    except ImportError as e:
        print("ERROR: \"import zmq\" failed. Set ENABLE_ZMQ=0 or " \
            "to run zmq tests, see dependency info in /qa/README.md.")
        raise e

#Tests
testScripts = [ RpcTest(t) for t in [
    Disabled('upgrade_activation', "Already activated on fork1"),
    'readonlyinputs',
    'readonlyinputssim',
    Disabled('hardfork1_activation_blocksizelimit', "Already activated on fork1"),
    'hardfork2_activation_tailstorm',
    'headerPath',
    'rejectReply',
    'msgCookie',
    'capd',
    'testpynode',
    'grouptokens',
    Disabled('sigchecks_inputstandardness_activation', 'Already activated, and mempool bad sigcheck mempool cleanup removed so test will fail'),
    'command_line_args',
    'finalizeblock',
    'expeditedblock',
    'txindex',
    Disabled('segwit_recovery', 'not needed in nextchain'),
    Disabled('bip135basic', 'bip135 uses removed nVersion field'),
    Disabled('ctor', "ctor always on in regtest"),
    'mining_ctor',
    'mining_adaptive_blocksize',
    Disabled('nov152018_forkactivation','Nov 2018 already activated'),
    'miningtest',
    'libnexatest',
    'libnexa_api_wrapper_test',
    'tweak',
    'notify',
    'validateblocktemplate',
    'parallel',
    'wallet --addrType=p2pkt',
    'wallet --addrType=p2pkh',
    'wallet_watchonly',
    'wallet_hd',
    'wallet_dump',
    'listtransactions',
    'receivedby',
    'mempool_resurrect_test',
    'txn_doublespend',
    'txn_clone',
    'getchaintips',
    'rawtransactions',
    'rest',
    'mempool_accept',
    'mempool_spendcoinbase',
    'mempool_reorg',
    'mempool_limit',
    'mempool_packages',
    'mempool_persist',
    'mempool_validate',
    'mempoolsync',
    'httpbasics',
    'multi_rpc',
    'zapwallettxes',
    'proxy_test',
    'merkle_blocks',
    'fundrawtransaction',
    'signrawtransactions',
    'nodehandling',
    'reindex',
    'decodescript',
    Disabled('p2p-fullblocktest', "TODO"),
    'blockchain',
    'disablewallet',
    'sendheaders',
    'keypool',
    'prioritise_transaction',
    Disabled('invalidblockrequest', "TODO"),
    'invalidtxrequest',
    'abandonconflict',
    Disabled('p2p-versionbits-warning', "Need to resolve issue with false positive warnings on mainnet"),
    'importprunedfunds',
    'compactblocks_1',
    'compactblocks_2',
    'graphene_optimized',
    'graphene_versions',
    'graphene_stage2',
    'thinblocks',
    Disabled('checkdatasig_activation', "CDSV has been already succesfully activated, keep test around as a template for other OP activation"),
    'extversion',
    'sighashmatch',
    'getlogcategories',
    'getrawtransaction',
    'rpc_getblockstats',
    'rpc_getutxo',
    'minimaldata',
    'schnorrmultisig',
    'uptime',
    'op_reversebytes',
    'bip69',
    'op_store_load',
] ]

testScriptsExt = [ RpcTest(t) for t in [
    'not_so_big_wallet_4node',
    'walletbackup',
    'limits',
    'weirdtx',
    'txPerf',
    'parallel --extensive',
    'bip65-cltv',
    'bip68_sequence',
    Disabled('bipdersig-p2p', "keep as an example of testing fork activation"),
    'bipdersig',
    'bip135-grace',
    'bip135-grace-failed',
    'bip135-threshold',
    'getblocktemplate_longpoll',
    'getblocktemplate_proposals',
    'txn_clone --mineblock',
    Disabled('pruning', "too much disk"),
    'invalidateblock',
    Disabled('rpcbind_test', "temporary, bug in libevent, see #6655"),
    'smartfees',
    Disabled('maxblocksinflight', "needs a rewrite and is already somewhat tested in sendheaders.py"),
    'p2p-acceptblock',
    'maxuploadtarget'
] ]

#Enable ZMQ tests
if ENABLE_ZMQ == 1:
    testScripts.append(RpcTest('zmq_test'))
    testScripts.append(RpcTest('interface_zmq'))
    testScripts.append(RpcTest('rpc_zmq'))

def show_wrapper_options():
    """ print command line options specific to wrapper """
    print("Wrapper options:")
    print()
    print("  -parallel=num         run this number of tests at the same time (default 2)")
    print("  -shard=index/count    run one deterministic, one-based test shard")
    print("  -extended/--extended  run the extended set of tests")
    print("  -only-extended / -extended-only\n" + \
          "  --only-extended / --extended-only\n" + \
          "                        run ONLY the extended tests")
    print("  -list / --list        only list test names")
    print("  -win / --win          signal running on Windows and run those tests")
    print("  -f / -force-enable / --force-enable\n" + \
          "                        attempt to run disabled/skipped tests")
    print("  -h / -help / --help   print this help")

def show_framework_options():
    """ print command line options that are passed to each test """
    print("Framework options:")
    print("  These options are passed to every test that is run.")
    print("""
  --tracerpc              Print out all RPC calls as they are made.
  --noshutdown            Do not stop any full nodes after the test completes.
  --nocleanup             Do not delete the full node directories even if the test succeeded.
  --no-ipv6-rpc-listen    Switch off listening on the IPv6 ::1 localhost RPC port (use if your environmnent does not support IPV6).
  --gitlab                Changes root directory for gitlab artifact exporting. overrides tmpdir and tmppfx.
  --srcdir                Source directory containing nexad and nexa-cli
  --tmppfx                All full node directories are created in a test-specific subdirectories of this dir (for example, --tmppfx=/ramdisk/test).
  --coveragedir           Write tested RPC commands into this directory
  --randomseed            Set RNG seed for tests that use randomness (ignored otherwise)
  --testbinary            nexad binary to run.
  --refbinary             nexad binary to use for reference nodes (if any).
""")

def runtests():
    global passOn
    coverage = None
    test_passed = []
    disabled = []
    skipped = []
    tests_to_run = []

    force_enable = option_passed('force-enable') or '-f' in opts
    run_only_extended = option_passed('only-extended') or option_passed('extended-only')

    if option_passed('list'):
        tests_to_list = list(testScriptsExt if run_only_extended else testScripts)
        if not run_only_extended and option_passed('extended'):
            tests_to_list += testScriptsExt
        tests_to_list = tests_to_list[run_shard_index - 1::run_shard_count]
        for t in tests_to_list:
            print(t)
        sys.exit(0)

    if ENABLE_COVERAGE:
        coverage = RPCCoverage()
        print("Initializing coverage directory at %s\n" % coverage.dir)

    if(ENABLE_WALLET == 1 and ENABLE_UTILS == 1 and ENABLE_NEXAD == 1):
        rpcTestDir = RPC_TESTS_DIR
        buildDir   = BUILDDIR
        run_extended = option_passed('extended') or run_only_extended
        cov_flag = coverage.flag if coverage else ''
        flags = " --srcdir %s/src %s %s" % (buildDir, cov_flag, passOn)

        # compile the list of tests to check

        # check for explicit tests
        if showHelp:
            print("usage: rpc-tests.py [flags] [tests to run]")
            show_wrapper_options()
            print()
            show_framework_options()
            quit()
        else:
            for o in opts:
                if not o.startswith('-'):
                    found = False
                    for t in testScripts + testScriptsExt:
                        t_rep = str(t).split(' ')
                        if (t_rep[0] == o or t_rep[0] == o + '.py') and len(t_rep) > 1:
                            # it is a test with args - check all args match what was passed, otherwise don't add this test
                            t_args = t_rep[1:]
                            all_args_found = True
                            for targ in t_args:
                                if not targ in passOn.split(' '):
                                    all_args_found = False

                            if all_args_found:
                                tests_to_run.append(t)
                                found = True
                        elif t_rep[0] == o or t_rep[0] == o + '.py':
                            passOnSplit = [x for x in passOn.split(' ') if x != '']
                            found_non_framework_opt = False
                            for p in passOnSplit:
                                if p in test_script_opts:
                                    found_non_framework_opt = True
                            if not found_non_framework_opt:
                                tests_to_run.append(t)
                                found = True
                    if not found:
                        print("Error: %s is not a known test." % o)
                        sys.exit(1)

        # if no explicit tests specified, use the lists
        if not len(tests_to_run):
            if run_only_extended:
                tests_to_run = testScriptsExt
            else:
                tests_to_run += testScripts
                if run_extended:
                    tests_to_run += testScriptsExt

        # weed out the disabled / skipped tests and print them beforehand
        # this allows earlier intervention in case a test is unexpectedly
        # skipped
        if not force_enable:
            trimmed_tests_to_run = []
            for t in tests_to_run:
                if t.is_disabled():
                    print("Disabled testscript %s%s%s (reason: %s)" % (bold[1], t, bold[0], t.reason))
                    disabled.append(str(t))
                elif t.is_skipped():
                    print("Skipping testscript %s%s%s on this platform (reason: %s)" % (bold[1], t, bold[0], t.reason))
                    skipped.append(str(t))
                else:
                    trimmed_tests_to_run.append(t)
            tests_to_run = trimmed_tests_to_run

        tests_to_run = tests_to_run[run_shard_index - 1::run_shard_count]
        if run_shard_count > 1:
            print("Running test shard %d/%d (%d tests)" %
                  (run_shard_index, run_shard_count, len(tests_to_run)))

        # if all specified tests are disabled just quit
        if len(tests_to_run) == 0:
            quit()

        if len(tests_to_run) > 1 and run_parallel:
            # Populate cache
            cCargs = [RPC_TESTS_DIR + 'create_cache.py'] + [x.strip() for x in flags.split()] + (["--no-ipv6-rpc-listen"] if option_passed("no-ipv6-rpc-listen") else [])
            subprocess.check_output(cCargs)

        tests_to_run = list(map(str,tests_to_run))
        max_len_name = len(max(tests_to_run, key=len))
        time_sum = 0
        time0 = time.time()
        job_queue = RPCTestHandler(run_parallel, tests_to_run, flags)
        results = BOLD[1] + "%s | %s | %s\n\n" % ("TEST".ljust(max_len_name), "PASSED", "DURATION") + BOLD[0]
        all_passed = True

        for _ in range(len(tests_to_run)):
            (name, retCode, coreOutput, stdout, stderr, stderr_filtered, passed, duration) = job_queue.get_next()
            test_passed.append(passed)
            all_passed = all_passed and passed
            time_sum += duration
            results += "%s | %s | %s s\n" % (name.ljust(max_len_name), str(passed).ljust(6), duration)

            print("")
            if inTravis():
                print("travis_fold:start:%s_%s" % (name, passed))
            print(BOLD[1] + name + BOLD[0] + ": Pass: %s%s%s, Duration: %s s" % (BOLD[1], passed, BOLD[0], duration))
            print("#"*50)
            print("- " + retCode)
            if stdout != "":
                print('- stdout '+("-"*50)+"\n", stdout)
            if stderr != "":
                print('- stderr '+("-"*50)+"\n", stderr)
            if coreOutput != "":
                if inTravis():  # if in travis we already folded this
                    print(coreOutput)
                else: # so no need for another header
                    print('- core dump '+("-"*50)+"\n", coreOutput)
            #print('stderr_filtered:\n' if not stderr_filtered == '' else '', repr(stderr_filtered))
            print("#"*25)
            if inTravis():
                print("travis_fold:end:%s_%s" % (name, passed))

        results += BOLD[1] + "\n%s | %s | %s s (accumulated)" % ("ALL".ljust(max_len_name), str(all_passed).ljust(6), time_sum) + BOLD[0]
        print(results)
        print("\nRuntime: %s s" % (int(time.time() - time0)))

        if coverage:
            coverage.report_rpc_coverage()

            print("Cleaning up coverage data")
            coverage.cleanup()

        if not showHelp:
            # show some overall results and aggregates
            print()
            print("%d test(s) passed / %d test(s) failed / %d test(s) executed" % (test_passed.count(True),
                                                                       test_passed.count(False),
                                                                       len(test_passed)))
            print("%d test(s) disabled / %d test(s) skipped due to platform" % (len(disabled), len(skipped)))

        # signal that tests have failed using exit code
        sys.exit(not all_passed)

    else:
        print("No rpc tests to run. Wallet, utils, and nexad must all be enabled")

class RPCTestHandler:
    """
    Trigger the testscrips passed in via the list.
    """

    def __init__(self, num_tests_parallel, test_list=None, flags=None):
        assert(num_tests_parallel >= 1)
        self.num_jobs = num_tests_parallel
        self.test_list = test_list
        self.flags = flags
        self.num_running = 0
        # In case there is a graveyard of zombie nexads, we can apply a
        # pseudorandom offset to hopefully jump over them.
        # 3750 is PORT_RANGE/MAX_NODES defined in util, but awkward to import into rpc-test.py
        self.portseed_offset = int(time.time() * 1000) % 3750
        self.jobs = []

    @staticmethod
    def _new_log_file():
        return tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)

    @staticmethod
    def _read_and_remove_log(log_file):
        path = log_file.name
        log_file.close()
        try:
            with open(path, mode="r", encoding="utf-8", errors="replace") as reader:
                return reader.read()
        finally:
            os.remove(path)

    @staticmethod
    def _retire_core(full_core_file, core, test_name):
        if inGitLabCI():
            saved_cores = os.path.join(os.environ.get("CI_PROJECT_DIR", None), "saved-cores")
            os.makedirs(saved_cores, exist_ok=True)
            shutil.move(full_core_file, os.path.join(saved_cores, str(core) + "-" + str(test_name)))
        else:
            os.remove(full_core_file)

    def get_next(self):
        while self.num_running < self.num_jobs and self.test_list:
            # Add tests
            self.num_running += 1
            t = self.test_list.pop(0)
            port_seed = ["--portseed={}".format(len(self.test_list) + self.portseed_offset)]
            log_stdout = self._new_log_file()
            log_stderr = self._new_log_file()
            print("Starting %s" % t)
            self.jobs.append((t,
                              time.time(),
                              subprocess.Popen((RPC_TESTS_DIR + t).split() + self.flags.split() + port_seed,
                                               universal_newlines=True,
                                               stdin=subprocess.DEVNULL,
                                               stdout=log_stdout,
                                               stderr=log_stderr,
                                               close_fds=True,
                                               restore_signals=True,
                                               start_new_session=True),
                              log_stdout, log_stderr))
        if not self.jobs:
            raise IndexError('pop from empty list')
        count = 0
        while True:
            count+=1
            # Return first proc that finishes
            time.sleep(.5)
            for j in self.jobs:
                (name, time0, proc, log_stdout, log_stderr) = j
                if ((inGitLabCI() or inTravis()) and int(time.time() - time0) > 20 * 60):
                    # In external CI services, timeout individual tests after 20 minutes (to stop tests hanging and not
                    # providing useful output.
                    proc.send_signal(signal.SIGINT)

                retval = proc.poll()
                if retval is not None:

                    coreOutputs = []
                    if inGitLabCI():
                        coreDir = os.path.join(os.environ.get("CI_PROJECT_DIR", None), "cores")
                    else:
                        coreDir = "/tmp/cores"
                    try:
                        cores = os.listdir(coreDir)
                    except Exception as e:
                        print("Exception trying to list core files in " + coreDir + " :" + str(e))
                        cores = []

                    for core in cores:
                        print("Trying to analyze core file: " + str(core))
                        fullCoreFile = os.path.join(coreDir, core)
                        try:
                            nexadBin = os.environ["NEXAD"]
                            if os.path.isfile(CORE_ANALYSIS_SCRIPT):
                                popenList = ["gdb", "-core", fullCoreFile, nexadBin, "-x", CORE_ANALYSIS_SCRIPT, "-batch"]
                            else:
                                popenList = ["gdb", "-core", fullCoreFile, nexadBin, "-ex", "thread apply all bt", "-ex", "set pagination 0", "-batch"]
                            gdb = subprocess.Popen(popenList, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            try:
                                (out, err) = gdb.communicate(timeout=CORE_ANALYSIS_TIMEOUT)
                            except subprocess.TimeoutExpired:
                                gdb.kill()
                                (out, err) = gdb.communicate()
                                err += "\nCore dump analysis timed out after %s seconds; GDB was terminated.\n" % CORE_ANALYSIS_TIMEOUT
                            fold_start = ("\ntravis_fold:start:%s\nCore dump analysis\n" % core) if inTravis() else ""
                            fold_end = ("\ntravis_fold:end:%s\n" % core) if inTravis() else ""
                            coreOutputs.append(fold_start + out + "\n-------\n" + err + fold_end)
                        except Exception as e:
                            coreOutputs.append("Exception trying to analyze core file " + fullCoreFile + " :" + str(e))
                        finally:
                            try:
                                self._retire_core(fullCoreFile, core, name)
                            except Exception as e:
                                coreOutputs.append("Exception trying to retire core file " + fullCoreFile + " :" + str(e))
                    coreOutput = "\n".join(coreOutputs)

                    returnCode = "Process %s return code: %d" % (" ".join(proc.args),retval)
                    stdout = self._read_and_remove_log(log_stdout)
                    stderr = self._read_and_remove_log(log_stderr)
                    passed = stderr == "" and proc.returncode == 0

                    # This is a list of expected messages on stderr. If they appear, they do not
                    # necessarily indicate final failure of a test.

                    # These 2 are due to accidental port conflicts caused by running multiple tests simultaneously.
                    stderr_filtered = stderr.replace("Error: Unable to start HTTP server. See debug log for details.", "")
                    stderr_filtered = stderr.replace("Error: Unable to start RPC services. See debug log for details.", "")

                    stderr_filtered = re.sub(r"Error: Unable to bind to 0.0.0.0:[0-9]+ on this computer\. BCH Unlimited is probably already running\.",
                                             "", stderr_filtered)
                    invalid_index = re.compile(r'.*?\n.*?EXCEPTION.*?\n.*?invalid index for tx.*?\n.*?ProcessMessages.*?\n', re.MULTILINE)
                    stderr_filtered = invalid_index.sub("", stderr_filtered)
                    stderr_filtered = stderr_filtered.replace("Error: Failed to listen on any port. Use -listen=0 if you want this.", "")
                    stderr_filtered = stderr_filtered.replace("Error: Failed to listen on all P2P ports. Failing as requested by -bindallorfail.", "")
                    stderr_filtered = stderr_filtered.replace(" ", "")
                    stderr_filtered = stderr_filtered.replace("\n", "")
                    passed = stderr_filtered == "" and proc.returncode == 0
                    self.num_running -= 1
                    self.jobs.remove(j)
                    return name, returnCode, coreOutput, stdout, stderr, stderr_filtered, passed, int(time.time() - time0)
            print('.', end=('' if count%160!=0 else '\n'), flush=True)

class RPCCoverage(object):
    """
    Coverage reporting utilities for pull-tester.

    Coverage calculation works by having each test script subprocess write
    coverage files into a particular directory. These files contain the RPC
    commands invoked during testing, as well as a complete listing of RPC
    commands per `nexa-cli help` (`rpc_interface.txt`).

    After all tests complete, the commands run are combined and diff'd against
    the complete list to calculate uncovered RPC commands.

    See also: qa/rpc-tests/test_framework/coverage.py

    """
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="coverage")
        self.flag = '--coveragedir %s' % self.dir

    def report_rpc_coverage(self):
        """
        Print out RPC commands that were unexercised by tests.

        """
        uncovered = self._get_uncovered_rpc_commands()

        if uncovered:
            print("Uncovered RPC commands:")
            print("".join(("  - %s\n" % i) for i in sorted(uncovered)))
        else:
            print("All RPC commands covered.")

    def cleanup(self):
        return shutil.rmtree(self.dir)

    def _get_uncovered_rpc_commands(self):
        """
        Return a set of currently untested RPC commands.

        """
        # This is shared from `qa/rpc-tests/test-framework/coverage.py`
        REFERENCE_FILENAME = 'rpc_interface.txt'
        COVERAGE_FILE_PREFIX = 'coverage.'

        coverage_ref_filename = os.path.join(self.dir, REFERENCE_FILENAME)
        coverage_filenames = set()
        all_cmds = set()
        covered_cmds = set()

        if not os.path.isfile(coverage_ref_filename):
            raise RuntimeError("No coverage reference found")

        with open(coverage_ref_filename, 'r') as f:
            all_cmds.update([i.strip() for i in f.readlines()])

        for root, dirs, files in os.walk(self.dir):
            for filename in files:
                if filename.startswith(COVERAGE_FILE_PREFIX):
                    coverage_filenames.add(os.path.join(root, filename))

        for filename in coverage_filenames:
            with open(filename, 'r') as f:
                covered_cmds.update([i.strip() for i in f.readlines()])

        return all_cmds - covered_cmds


if __name__ == '__main__':
    runtests()
