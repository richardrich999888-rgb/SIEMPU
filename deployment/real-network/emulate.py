"""CORE/Mininet adapters for the actual SIEPMU processes. Shared-kernel evidence only."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--backend', choices=['core', 'mininet'], required=True)
parser.add_argument('--state', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--execute', action='store_true')
args = parser.parse_args()
state, output, root = Path(args.state).resolve(), Path(args.output).resolve(), Path.cwd()
output.mkdir(parents=True, exist_ok=False)
report = {'backend': args.backend, 'evidenceClass': 'EMULATED_SHARED_KERNEL', 'independentHosts': False,
          'startedAtUnixMs': time.time_ns() // 1000000, 'rows': [], 'outcome': 'BLOCKED',
          'profile': {'repetitions': 3, 'messagesPerProfile': 5, 'bytes': 4096, 'timeoutSeconds': 30}}


def save():
    (output / 'emulation.json').write_text(json.dumps(report, indent=2) + '\n')


try:
    report['source'] = json.loads(subprocess.check_output(['node', 'deployment/real-network/source.mjs'], text=True, timeout=10))
except (OSError, ValueError, subprocess.SubprocessError):
    report['reason'] = 'CLEAN_FROZEN_SOURCE_REQUIRED'
    save()
    raise SystemExit(2)

missing = [name for name in ['ip', 'tc', 'setpriv', 'setsid', 'timeout', 'node'] if not shutil.which(name)]
if os.geteuid() != 0 or missing or importlib.util.find_spec(args.backend) is None or not args.execute:
    report['reason'] = {'rootRequired': os.geteuid() != 0, 'missingTools': missing,
                        'moduleAvailable': importlib.util.find_spec(args.backend) is not None,
                        'executionRequested': args.execute}
    save()
    print(json.dumps({'outcome': 'BLOCKED', 'report': str(output / 'emulation.json')}))
    raise SystemExit(2)

config = json.loads((state / 'deployment.json').read_text())
assert config['mode'] == 'multi-host'
report['source'] = config['source']
nodes, processes = {}, []
net = session = core = None
node_binary = shutil.which('node')
owner = state.stat()
drop = ['setpriv', '--reuid', str(owner.st_uid), '--regid', str(owner.st_gid), '--clear-groups']


def command(name, argv, shell=False, accepted=(0,)):
    text = argv if shell else shlex.join(argv)
    # Both backends run the same explicit shell exit oracle. Mininet otherwise
    # returns stdout even when tc/mount fails; that must never become a pass.
    wrapped = '{ ' + text + '; }; p047_rc=$?; printf "\\nP047_EXIT=%d\\n" "$p047_rc"'
    response = nodes[name].cmd(wrapped, shell=True) if args.backend == 'core' else nodes[name].cmd(wrapped)
    body, marker, status = response.rpartition('\nP047_EXIT=')
    if not marker or not status.strip().isdigit():
        raise RuntimeError('COMMAND_EXIT_RECORD_MISSING:' + name)
    if int(status.strip()) not in accepted:
        raise RuntimeError('COMMAND_FAILED:' + name + ':' + status.strip() + ':' + body[-300:])
    return body


def endpoint(name, role, operation, arg=None):
    argv = ['timeout', '30'] + drop + [node_binary, str(root / 'deployment/real-network/endpoint.mjs'),
                                     str(state / name / role), operation]
    if arg is not None:
        argv.append(str(arg))
    response = command(name, argv, accepted=(0, 1))
    return json.loads(response.strip().splitlines()[-1])


try:
    if args.backend == 'mininet':
        from mininet.net import Mininet
        from mininet.nodelib import LinuxBridge
        from mininet.link import TCLink
        net = Mininet(controller=None, switch=LinuxBridge, link=TCLink, build=False, ipBase='10.77.0.0/24')
        switch = net.addSwitch('p047s')
        for index, name in enumerate('ABCDEF', 1):
            nodes[name] = net.addHost('p047' + name.lower(), ip=f'10.77.0.{index}/24',
                                      privateDirs=[('/etc/hosts', str(state / 'hosts.example'))])
            net.addLink(nodes[name], switch)
        net.build()
        net.start()
    else:
        from core.emulator.coreemu import CoreEmu
        from core.emulator.data import InterfaceData
        from core.emulator.enumerations import EventTypes
        from core.nodes.base import CoreNode
        from core.nodes.network import SwitchNode
        core = CoreEmu()
        os.umask(0o077)
        session = core.create_session()
        session.set_state(EventTypes.CONFIGURATION_STATE)
        switch = session.add_node(SwitchNode)
        for index, name in enumerate('ABCDEF', 1):
            options = CoreNode.create_options()
            options.model = 'p047-application-only'
            nodes[name] = session.add_node(CoreNode, name='p047' + name.lower(), options=options)
            session.add_link(nodes[name].id, switch.id, InterfaceData(id=0, name='eth0', ip4=f'10.77.0.{index}', ip4_mask=24))
        startup_errors = session.instantiate()
        assert not startup_errors, 'CORE_NODE_STARTUP_FAILED'
        for name in nodes:
            command(name, ['mount', '--bind', str(state / 'hosts.example'), '/etc/hosts'])
    for name in 'DCB':
        log = state / name / 'service-private.log'
        argv = ['setsid'] + drop + [node_binary, str(root / 'deployment/real-network/host.mjs'), str(state / name)]
        pid = command(name, f'cd {shlex.quote(str(root))} || exit; {shlex.join(argv)} > {shlex.quote(str(log))} 2>&1 & echo $!', shell=True).strip().splitlines()[-1]
        assert pid.isdigit()
        processes.append(int(pid))
    for _ in range(60):
        try:
            if endpoint('A', 'unit-a', 'probe')['ok']:
                break
        except (ValueError, RuntimeError):
            pass
        time.sleep(.2)
    else:
        raise RuntimeError('SERVICE_READINESS')
    for name, role in [('A', 'unit-a'), ('E', 'unit-b'), ('E', 'unit-denied')]:
        assert endpoint(name, role, 'init' if role == 'unit-a' else 'login')['ok']
    interface = 'eth0' if args.backend == 'core' else str(nodes['A'].defaultIntf())
    profiles = {
        'N0': ['delay', '0ms'],
        'N1': ['delay', '50ms', '10ms', 'distribution', 'normal'],
        'N2': ['delay', '50ms', 'loss', '1%', 'duplicate', '0.1%'],
        'N3': ['delay', '50ms', 'reorder', '25%', '50%'],
    }
    for label, netem in profiles.items():
        command('A', ['tc', 'qdisc', 'replace', 'dev', interface, 'root', 'netem'] + netem)
        for repetition in range(3):
            for index in range(5):
                began = time.monotonic_ns()
                sent = endpoint('A', 'unit-a', 'send', 4096)
                assert sent['ok']
                received = endpoint('E', 'unit-b', 'receive', sent['result']['objectId'])
                assert received['ok'] and received['result']['sha256'] == sent['result']['sha256']
                report['rows'].append({'profile': label, 'repetition': repetition, 'index': index,
                                       'outcome': 'PASS', 'elapsedMs': (time.monotonic_ns()-began)/1e6,
                                       'sent': sent, 'received': received})
                save()
        observed = json.loads(command('A', ['tc', '-s', '-j', 'qdisc', 'show', 'dev', interface]))
        assert any(item.get('kind') == 'netem' and item.get('packets', 0) > 0 for item in observed), 'NETEM_NOT_OBSERVED'
        report['rows'].append({'profile': label, 'observedQdisc': observed})
    queued = endpoint('A', 'unit-a', 'queue', 4096)
    assert queued['ok']
    command('A', ['tc', 'qdisc', 'replace', 'dev', interface, 'root', 'netem', 'loss', '100%'])
    denied = endpoint('A', 'unit-a', 'submit', queued['result']['objectId'])
    assert not denied['ok']
    command('A', ['tc', 'qdisc', 'replace', 'dev', interface, 'root', 'netem', 'delay', '0ms'])
    assert endpoint('A', 'unit-a', 'submit', queued['result']['objectId'])['ok']
    received = endpoint('E', 'unit-b', 'receive', queued['result']['objectId'])
    assert received['ok'] and received['result']['sha256'] == queued['result']['sha256']
    report['rows'].append({'id': 'NET-05', 'outcome': 'PASS', 'outageResult': denied, 'reconnection': received})
    report['outcome'] = 'PASS_EMULATION_ONLY'
except Exception as error:
    report['outcome'] = 'FAIL'
    report['error'] = type(error).__name__ + ': ' + str(error)[:300]
finally:
    for pid in processes:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 6
    while processes and time.monotonic() < deadline:
        remaining = []
        for pid in processes:
            try:
                os.killpg(pid, 0)
                remaining.append(pid)
            except ProcessLookupError:
                pass
        processes = remaining
        if processes:
            time.sleep(.1)
    for pid in processes:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if net:
        net.stop()
    if session:
        session.shutdown()
    report['finishedAtUnixMs'] = time.time_ns() // 1000000
    save()
print(json.dumps({'outcome': report['outcome'], 'report': str(output / 'emulation.json')}))
raise SystemExit(1 if report['outcome'] == 'FAIL' else 0)
