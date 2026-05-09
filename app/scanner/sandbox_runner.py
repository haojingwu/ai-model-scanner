"""Docker沙箱调度"""
import docker, json

client = docker.from_env()
SANDBOX_IMAGE = 'model-sandbox:latest'
TIMEOUT = 30

def run_sandbox(model_path: str, model_type: str) -> dict:
    try:
        container = client.containers.run(
            image=SANDBOX_IMAGE,
            command=f'/model/file {model_type}',
            volumes={model_path: {'bind': '/model/file', 'mode': 'ro'}},
            network_mode='none',
            mem_limit='512m',
            cpu_quota=50000,
            user='sandbox',
            security_opt=['no-new-privileges'],
            cap_drop=['ALL'],
            detach=True,
            remove=False,
        )
        try:
            result = container.wait(timeout=TIMEOUT)
            exit_code = result['StatusCode']
        except Exception:
            container.kill()
            exit_code = -1
        logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='ignore')
        container.remove(force=True)
        try:
            return json.loads(logs.strip().split('\n')[-1])
        except:
            return {'status': 'parse_error', 'exit_code': exit_code, 'raw_log': logs[:500]}
    except Exception as e:
        return {'status': 'docker_error', 'error': str(e)}