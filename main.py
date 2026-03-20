from typing import Annotated
import typer
from pick import pick
import sys
import logging
import json
import yaml
from datetime import datetime
from kubernetes import client, config
from dataclasses import dataclass, field, asdict
from rich.console import Console
from rich.table import Table

SYSTEM_NAMESPACES_LIST = ["cilium-secrets", "kube-node-lease", "kube-public", "kube-system", "longhorn-system", "vso-system", "traefik", "velero", "cnpg-system", "cert-manager"]
SEVERITY_DICT = {"critical": 1, "high": 2, "medium": 3, "low": 4}
TABLE_COLUMNS = ["namespace", "name", "container", "issue", "severity"]
TABLE_NAME_OVERRIDE = "Kubernetes Cluster Misconfiguration Auditor"

@dataclass
class Findings:
    time: str
    namespace: str
    name: str
    container: str
    issue: str
    severity: str

@dataclass
class KubernetesMisconfigurationAuditor:
    """
    Tool to automatically find resources that are misconfigured.
    Output is in form of table.
    """
    findings: list[Findings] = field(default_factory=list)
    table: Table = field(default_factory=Table)

    def get_context_names(self):
        """
        Gather context names from Kubeconfig.
        Return list of context names, and current active context
        """
        contexts, active_context = config.list_kube_config_contexts()
        if not contexts:
            raise config.ConfigException("Failed to load contexts")

        context_names = [context['name'] for context in contexts]
        active_context_name = active_context['name']
        active_context_index = context_names.index(active_context['name'])

        return context_names, active_context_name, active_context_index

    def list_contexts(self, list_contexts, context, context_names):
        """
        List all context names from Kubeconfig.
        """
        if list_contexts and context:
            raise ValueError("Can't list contexts and print data for certain context at the same time! Choose only one of those parameters.")
            sys.exit(1)
        if list_contexts:
            console.print("[bold]Available context names[/bold]:")
            for context in context_names:
                print(f"  {context}")

            # Gracefully quit the program
            sys.exit(0)

    def select_context(self, context, it, format, context_names, active_context_name, active_context_index):
        """
        Select Kubernetes context. If `context` user-defined as part of CLI parameter, then Kubeconfig is loaded.
        Otherwise interactive contexts window selector is shown to user to choose from.
        """
        if context and context not in context_names:
            raise ValueError(f"Context name '{context}' not in list of contexts.")
            sys.exit(1)
        # if --context and --it options are defined - print error
        elif context and it:
            raise ValueError("You cannot explicitely define context and interactive selection of context!")
            sys.exit(1)
        elif not context and not format and it:
            # context = misconf_auditor.pick_context(context_names, active_context_name)
            context, _ = pick(context_names, "Pick Kubernetes context to load", default_index=active_context_index)
        else:
            # If interactive mode is disabled (default), no cluster is selected explicitely, use active context name
            context = active_context_name
        
        return context

    def get_all_namespaces(self, v1):
        """
        Gather info about all namespaces. Going to be filtered out in case user will not specify any namespace
        """
        namespaces = v1.list_namespace()
        all_namespaces_list = []

        for namespace in namespaces.items:
            all_namespaces_list.append(namespace.metadata.name)

        return all_namespaces_list

    def audit_pod(self, pod):
        """
        Central Pod check system.
        Gatheres data from Pods if one or more are missing or have dangerous consequences:
            - resources of container, security context, probes, image tag
        """
        name = pod.metadata.name
        namespace = pod.metadata.namespace

        for container in pod.spec.containers:
            container_report = []
            time = datetime.now().isoformat()

            container_report.append(self.check_resources(container))
            container_report.append(self.check_security_context(container))
            container_report.append(self.check_probes(container))
            container_report.append(self.check_image_tag(container))

            for report in container_report:
                if report:
                    self.findings.append(Findings(time=time, namespace=namespace, name=name, container=container.name, issue=report['issue'], severity=report['severity']))
                else:
                    continue

    def check_resources(self, container):
        """Checks container for resources"""
        requests = container.resources.requests
        limits = container.resources.limits

        if not requests and not limits:
            return {"issue": "no resources defined", "severity": "high"}
        elif not requests:
            return {"issue": "requests undefined", "severity": "medium"}
        elif not limits:
            return {"issue": "limits undefined", "severity": "low"}

    def check_security_context(self, container):
        """Checks for security context and whther container is running as root"""
        security_context = container.security_context
        # Will be overwritten, assumin worst case scenario
        run_as_non_root: bool = False

        if security_context:
            run_as_non_root = security_context.run_as_non_root
        if security_context is None or not run_as_non_root:
            return {"issue": "container runs as root", "severity": "critical"}

    def check_probes(self, container):
        """Checks for liveness and readiness probes"""
        if not container.liveness_probe and not container.readiness_probe:
            return {"issue": "probes undefined", "severity": "medium"}
        elif not container.readiness_probe:
            return {"issue": "readiness probe undefined", "severity": "medium"}
        elif not container.liveness_probe:
            return {"issue": "linebess probe undefined", "severity": "medium"}

    def check_image_tag(self, container):
        """Search for `latest` image tag"""
        # Image name format: registry.exaple.com:5000/myapp:v1.2
        image_name_split = container.image.split(":")

        # Image does not have to explicitely have tag - image: nginx
        if len(image_name_split) == 1:
            return {"issue": "no image tag (default: latest)", "severity": "high"}
        elif image_name_split[-1] == 'latest':
            return {"issue": "latest image tag", "severity": "high"}

    def namespace_selector(self, v1, namespace):
        """
        Based on namespace existence, choose whether:
            - Get all pods if `all` or nothing specified
            - Get pods from specified namespace (ns existence check)
        Then iterate over each V1PodList:
            - Audit Pod if namespace was specified
            - If wasn't (then user wants non-system namespaces), and logic will filter so
        """
        if namespace == 'all' or not namespace:
            pods = v1.list_pod_for_all_namespaces()
        else:
            # Print error if namespace do not exist
            namespaces = self.get_all_namespaces(v1)

            if namespace not in namespaces:
                raise ValueError(f"Did not found '{namespace}' namespace in the specified cluster.")

            # If namespace exist, logic continues
            pods = v1.list_namespaced_pod(namespace)

        for pod in pods.items:
            if namespace:
                self.audit_pod(pod)
            # Filter and keep non-system pods
            elif not namespace:
                if not SYSTEM_NAMESPACES_LIST:
                    raise ValueError("Variable 'SYSTEM_NAMESPACES_LIST' with system namespaces cannot be blank!")
                if pod.metadata.namespace in SYSTEM_NAMESPACES_LIST:
                    continue
                else:
                    self.audit_pod(pod)

    def filter_by_severity(self, severity):
        """
        Filter Data by severity
        """
        if not SEVERITY_DICT:
            raise ValueError("Severity dict 'SEVERITY_DICT' cannot be blank!")
        if severity in SEVERITY_DICT.keys():
            filtered_findings = []

            for finding in self.findings:
                if finding.severity == severity.lower():
                    filtered_findings.append(finding)

            self.findings = filtered_findings
        elif severity != "":
            severities = str(list(SEVERITY_DICT.keys())).replace("'", "").strip("[]")
            logger.error(f"Severity '{severity}' does not exist! Available options are: {severities}")
            sys.exit(1)

    def sort_by_column(self, sort):
        """
        Sort column alphabetically except severity (this will be sorted custom)
        """
        if not sort:
            return

        if sort not in TABLE_COLUMNS:
            raise ValueError(f"Column '{sort}' does not exist!")

        if sort.lower() == 'severity':
            sorted_findings = sorted(self.findings, key=lambda item: SEVERITY_DICT[item.severity])
        elif sort and sort.lower() != 'severity':
            sorted_findings = sorted(self.findings, key=lambda x: getattr(x, sort))

        self.findings = sorted_findings

    def render_report(self, format):
        """
        Based on format parameter gathered data, render happens.
        """
        if not self.findings:
            raise ValueError("Table is empty.")

        if not format:
            self.table: Table = Table(title=TABLE_NAME_OVERRIDE)

            if not TABLE_COLUMNS:
                logger.error("Table of columns is blank!")
                sys.exit(1)

            for column in TABLE_COLUMNS:
                self.table.add_column(column)

        for finding in self.findings:
            if format.lower() == 'json':
                self.render_json_report(finding)
            elif format.lower() == 'yaml':
                self.render_yaml_report(finding)
            else:
                self.render_table_report(finding)

        if not format:
            console.print(self.table)

    def render_table_report(self, finding):
        """
        Table report is rendered when no format parameter is defined.
        Inizialization (e.g. setting header, adding columns) of the table happens first, then rows are added, last thing is to render whole table.
        """
        if finding.severity == 'critical':
            self.table.add_row(finding.namespace, finding.name, finding.container, finding.issue, finding.severity, style="red")
        elif finding.severity == 'high':
            self.table.add_row(finding.namespace, finding.name, finding.container, finding.issue, finding.severity, style="dark_orange")
        else:
            self.table.add_row(finding.namespace, finding.name, finding.container, finding.issue, finding.severity)

    def render_json_report(self, finding):
        output = json.dumps(asdict(finding))
        console.print(output)

    def render_yaml_report(self, finding):
        output = yaml.dump(asdict(finding))
        console.print(output)

# --- Create instances ---
console = Console()
logger = logging.getLogger(__name__)
app = typer.Typer()
misconf_auditor = KubernetesMisconfigurationAuditor()

@app.command()
def main(
    namespace: Annotated[str, typer.Option(help="Namespace to print (Default: all non-system namespaces) | `all` to print all namespaces")] = "",
    severity: Annotated[str, typer.Option(help="Severity level to filter (Default: no filtering)")] = "",
    sort: Annotated[str, typer.Option(help="Column to sort alphabetically, `severity` column is sorted by severity (Default: namespace)")] = "",
    format: Annotated[str, typer.Option(help="Change output style to JSON or YAML (Default: table)")] = "",
    context: Annotated[str, typer.Option(help="Select a context name explicitely without interactive window")] = "",
    list_contexts: bool = typer.Option(False, help="List all context names"),
    it: bool = typer.Option(False, help="Enable interactive context selection - pick (Default: False)")
    ):

    try:
        # --- List contexts and select one ---
        context_names, active_context_name, active_context_index = misconf_auditor.get_context_names()
        misconf_auditor.list_contexts(list_contexts, context, context_names)
        context = misconf_auditor.select_context(context, it, format,  context_names, active_context_name, active_context_index)

        # --- Load Kubeconfig ---
        config.load_kube_config(context=context)
    except (config.ConfigException, ValueError) as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

    # Create API client AFTER loading kubeconfig (authentication and address)
    v1 = client.CoreV1Api()

    try:
        # --- Data manipulation and sorting ---
        misconf_auditor.namespace_selector(v1, namespace)
        misconf_auditor.filter_by_severity(severity)
        misconf_auditor.sort_by_column(sort)

        # --- Print table report ---
        misconf_auditor.render_report(format)
    except ValueError as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

# --- Run only as script ---
if __name__ == "__main__":
    app()