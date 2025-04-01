import dearpygui.dearpygui as dpg
import meraki
from typing import Optional, List, Dict, Callable
import time
from datetime import datetime
import csv
import io
from enum import Enum


class RateLimiter:
    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.last_request = datetime.now()
        self.tokens = requests_per_second
        self.last_refill = datetime.now()

    def wait_if_needed(self):
        now = datetime.now()
        time_since_last = (now - self.last_refill).total_seconds()
        if time_since_last > 1:
            self.tokens = self.requests_per_second
            self.last_refill = now
        else:
            self.tokens += time_since_last * self.requests_per_second
        self.tokens = min(self.tokens, self.requests_per_second)
        if self.tokens < 1:
            sleep_time = 1 - time_since_last
            time.sleep(sleep_time)
            self.tokens = 1
        self.tokens -= 1
        self.last_request = now


class MerakiManager:
    def __init__(self):
        self.dashboard: Optional[meraki.DashboardAPI] = None
        self.organization_id: Optional[str] = None
        self.networks: List[Dict] = []
        self.baseline_rules: List[Dict] = []
        self.baseline_content_filtering: Dict = {}
        self.rate_limiter = RateLimiter()
        self.log_callback = None

    def initialize_api(self, api_key: str) -> bool:
        try:
            self.dashboard = meraki.DashboardAPI(
                api_key,
                wait_on_rate_limit=True,
                nginx_429_retry_wait_time=15,
                retry_4xx_error=True,
                retry_4xx_error_wait_time=15,
                maximum_retries=3,
                suppress_logging=False,
                output_log=False,
            )
            orgs = self.dashboard.organizations.getOrganizations()
            if not orgs:
                raise Exception("No organizations found")
            self.organization_id = orgs[0]["id"]
            return True
        except Exception as e:
            self.log(f"API initialization failed: {e}")
            return False

    def set_log_callback(self, callback):
        self.log_callback = callback

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def _execute_api_call(self, func, error_msg, *args, **kwargs):
        try:
            self.rate_limiter.wait_if_needed()
            return func(*args, **kwargs)
        except Exception as e:
            self.log(f"{error_msg}: {e}")
            return [] if isinstance([], type(kwargs.get("default", []))) else {}

    def get_configuration_changes(self, timespan: int = 3600) -> List[Dict]:
        return self._execute_api_call(
            self.dashboard.organizations.getOrganizationConfigurationChanges,
            "Error fetching configuration changes",
            self.organization_id,
            timespan=timespan,
        )

    def get_networks(self) -> List[Dict]:
        self.networks = self._execute_api_call(
            self.dashboard.organizations.getOrganizationNetworks,
            "Error fetching networks",
            self.organization_id,
            total_pages="all",
        )
        return self.networks

    def get_devices(self) -> List[Dict]:
        return self._execute_api_call(
            self.dashboard.organizations.getOrganizationDevices,
            "Error fetching devices",
            self.organization_id,
            total_pages="all",
        )

    def create_action_batch(
        self, actions: List[Dict], confirmed: bool = False, synchronous: bool = False
    ) -> Dict:
        return self._execute_api_call(
            self.dashboard.organizations.createOrganizationActionBatch,
            "Error creating action batch",
            self.organization_id,
            actions=actions,
            confirmed=confirmed,
            synchronous=synchronous,
        )

    def get_l7_rules(self, network_id: str) -> List[Dict]:
        response = self._execute_api_call(
            self.dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules,
            "Error fetching L7 rules",
            network_id,
        )
        rules = response.get("rules", [])
        self.baseline_rules = rules
        return rules

    def get_content_filtering(self, network_id: str) -> Dict:
        self.baseline_content_filtering = self._execute_api_call(
            self.dashboard.appliance.getNetworkApplianceContentFiltering,
            "Error fetching content filtering",
            network_id,
        )
        return self.baseline_content_filtering

    def deploy_l7_rules(self, target_network_id: str) -> bool:
        if not self.baseline_rules:
            return False

        try:
            self.rate_limiter.wait_if_needed()
            self.dashboard.appliance.updateNetworkApplianceFirewallL7FirewallRules(
                target_network_id, rules=self.baseline_rules
            )
            self.log(f"Successfully deployed L7 rules to network {target_network_id}")
            return True
        except Exception as e:
            self.log(f"Error deploying L7 rules to network {target_network_id}: {e}")
            return False

    def deploy_content_filtering(self, target_network_id: str) -> bool:
        if not self.baseline_content_filtering:
            return False

        try:
            blocked_categories = [
                category["id"]
                for category in self.baseline_content_filtering.get(
                    "blockedUrlCategories", []
                )
            ]

            self.rate_limiter.wait_if_needed()
            self.dashboard.appliance.updateNetworkApplianceContentFiltering(
                target_network_id,
                allowedUrlPatterns=self.baseline_content_filtering.get(
                    "allowedUrlPatterns", []
                ),
                blockedUrlPatterns=self.baseline_content_filtering.get(
                    "blockedUrlPatterns", []
                ),
                blockedUrlCategories=blocked_categories,
                urlCategoryListSize=self.baseline_content_filtering.get(
                    "urlCategoryListSize", "topSites"
                ),
            )
            self.log(
                f"Successfully deployed content filtering to network {target_network_id}"
            )
            return True
        except Exception as e:
            self.log(
                f"Error deploying content filtering to network {target_network_id}: {e}"
            )
            return False

    def get_l3_rules(self, network_id: str) -> List[Dict]:
        response = self._execute_api_call(
            self.dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules,
            "Error fetching L3 rules",
            network_id,
        )
        rules = response.get("rules", [])
        return rules

    def deploy_l3_rules(self, target_network_id: str, rules: List[Dict]) -> bool:
        if not rules:
            return False

        try:
            self.rate_limiter.wait_if_needed()
            self.dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(
                target_network_id, rules=rules
            )
            self.log(f"Successfully deployed L3 rules to network {target_network_id}")
            return True
        except Exception as e:
            self.log(f"Error deploying L3 rules to network {target_network_id}: {e}")
            return False

    def export_l3_rules_to_csv(self, network_id: str, output_file: str) -> bool:
        try:
            rules = self.get_l3_rules(network_id)

            field_names = [
                "comment",
                "policy",
                "protocol",
                "srcCidr",
                "srcPort",
                "destCidr",
                "destPort",
                "syslogEnabled",
            ]

            with open(output_file, mode="w", newline="\n") as fp:
                csv_writer = csv.DictWriter(
                    fp, field_names, delimiter=",", quotechar='"', quoting=csv.QUOTE_ALL
                )
                csv_writer.writeheader()
                for rule in rules:
                    # Ensure all fields exist in the rule
                    rule_row = {field: rule.get(field, "") for field in field_names}
                    csv_writer.writerow(rule_row)

            self.log(f"Successfully exported {len(rules)} L3 rules to {output_file}")
            return True
        except Exception as e:
            self.log(f"Error exporting L3 rules to CSV: {e}")
            return False

    def import_l3_rules_from_csv(self, input_file: str) -> List[Dict]:
        try:
            rules = []
            with open(input_file, mode="r", newline="\n") as fp:
                csv_reader = csv.DictReader(fp)
                field_names = csv_reader.fieldnames

                for row in csv_reader:
                    rule = {}
                    for field in field_names:
                        if field in row:
                            # Convert empty strings to None for optional fields
                            if row[field] == "":
                                continue

                            # Convert string "True"/"False" to boolean for syslogEnabled
                            if field == "syslogEnabled":
                                rule[field] = row[field].lower() == "true"
                            else:
                                rule[field] = row[field]
                    rules.append(rule)

            self.log(f"Successfully imported {len(rules)} L3 rules from {input_file}")
            return rules
        except Exception as e:
            self.log(f"Error importing L3 rules from CSV: {e}")
            return []

    def fetch_uplink_statuses(self) -> list:
        try:
            self.rate_limiter.wait_if_needed()
            self.log("Fetching appliance uplink statuses...")
            appliance_statuses = (
                self.dashboard.appliance.getOrganizationApplianceUplinkStatuses(
                    self.organization_id, total_pages="all"
                )
            )
            self.log("Fetching networks...")
            networks = self.dashboard.organizations.getOrganizationNetworks(
                self.organization_id, total_pages="all"
            )
            self.log("Fetching device statuses...")
            devices = self.dashboard.organizations.getOrganizationDevicesStatuses(
                self.organization_id, total_pages="all"
            )

            devices_by_serial = {d["serial"]: d["name"] for d in devices}
            networks_by_id = {n["id"]: n["name"] for n in networks}

            for status in appliance_statuses:
                status["name"] = devices_by_serial.get(status["serial"], "Unknown")
                status["network"] = networks_by_id.get(status["networkId"], "Unknown")

            self.log(
                f"Successfully fetched {len(appliance_statuses)} appliance statuses"
            )
            return appliance_statuses
        except Exception as e:
            self.log(f"Error fetching uplink statuses: {e}")
            return []

    def generate_raw_wan_ips(self, output_file=None):
        self.log("Generating raw WAN IPs list...")
        statuses = self.fetch_uplink_statuses()
        public_ips = {
            uplink["publicIp"]
            for status in statuses
            for uplink in status.get("uplinks", [])
            if uplink.get("publicIp")
        }
        sorted_ips = sorted(public_ips)
        content = "\n".join(sorted_ips)
        if output_file:
            with open(output_file, "w") as f:
                f.write(content)
            self.log(f"WAN IPs saved to {output_file} ({len(public_ips)} IPs)")
        return sorted_ips, content

    def generate_detailed_wan_info(self, output_file=None):
        self.log("Generating detailed WAN information...")
        statuses = self.fetch_uplink_statuses()

        field_names = [
            "name",
            "serial",
            "model",
            "network",
            "networkId",
            "wan1_status",
            "wan1_ip",
            "wan1_gateway",
            "wan1_publicIp",
            "wan2_status",
            "wan2_ip",
            "wan2_gateway",
            "wan2_publicIp",
        ]

        records = []
        for status in statuses:
            record = {
                "name": status.get("name", ""),
                "serial": status.get("serial", ""),
                "model": status.get("model", ""),
                "network": status.get("network", ""),
                "networkId": status.get("networkId", ""),
            }

            for uplink in status.get("uplinks", []):
                interface = uplink.get("interface")
                if interface in ["wan1", "wan2"]:
                    record.update(
                        {
                            f"{interface}_status": uplink.get("status", ""),
                            f"{interface}_ip": uplink.get("ip", ""),
                            f"{interface}_gateway": uplink.get("gateway", ""),
                            f"{interface}_publicIp": uplink.get("publicIp", ""),
                        }
                    )

            records.append(record)

        csv_buffer = io.StringIO()
        csv_writer = csv.DictWriter(
            csv_buffer, field_names, delimiter=",", quotechar='"', quoting=csv.QUOTE_ALL
        )
        csv_writer.writeheader()
        for record in records:
            csv_writer.writerow(record)

        csv_content = csv_buffer.getvalue()

        if output_file:
            with open(output_file, mode="w", newline="\n") as fp:
                fp.write(csv_content)
            self.log(
                f"Detailed WAN IPs saved to {output_file} ({len(statuses)} devices)"
            )

        return records, csv_content

    def check_network_statuses(self, check_type, get_func):
        self.log(f"Checking {check_type} status for all networks...")
        statuses = {}
        for i, network in enumerate(self.networks):
            network_id = network["id"]
            try:
                self.rate_limiter.wait_if_needed()
                response = get_func(network_id)
                statuses[network_id] = response
                if (i + 1) % 10 == 0:
                    self.log(
                        f"Checked {check_type} status for {i + 1}/{len(self.networks)} networks"
                    )
            except Exception as e:
                self.log(
                    f"Error fetching {check_type} status for network {network_id}: {e}"
                )
                statuses[network_id] = {}
        self.log(
            f"Completed {check_type} status check for {len(self.networks)} networks"
        )
        return statuses

    def check_amp_status(self) -> Dict[str, bool]:
        def get_amp(network_id):
            response = self.dashboard.appliance.getNetworkApplianceSecurityMalware(
                network_id
            )
            return response.get("mode", "disabled") == "enabled"

        return self.check_network_statuses("AMP", get_amp)

    def check_ids_ips_status(self) -> Dict[str, Dict]:
        def get_ids_ips(network_id):
            response = self.dashboard.appliance.getNetworkApplianceSecurityIntrusion(
                network_id
            )
            return {
                "mode": response.get("mode", "disabled"),
                "ruleset": response.get("idsRulesets", "none"),
            }

        return self.check_network_statuses("IDS/IPS", get_ids_ips)

    def check_port_forwarding_status(self) -> Dict[str, List[Dict]]:
        def get_port_forwarding(network_id):
            response = (
                self.dashboard.appliance.getNetworkApplianceFirewallPortForwardingRules(
                    network_id
                )
            )
            rules = response.get("rules", [])
            return [rule for rule in rules if "any" in rule.get("allowedIps", [])]

        return self.check_network_statuses("port forwarding rules", get_port_forwarding)


class ViewType(Enum):
    NONE = 0
    L7_RULES = 1
    CONTENT_FILTERING = 2
    L3_RULES = 3
    PUBLIC_IPS = 4
    IDS_IPS_STATUS = 5
    AMP_STATUS = 6
    PORT_FORWARDING = 7
    NETWORK_SELECTION = 8


class GUI:
    def __init__(self):
        self.meraki = MerakiManager()
        self.selected_baseline: Optional[str] = None
        self.selected_targets: List[str] = []
        self.network_filter: str = ""
        self.sort_ascending: bool = True
        self.l3_rules: List[Dict] = []
        self.current_view: ViewType = ViewType.NONE
        self.console_logs: List[str] = []
        self.max_console_logs = 500
        self.deploy_option: str = "l7"
        self.selection_callback: Optional[Callable] = None
        self.status_bar_tag = "status_bar"

    def add_log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.console_logs.append(log_entry)

        if len(self.console_logs) > self.max_console_logs:
            self.console_logs = self.console_logs[-self.max_console_logs :]

        if dpg.does_item_exist("console_text"):
            dpg.set_value("console_text", "\n".join(self.console_logs))
            dpg.set_y_scroll("console_window", -1.0)

        if dpg.does_item_exist(self.status_bar_tag):
            dpg.set_value(self.status_bar_tag, log_entry)

    def setup_gui(self):
        dpg.create_context()

        # authentication window
        with dpg.window(
            label="Meraki Authentication",
            tag="auth_window",
            no_resize=True,
            no_move=True,
            no_collapse=True,
            no_close=True,
        ):
            dpg.add_input_text(
                label="API Key",
                tag="api_key_input",
                password=True,
                callback=lambda s, a: self.authenticate() if a else None,
                on_enter=True,
            )
            dpg.add_button(label="Connect", callback=self.authenticate)

        # Main application window
        with dpg.window(
            label="Mirage - V0.4",
            tag="main_window",
            show=False,
            no_resize=True,
            no_move=True,
            no_collapse=True,
            no_close=True,
        ):
            with dpg.menu_bar():
                with dpg.menu(label="Menu"):
                    dpg.add_menu_item(
                        label="Refresh Networks", callback=self.refresh_networks
                    )
                    dpg.add_menu_item(
                        label="Clear Console", callback=self.clear_console
                    )
                    dpg.add_menu_item(
                        label="Exit", callback=lambda: dpg.stop_dearpygui()
                    )

            with dpg.group(horizontal=False):
                # Main content area (sidebar + content)
                with dpg.group(horizontal=True, tag="main_content_group"):
                    # Sidebar with navigation buttons
                    with dpg.child_window(
                        width=200, border=False, tag="sidebar_window"
                    ):
                        with dpg.collapsing_header(
                            label="Deployment", default_open=True
                        ):
                            dpg.add_button(
                                label="L7 Rules",
                                callback=lambda: self.change_view(ViewType.L7_RULES),
                                width=-1,
                            )
                            dpg.add_button(
                                label="Content Filtering",
                                callback=lambda: self.change_view(
                                    ViewType.CONTENT_FILTERING
                                ),
                                width=-1,
                            )
                            dpg.add_button(
                                label="L3 Rules",
                                callback=lambda: self.change_view(ViewType.L3_RULES),
                                width=-1,
                            )
                        with dpg.collapsing_header(
                            label="Assessment", default_open=True
                        ):
                            dpg.add_button(
                                label="Public IPs",
                                callback=lambda: self.change_view(ViewType.PUBLIC_IPS),
                                width=-1,
                            )
                            dpg.add_button(
                                label="IDS/IPS Status",
                                callback=lambda: self.change_view(
                                    ViewType.IDS_IPS_STATUS
                                ),
                                width=-1,
                            )
                            dpg.add_button(
                                label="AMP Status",
                                callback=lambda: self.change_view(ViewType.AMP_STATUS),
                                width=-1,
                            )
                            dpg.add_button(
                                label="Port Forwarding Check",
                                callback=lambda: self.change_view(
                                    ViewType.PORT_FORWARDING
                                ),
                                width=-1,
                            )

                    # Main content window
                    with dpg.child_window(tag="content_window", border=False):
                        pass

                # console and status bar
                with dpg.collapsing_header(
                    label="Console", default_open=True, tag="console_header"
                ):
                    with dpg.child_window(
                        tag="console_window", height=150, horizontal_scrollbar=True
                    ):
                        dpg.add_text("", tag="console_text", wrap=0)

                dpg.add_text("Ready", tag=self.status_bar_tag)

    def clear_console(self):
        self.console_logs = []
        if dpg.does_item_exist("console_text"):
            dpg.set_value("console_text", "")

    def change_view(self, view_type: ViewType, extra_data=None):
        self.current_view = view_type
        dpg.delete_item("content_window", children_only=True)

        if view_type == ViewType.L7_RULES:
            self.deploy_option = "l7"
            if not self.selected_baseline:
                self.show_network_selection(
                    "Select Baseline Network", False, self.handle_l7_baseline_selection
                )
            else:
                self.show_l7_deployment_interface()

        elif view_type == ViewType.CONTENT_FILTERING:
            self.deploy_option = "content_filtering"
            if not self.selected_baseline:
                self.show_network_selection(
                    "Select Baseline Network for Content Filtering",
                    False,
                    self.handle_content_filtering_baseline_selection,
                )
            else:
                self.show_content_filtering_interface()

        elif view_type == ViewType.L3_RULES:
            self.deploy_option = "l3"
            self.show_l3_rules()

        elif view_type == ViewType.PUBLIC_IPS:
            self.show_public_ips_content()

        elif view_type == ViewType.IDS_IPS_STATUS:
            self.show_ids_ips_status()

        elif view_type == ViewType.AMP_STATUS:
            self.show_amp_status()

        elif view_type == ViewType.PORT_FORWARDING:
            self.show_port_forwarding_check()

        elif view_type == ViewType.NETWORK_SELECTION:
            if isinstance(extra_data, dict):
                self.show_network_selection(
                    extra_data.get("title", "Select Networks"),
                    extra_data.get("multi_select", False),
                    extra_data.get("callback", None),
                )

    def show_network_selection(
        self, title: str, multi_select: bool = False, callback: Callable = None
    ):
        self.selection_callback = callback

        with dpg.group(parent="content_window"):
            with dpg.group(horizontal=True):
                dpg.add_text(title, color=(255, 255, 0))
                dpg.add_input_text(
                    label="Search",
                    tag="network_filter",
                    callback=lambda s, a: self.handle_filter_input(a),
                    on_enter=True,
                    default_value=self.network_filter,
                    width=200,
                )
                dpg.add_button(
                    label="Sort (A-Z)" if self.sort_ascending else "Sort (Z-A)",
                    callback=self.toggle_sort,
                )

            if multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Select All", callback=self.select_all_networks
                    )
                    dpg.add_button(
                        label="Clear Selection", callback=self.clear_selection
                    )

            self.create_network_table(multi_select)

            if multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_text(
                        f"Selected: {len(self.selected_targets)}",
                        tag="selected_count_text",
                    )
                    dpg.add_button(
                        label="Done",
                        callback=lambda: self.selection_callback()
                        if self.selection_callback
                        else None,
                        width=100,
                    )

    def create_network_table(self, multi_select: bool):
        dpg.add_table(
            header_row=True,
            borders_innerH=True,
            borders_outerH=True,
            tag="networks_table",
        )

        dpg.add_table_column(label="Network Name", width=400, parent="networks_table")
        dpg.add_table_column(label="Select", width=100, parent="networks_table")

        filtered_networks = self.filter_and_sort_networks()

        if not filtered_networks:
            with dpg.table_row(parent="networks_table"):
                dpg.add_text("No networks found")
                dpg.add_text("")
        else:
            for network in filtered_networks:
                with dpg.table_row(parent="networks_table"):
                    dpg.add_text(network["name"])
                    if multi_select:
                        checkbox_tag = f"checkbox_{network['id']}"
                        dpg.add_checkbox(
                            tag=checkbox_tag,
                            default_value=network["id"] in self.selected_targets,
                            callback=lambda s, a, u: self.toggle_target_selection(u),
                            user_data=network["id"],
                        )
                    else:
                        dpg.add_button(
                            label="Select",
                            callback=lambda s, a, u: self.select_baseline(u),
                            user_data={"id": network["id"], "name": network["name"]},
                        )

    def handle_filter_input(self, app_data: str):
        self.network_filter = app_data
        multi_select = False
        if self.selection_callback is not None:
            if self.selection_callback.__name__ in [
                "handle_l7_baseline_selection",
                "handle_content_filtering_baseline_selection",
                "handle_l3_network_selection",
            ]:
                multi_select = False
            else:
                multi_select = True
        self.update_network_table(multi_select)

    def update_network_table(self, multi_select: bool):
        # Remove all rows
        if dpg.does_item_exist("networks_table"):
            children = dpg.get_item_children("networks_table", slot=1)
            if children:
                for child in children:
                    dpg.delete_item(child)

            # Add new rows based on filtered networks
            filtered_networks = self.filter_and_sort_networks()

            if not filtered_networks:
                with dpg.table_row(parent="networks_table"):
                    dpg.add_text("No networks found")
                    dpg.add_text("")
            else:
                for network in filtered_networks:
                    with dpg.table_row(parent="networks_table"):
                        dpg.add_text(network["name"])
                        if multi_select:
                            checkbox_tag = f"checkbox_{network['id']}"
                            dpg.add_checkbox(
                                tag=checkbox_tag,
                                default_value=network["id"] in self.selected_targets,
                                callback=lambda s, a, u: self.toggle_target_selection(
                                    u
                                ),
                                user_data=network["id"],
                            )
                        else:
                            dpg.add_button(
                                label="Select",
                                callback=lambda s, a, u: self.select_baseline(u),
                                user_data={
                                    "id": network["id"],
                                    "name": network["name"],
                                },
                            )

        if dpg.does_item_exist("selected_count_text"):
            dpg.set_value(
                "selected_count_text", f"Selected: {len(self.selected_targets)}"
            )

    def filter_and_sort_networks(self) -> List[Dict]:
        networks = self.meraki.networks
        if self.network_filter:
            networks = [
                n for n in networks if self.network_filter.lower() in n["name"].lower()
            ]
        return sorted(
            networks, key=lambda x: x["name"], reverse=not self.sort_ascending
        )

    def toggle_sort(self):
        self.sort_ascending = not self.sort_ascending
        self.update_network_table(self.selection_callback is not None)

    def select_baseline(self, network_data: Dict):
        self.selected_baseline = network_data["id"]
        self.add_log(f"Selected baseline network: {network_data['name']}")

        if self.deploy_option == "content_filtering":
            self.show_content_filtering_interface()
        elif self.deploy_option == "l3":
            self.show_l3_rules()
        else:
            self.show_l7_deployment_interface()

    def toggle_target_selection(self, network_id: str):
        if network_id in self.selected_targets:
            self.selected_targets.remove(network_id)
        else:
            self.selected_targets.append(network_id)

        if dpg.does_item_exist("selected_count_text"):
            dpg.set_value(
                "selected_count_text", f"Selected: {len(self.selected_targets)}"
            )

    def select_all_networks(self):
        self.selected_targets = [n["id"] for n in self.filter_and_sort_networks()]
        self.update_network_table(True)

    def clear_selection(self):
        self.selected_targets = []
        self.update_network_table(True)

    def get_network_name(self, network_id: str) -> str:
        for network in self.meraki.networks:
            if network["id"] == network_id:
                return network["name"]
        return "Unknown Network"

    def show_deployment_status(self, success_count: int, total: int, deploy_type: str):
        result_message = (
            f"{deploy_type} deployment complete: {success_count}/{total} successful"
        )
        self.add_log(result_message)

    def deploy_config(self):
        if not self.selected_targets:
            self.add_log("⚠️ Deployment failed: No target networks selected")
            return

        deploy_type = self.deploy_option

        if deploy_type == "content_filtering":
            deploy_function = self.meraki.deploy_content_filtering
        elif deploy_type == "l3":
            if not self.l3_rules:
                self.add_log("⚠️ Deployment failed: No L3 rules to deploy")
                return
            deploy_function = lambda target_id: self.meraki.deploy_l3_rules(
                target_id, self.l3_rules
            )
        else:  # l7
            deploy_function = self.meraki.deploy_l7_rules

        self.add_log(
            f"Starting {deploy_type} deployment to {len(self.selected_targets)} networks"
        )
        success_count = 0
        total = len(self.selected_targets)

        for idx, target_id in enumerate(self.selected_targets, 1):
            network_name = self.get_network_name(target_id)
            self.add_log(f"Deploying to {network_name} ({idx}/{total})")

            if deploy_function(target_id):
                success_count += 1

        self.show_deployment_status(success_count, total, deploy_type)

    def authenticate(self):
        api_key = dpg.get_value("api_key_input")
        self.add_log("Authenticating...")

        self.meraki.set_log_callback(self.add_log)

        if self.meraki.initialize_api(api_key):
            dpg.hide_item("auth_window")
            dpg.show_item("main_window")
            self.add_log("Authentication successful, loading networks...")
            self.meraki.get_networks()
            self.add_log(f"Loaded {len(self.meraki.networks)} networks")
        else:
            self.add_log(
                "⚠️ Authentication failed! Please check your API key and try again."
            )

    def refresh_networks(self):
        self.add_log("Refreshing networks...")
        networks = self.meraki.get_networks()
        if networks:
            self.add_log(
                f"Networks refreshed successfully. Found {len(networks)} networks."
            )

            # Refresh current view
            self.change_view(self.current_view)
        else:
            self.add_log("⚠️ Failed to refresh networks")

    def show_l7_deployment_interface(self):
        if not self.selected_baseline:
            self.add_log("⚠️ No baseline network selected")
            self.show_network_selection(
                "Select Baseline Network", False, self.handle_l7_baseline_selection
            )
            return

        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.get_network_name(self.selected_baseline))

            dpg.add_text("Current L7 Rules:", color=(255, 255, 0))

            rules = self.meraki.get_l7_rules(self.selected_baseline)

            if rules:
                with dpg.table(
                    header_row=True, borders_innerH=True, borders_outerH=True
                ):
                    dpg.add_table_column(label="Policy", width=100)
                    dpg.add_table_column(label="Type", width=100)
                    dpg.add_table_column(label="Value", width=200)

                    for rule in rules:
                        with dpg.table_row():
                            policy_color = (
                                (255, 100, 100)
                                if rule["policy"] == "deny"
                                else (100, 255, 100)
                            )
                            dpg.add_text(rule["policy"], color=policy_color)
                            dpg.add_text(rule["type"])
                            dpg.add_text(rule["value"])
            else:
                dpg.add_text("No rules configured", color=(255, 255, 0))

            self.add_deployment_buttons()

    def handle_l7_baseline_selection(self):
        self.show_l7_deployment_interface()

    def handle_content_filtering_baseline_selection(self):
        self.show_content_filtering_interface()

    def handle_l3_network_selection(self):
        if self.selected_baseline:
            self.l3_rules = self.meraki.get_l3_rules(self.selected_baseline)
            self.show_l3_rules()

    def add_deployment_buttons(self):
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="Change Baseline", callback=self.reset_baseline, width=150
            )
            dpg.add_button(
                label="Select Targets",
                callback=self.select_deployment_targets,
                width=150,
            )

        if self.selected_targets:
            with dpg.group(horizontal=True):
                dpg.add_text(f"Selected Targets: {len(self.selected_targets)}")
                dpg.add_button(
                    label="Deploy Config", callback=self.deploy_config, width=150
                )

    def reset_baseline(self):
        self.selected_baseline = None
        if self.deploy_option == "content_filtering":
            self.change_view(ViewType.CONTENT_FILTERING)
        elif self.deploy_option == "l3":
            self.change_view(ViewType.L3_RULES)
        else:
            self.change_view(ViewType.L7_RULES)

    def select_deployment_targets(self):
        callback = None
        if self.deploy_option == "content_filtering":
            callback = lambda: self.change_view(ViewType.CONTENT_FILTERING)
        elif self.deploy_option == "l3":
            callback = lambda: self.change_view(ViewType.L3_RULES)
        else:
            callback = lambda: self.change_view(ViewType.L7_RULES)

        self.show_network_selection("Select Target Networks", True, callback)

    def show_content_filtering_interface(self):
        if not self.selected_baseline:
            self.add_log("⚠️ No baseline network selected for content filtering")
            self.show_network_selection(
                "Select Baseline Network for Content Filtering",
                False,
                self.handle_content_filtering_baseline_selection,
            )
            return

        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.get_network_name(self.selected_baseline))

            dpg.add_text(
                "Current Content Filtering Configuration:", color=(255, 255, 0)
            )

            content_filtering = self.meraki.get_content_filtering(
                self.selected_baseline
            )

            if content_filtering:
                dpg.add_text("Allowed URL Patterns:", color=(100, 255, 100))
                if content_filtering.get("allowedUrlPatterns", []):
                    for url in content_filtering.get("allowedUrlPatterns", []):
                        dpg.add_text(url, indent=20)
                else:
                    dpg.add_text("No allowed URL patterns configured", indent=20)

                dpg.add_text("Blocked URL Patterns:", color=(255, 100, 100))
                if content_filtering.get("blockedUrlPatterns", []):
                    for url in content_filtering.get("blockedUrlPatterns", []):
                        dpg.add_text(url, indent=20)
                else:
                    dpg.add_text("No blocked URL patterns configured", indent=20)

                dpg.add_text("Blocked URL Categories:", color=(255, 100, 100))
                if content_filtering.get("blockedUrlCategories", []):
                    for category in content_filtering.get("blockedUrlCategories", []):
                        dpg.add_text(
                            f"{category.get('name', 'Unknown')} ({category.get('id', 'Unknown')})",
                            indent=20,
                        )
                else:
                    dpg.add_text("No blocked URL categories configured", indent=20)

                dpg.add_text(
                    f"URL Category List Size: {content_filtering.get('urlCategoryListSize', 'Unknown')}"
                )
            else:
                dpg.add_text(
                    "No content filtering configuration found", color=(255, 255, 0)
                )

            self.add_deployment_buttons()

    def show_l3_rules(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("L3 Firewall Rules", color=(255, 255, 0))

            with dpg.group(horizontal=True):
                if not self.selected_baseline:
                    dpg.add_button(
                        label="Select Network",
                        callback=lambda: self.show_network_selection(
                            "Select Network for L3 Rules",
                            False,
                            self.handle_l3_network_selection,
                        ),
                        width=150,
                    )
                else:
                    network_name = self.get_network_name(self.selected_baseline)
                    dpg.add_text(f"Selected Network: {network_name}")

                    dpg.add_button(
                        label="Extract to CSV",
                        callback=self.export_l3_rules,
                        width=150,
                    )

            if self.selected_baseline or self.l3_rules:
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Import from CSV",
                        callback=self.import_l3_rules,
                        width=150,
                    )

                    if self.l3_rules:
                        dpg.add_button(
                            label="Select Targets for Deployment",
                            callback=self.select_l3_deployment_targets,
                            width=200,
                        )

            if self.l3_rules:
                if hasattr(self, "rules_imported") and self.rules_imported:
                    dpg.add_text("Imported L3 Firewall Rules:", color=(255, 255, 0))
                else:
                    dpg.add_text("Current L3 Firewall Rules:", color=(255, 255, 0))

                self.display_l3_rules_table()

                # show deployment info if targets selected
                if self.selected_targets:
                    with dpg.group(horizontal=True):
                        dpg.add_text(f"Selected Targets: {len(self.selected_targets)}")
                        dpg.add_button(
                            label="Deploy L3 Rules",
                            callback=self.deploy_config,
                            width=150,
                        )
            elif self.selected_baseline:
                # display current network rules if we have a baseline but no imported rules
                self.display_l3_rules(self.selected_baseline)

    def display_l3_rules(self, network_id):
        rules = self.meraki.get_l3_rules(network_id)
        self.l3_rules = rules
        self.rules_imported = False

        if not rules:
            dpg.add_text("No L3 rules found", color=(255, 255, 0))
            return

        self.display_l3_rules_table()

    def display_l3_rules_table(self):
        if not self.l3_rules:
            dpg.add_text("No L3 rules found", color=(255, 255, 0))
            return

        with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True):
            dpg.add_table_column(label="Comment", width=150)
            dpg.add_table_column(label="Policy", width=80)
            dpg.add_table_column(label="Protocol", width=80)
            dpg.add_table_column(label="Source CIDR", width=120)
            dpg.add_table_column(label="Source Port", width=100)
            dpg.add_table_column(label="Dest CIDR", width=120)
            dpg.add_table_column(label="Dest Port", width=100)
            dpg.add_table_column(label="Syslog", width=60)

            for rule in self.l3_rules:
                with dpg.table_row():
                    dpg.add_text(rule.get("comment", ""))
                    policy = rule.get("policy", "")
                    policy_color = (
                        (100, 255, 100) if policy == "allow" else (255, 100, 100)
                    )
                    dpg.add_text(policy, color=policy_color)
                    dpg.add_text(rule.get("protocol", ""))
                    dpg.add_text(rule.get("srcCidr", ""))
                    dpg.add_text(rule.get("srcPort", ""))
                    dpg.add_text(rule.get("destCidr", ""))
                    dpg.add_text(rule.get("destPort", ""))
                    dpg.add_text("Yes" if rule.get("syslogEnabled", False) else "No")

    def export_l3_rules(self):
        if not self.selected_baseline:
            self.add_log("⚠️ No network selected for exporting L3 rules")
            return

        network_name = self.get_network_name(self.selected_baseline)

        with dpg.file_dialog(
            label="Save L3 Rules as CSV",
            width=600,
            height=400,
            callback=lambda s, a: self.save_l3_rules_to_csv(a),
            show=True,
            default_path=".",
            default_filename=f"{network_name}_l3_rules.csv",
            file_count=0,
            tag="save_l3_rules_dialog",
            directory_selector=False,
        ):
            dpg.add_file_extension(".csv", color=(0, 255, 0, 255))

    def save_l3_rules_to_csv(self, app_data):
        if app_data["file_path_name"]:
            file_path = app_data["file_path_name"]
            self.add_log(f"Exporting L3 rules to {file_path}...")
            success = self.meraki.export_l3_rules_to_csv(
                self.selected_baseline, file_path
            )
            if success:
                self.add_log(f"L3 rules successfully exported to {file_path}")
            else:
                self.add_log("⚠️ Failed to export L3 rules")
        else:
            self.add_log("L3 rules export cancelled")

    def import_l3_rules(self):
        with dpg.file_dialog(
            label="Import L3 Rules from CSV",
            width=600,
            height=400,
            callback=lambda s, a: self.load_l3_rules_from_csv(a),
            show=True,
            default_path=".",
            file_count=0,
            tag="import_l3_rules_dialog",
            directory_selector=False,
        ):
            dpg.add_file_extension(".csv", color=(0, 255, 0, 255))

    def load_l3_rules_from_csv(self, app_data):
        if not app_data["file_path_name"]:
            self.add_log("L3 rules import cancelled")
            return

        file_path = app_data["file_path_name"]
        self.add_log(f"Importing L3 rules from {file_path}...")
        imported_rules = self.meraki.import_l3_rules_from_csv(file_path)

        if imported_rules:
            self.rules_imported = True

            # clear the baseline - we now using imported rules instead
            # imported rules take precedence
            self.l3_rules = imported_rules

            self.add_log(f"Successfully imported {len(self.l3_rules)} L3 rules")
            # refresh the display
            self.show_l3_rules()
        else:
            self.add_log("⚠️ Failed to import L3 rules")

    def select_l3_deployment_targets(self):
        if not self.l3_rules:
            self.add_log("⚠️ No L3 rules to deploy")
            return

        # use lambda that doesn't interfere with baseline selection
        self.show_network_selection(
            "Select Target Networks for L3 Rules Deployment",
            True,
            lambda: self.change_view(ViewType.L3_RULES),
        )

    def show_public_ips_content(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("Public IPs", color=(255, 255, 0))

            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Extract Raw WAN IPs",
                    callback=self.extract_raw_wan_ips,
                    width=200,
                )
                dpg.add_button(
                    label="Extract Detailed WAN Info",
                    callback=self.extract_detailed_wan_info,
                    width=200,
                )

    def extract_raw_wan_ips(self):
        self.add_log("Starting extraction of raw WAN IPs...")
        ips, content = self.meraki.generate_raw_wan_ips()

        if not ips:
            self.add_log("⚠️ No WAN IPs found!")
            return

        with dpg.file_dialog(
            label="Save WAN IPs",
            width=600,
            height=400,
            callback=lambda s, a: self.save_raw_wan_ips(a, content),
            show=True,
            default_path=".",
            default_filename="wan_ips.txt",
            file_count=0,
            tag="save_raw_ips_dialog",
            directory_selector=False,
        ):
            dpg.add_file_extension(".txt", color=(0, 255, 0, 255))

    def save_raw_wan_ips(self, app_data, content):
        if app_data["file_path_name"]:
            file_path = app_data["file_path_name"]
            with open(file_path, "w") as f:
                f.write(content)
            self.add_log(f"Raw WAN IPs saved to {file_path}")
        else:
            self.add_log("Raw WAN IPs save cancelled")

    def extract_detailed_wan_info(self):
        self.add_log("Starting extraction of detailed WAN information...")
        records, csv_content = self.meraki.generate_detailed_wan_info()

        if not records:
            self.add_log("⚠️ No WAN information found!")
            return

        with dpg.file_dialog(
            label="Save Detailed WAN Info",
            width=600,
            height=400,
            callback=lambda s, a: self.save_detailed_wan_info(a, csv_content),
            show=True,
            default_path=".",
            default_filename="wan_ips_detailed.csv",
            file_count=0,
            tag="save_detailed_wan_dialog",
            directory_selector=False,
        ):
            dpg.add_file_extension(".csv", color=(0, 255, 0, 255))

    def save_detailed_wan_info(self, app_data, content):
        if app_data["file_path_name"]:
            file_path = app_data["file_path_name"]
            with open(file_path, "w", newline="\n") as f:
                f.write(content)
            self.add_log(f"Detailed WAN information saved to {file_path}")
        else:
            self.add_log("Detailed WAN information save cancelled")

    def show_amp_status(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("AMP Status", color=(255, 255, 0))
            self.add_log("Checking AMP status for all networks...")

            amp_statuses = self.meraki.check_amp_status()

            if not amp_statuses:
                dpg.add_text("No AMP statuses found", color=(255, 255, 0))
            else:
                with dpg.table(header_row=True, borders_innerH=True):
                    dpg.add_table_column(label="Network Name", width=400)
                    dpg.add_table_column(label="AMP Enabled", width=100)

                    for network in self.meraki.networks:
                        network_id = network["id"]
                        amp_enabled = amp_statuses.get(network_id, False)
                        with dpg.table_row():
                            dpg.add_text(network["name"])
                            dpg.add_text(
                                "Yes" if amp_enabled else "No",
                                color=(100, 255, 100)
                                if amp_enabled
                                else (255, 100, 100),
                            )

    def show_ids_ips_status(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("IDS/IPS Status", color=(255, 255, 0))
            self.add_log("Checking IDS/IPS status for all networks...")

            ids_ips_statuses = self.meraki.check_ids_ips_status()

            if not ids_ips_statuses:
                dpg.add_text("No IDS/IPS statuses found", color=(255, 255, 0))
            else:
                with dpg.table(header_row=True, borders_innerH=True):
                    dpg.add_table_column(label="Network Name", width=400)
                    dpg.add_table_column(label="Mode", width=100)
                    dpg.add_table_column(label="Ruleset", width=100)

                    for network in self.meraki.networks:
                        network_id = network["id"]
                        status = ids_ips_statuses.get(
                            network_id, {"mode": "error", "ruleset": "error"}
                        )
                        with dpg.table_row():
                            dpg.add_text(network["name"])
                            mode_color = (
                                (100, 255, 100)
                                if status["mode"] == "prevention"
                                else (
                                    (255, 255, 0)
                                    if status["mode"] == "detection"
                                    else (255, 100, 100)
                                )
                            )
                            dpg.add_text(status["mode"], color=mode_color)
                            dpg.add_text(status["ruleset"])

    def show_port_forwarding_check(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("Port Forwarding Check", color=(255, 255, 0))
            self.add_log("Checking port forwarding rules for all networks...")

            insecure_rules = self.meraki.check_port_forwarding_status()

            networks_with_issues = sum(1 for rules in insecure_rules.values() if rules)
            total_networks = len(self.meraki.networks)

            dpg.add_text(
                f"Networks with insecure rules: {networks_with_issues}/{total_networks}",
                color=(255, 100, 100) if networks_with_issues > 0 else (100, 255, 100),
            )

            if not any(insecure_rules.values()):
                dpg.add_text(
                    "No insecure port forwarding rules found", color=(100, 255, 100)
                )
            else:
                with dpg.table(header_row=True, borders_innerH=True):
                    dpg.add_table_column(label="Network Name", width=400)
                    dpg.add_table_column(label="Insecure Rules", width=400)

                    for network in self.meraki.networks:
                        network_id = network["id"]
                        rules = insecure_rules.get(network_id, [])
                        if rules:
                            with dpg.table_row():
                                dpg.add_text(network["name"])

                                # Format rules for better readability
                                rules_text = ""
                                for i, rule in enumerate(rules):
                                    rule_desc = f"{rule.get('name', 'Unnamed')} - "
                                    rule_desc += f"{rule.get('protocol', '?')} {rule.get('publicPort', '?')}"
                                    rule_desc += f" -> {rule.get('localIp', '?')}:{rule.get('localPort', '?')}"
                                    rules_text += rule_desc + "\n"

                                dpg.add_text(rules_text, wrap=400)

    def run(self):
        viewport_width = 1024
        viewport_height = 768

        dpg.create_viewport(
            title="Mirage v0.4", width=viewport_width, height=viewport_height
        )
        dpg.set_viewport_resize_callback(self.resize_windows)
        self.resize_windows(None, [viewport_width, viewport_height])

        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()

    def resize_windows(self, sender, app_data):
        viewport_width = dpg.get_viewport_width()
        viewport_height = dpg.get_viewport_height()

        # Resize auth window
        auth_width = 400
        auth_height = 150
        dpg.configure_item(
            "auth_window",
            width=auth_width,
            height=auth_height,
            pos=[
                (viewport_width - auth_width) // 2,
                (viewport_height - auth_height) // 2,
            ],
        )

        # Resize main window
        dpg.configure_item(
            "main_window", width=viewport_width, height=viewport_height, pos=[0, 0]
        )

        # Set content heights
        console_height = 150
        main_content_height = (
            viewport_height - console_height - 80
        )  # Allow for status bar

        if dpg.does_item_exist("main_content_group"):
            dpg.configure_item("main_content_group", height=main_content_height)

        if dpg.does_item_exist("sidebar_window"):
            dpg.configure_item("sidebar_window", height=main_content_height)

        content_width = viewport_width - 200
        if dpg.does_item_exist("content_window"):
            dpg.configure_item(
                "content_window", width=content_width, height=main_content_height
            )

        if dpg.does_item_exist("console_window"):
            dpg.configure_item(
                "console_window", width=viewport_width - 20, height=console_height
            )


def main():
    gui = GUI()
    gui.setup_gui()
    gui.run()


if __name__ == "__main__":
    main()
