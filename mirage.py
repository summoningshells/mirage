import dearpygui.dearpygui as dpg
import meraki
from typing import Optional, List, Dict
import time
from datetime import datetime
import csv

class RateLimiter:
    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.last_request = datetime.now()
        self.tokens = requests_per_second
        self.last_refill = datetime.now()

# rate limit handler for meraki api requests, refer to the official docs for excat rates based on the operations u want to make
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
        self.last_request = datetime.now()

# The "Brains of the tool" , it handles all requests, conversion, etc
class MerakiManager:
    def __init__(self):
        self.dashboard: Optional[meraki.DashboardAPI] = None
        self.organization_id: Optional[str] = None
        self.networks: List[Dict] = []
        self.baseline_rules: List[Dict] = []
        self.rate_limiter = RateLimiter()
        self.log_callback = None  # callback function to send logs to GUI

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
                output_log=False,      # enable to generate a .log file for all api resuests of each session
            )
            # get first organization (single org use case only sorry)
            orgs = self.dashboard.organizations.getOrganizations()
            if not orgs:
                raise Exception("No organizations found D:")
            self.organization_id = orgs[0]["id"]
            return True
        except Exception as e:
            self.log(f"API initialization failed: {e}")
            return False

    def set_log_callback(self, callback):
        """Set callback function to handle logs in GUI"""
        self.log_callback = callback

    def log(self, message):
        """Log msg to GUI console"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)  # Fallback if GUI not initialized

    def log_api_call(
        self, method: str, endpoint: str, status_code: int, response_time: float
    ):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "response_time": response_time,
        }
        # Log to GUI console
        self.log(f"API Call: {method} {endpoint} - Status: {status_code} - Time: {response_time:.2f}s")

    def get_configuration_changes(self, timespan: int = 3600) -> List[Dict]:
        try:
            self.rate_limiter.wait_if_needed()
            changes = self.dashboard.organizations.getOrganizationConfigurationChanges(
                self.organization_id, timespan=timespan
            )
            return changes
        except Exception as e:
            self.log(f"Error fetching configuration changes: {e}")
            return []

    def get_networks(self) -> List[Dict]:
        try:
            self.rate_limiter.wait_if_needed()
            self.networks = self.dashboard.organizations.getOrganizationNetworks(
                self.organization_id, total_pages="all"
            )
            return self.networks
        except Exception as e:
            self.log(f"Error fetching networks: {e}")
            return []

    def get_devices(self) -> List[Dict]:
        try:
            self.rate_limiter.wait_if_needed()
            devices = self.dashboard.organizations.getOrganizationDevices(
                self.organization_id, total_pages="all"
            )
            return devices
        except Exception as e:
            self.log(f"Error fetching devices: {e}")
            return []

    def create_action_batch(
        self, actions: List[Dict], confirmed: bool = False, synchronous: bool = False
    ) -> Dict:
        try:
            self.rate_limiter.wait_if_needed()
            response = self.dashboard.organizations.createOrganizationActionBatch(
                self.organization_id,
                actions=actions,
                confirmed=confirmed,
                synchronous=synchronous,
            )
            return response
        except Exception as e:
            self.log(f"Error creating action batch: {e}")
            return {}

    def get_l7_rules(self, network_id: str) -> List[Dict]:
        try:
            self.rate_limiter.wait_if_needed()
            response = (
                self.dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules(
                    network_id
                )
            )
            rules = response.get("rules", [])
            self.baseline_rules = rules
            return rules
        except Exception as e:
            self.log(f"Error fetching L7 rules: {e}")
            return []

    def deploy_l7_rules(self, target_network_id: str) -> bool:
        try:
            if not self.baseline_rules:
                return False

            self.rate_limiter.wait_if_needed()
            self.dashboard.appliance.updateNetworkApplianceFirewallL7FirewallRules(
                target_network_id, rules=self.baseline_rules
            )
            self.log(f"Successfully deployed L7 rules to network {target_network_id}")
            return True
        except Exception as e:
            self.log(f"Error deploying L7 rules to network {target_network_id}: {e}")
            return False

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

            # map networks and devices for ez reference
            devices_by_serial = {d["serial"]: d["name"] for d in devices}
            networks_by_id = {n["id"]: n["name"] for n in networks}

            # enrich with device and network names
            for status in appliance_statuses:
                status["name"] = devices_by_serial.get(status["serial"], "Unknown")
                status["network"] = networks_by_id.get(status["networkId"], "Unknown")

            self.log(f"Successfully fetched {len(appliance_statuses)} appliance statuses")
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
        else:
            self.log(f"Generated WAN IPs list with {len(public_ips)} IPs")
            
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
                "name": status.get("name"),
                "serial": status.get("serial"),
                "model": status.get("model"),
                "network": status.get("network"),
                "networkId": status.get("networkId"),
            }

            # WAN1 and WAN2 data
            for uplink in status.get("uplinks", []):
                if uplink.get("interface") == "wan1":
                    record.update(
                        {
                            "wan1_status": uplink.get("status"),
                            "wan1_ip": uplink.get("ip"),
                            "wan1_gateway": uplink.get("gateway"),
                            "wan1_publicIp": uplink.get("publicIp"),
                        }
                    )
                elif uplink.get("interface") == "wan2":
                    record.update(
                        {
                            "wan2_status": uplink.get("status"),
                            "wan2_ip": uplink.get("ip"),
                            "wan2_gateway": uplink.get("gateway"),
                            "wan2_publicIp": uplink.get("publicIp"),
                        }
                    )
            
            records.append(record)
        
        # Generate CSV content as string
        import io
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
            self.log(f"Detailed WAN IPs saved to {output_file} ({len(statuses)} devices)")
        else:
            self.log(f"Generated detailed WAN information for {len(statuses)} devices")
            
        return records, csv_content

    def check_amp_status(self) -> Dict[str, bool]:
        self.log("Checking AMP status for all networks...")
        amp_statuses = {}
        for i, network in enumerate(self.networks):
            network_id = network["id"]
            try:
                self.rate_limiter.wait_if_needed()
                response = self.dashboard.appliance.getNetworkApplianceSecurityMalware(
                    network_id
                )
                amp_statuses[network_id] = response.get("mode", "disabled") == "enabled"
                if (i+1) % 10 == 0:
                    self.log(f"Checked AMP status for {i+1}/{len(self.networks)} networks")
            except Exception as e:
                self.log(f"Error fetching AMP status for network {network_id}: {e}")
                amp_statuses[network_id] = False
        self.log(f"Completed AMP status check for {len(self.networks)} networks")
        return amp_statuses

    def check_ids_ips_status(self) -> Dict[str, Dict]:
        self.log("Checking IDS/IPS status for all networks...")
        ids_ips_statuses = {}
        for i, network in enumerate(self.networks):
            network_id = network["id"]
            try:
                self.rate_limiter.wait_if_needed()
                response = (
                    self.dashboard.appliance.getNetworkApplianceSecurityIntrusion(
                        network_id
                    )
                )
                ids_ips_statuses[network_id] = {
                    "mode": response.get("mode", "disabled"),
                    "ruleset": response.get("idsRulesets", "none"),
                }
                if (i+1) % 10 == 0:
                    self.log(f"Checked IDS/IPS status for {i+1}/{len(self.networks)} networks")
            except Exception as e:
                self.log(f"Error fetching IDS/IPS status for network {network_id}: {e}")
                ids_ips_statuses[network_id] = {"mode": "error", "ruleset": "error"}
        self.log(f"Completed IDS/IPS status check for {len(self.networks)} networks")
        return ids_ips_statuses

    def check_port_forwarding_status(self) -> Dict[str, List[Dict]]:
        self.log("Checking port forwarding rules for all networks...")
        insecure_rules = {}
        for i, network in enumerate(self.networks):
            network_id = network["id"]
            try:
                self.rate_limiter.wait_if_needed()
                response = self.dashboard.appliance.getNetworkApplianceFirewallPortForwardingRules(
                    network_id
                )
                rules = response.get("rules", [])
                insecure_rules[network_id] = [
                    rule for rule in rules if "any" in rule.get("allowedIps", [])
                ]
                if (i+1) % 10 == 0:
                    self.log(f"Checked port forwarding rules for {i+1}/{len(self.networks)} networks")
            except Exception as e:
                self.log(
                    f"Error fetching port forwarding rules for network {network_id}: {e}"
                )
                insecure_rules[network_id] = []
        self.log(f"Completed port forwarding check for {len(self.networks)} networks")
        return insecure_rules

    def parse_l3_rules_csv(self, file_path: str) -> List[Dict]:
        self.log(f"Parsing L3 rules from CSV file: {file_path}")
        rules = []
        try:
            with open(file_path, mode="r") as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    rules.append(
                        {
                            "comment": row.get("comment", ""),
                            "policy": row.get("policy", "allow"),
                            "protocol": row.get("protocol", "tcp"),
                            "destPort": row.get("destPort", "Any"),
                            "destCidr": row.get("destCidr", "Any"),
                            "srcPort": row.get("srcPort", "Any"),
                            "srcCidr": row.get("srcCidr", "Any"),
                        }
                    )
            self.log(f"Successfully parsed {len(rules)} L3 rules from CSV")
            return rules
        except Exception as e:
            self.log(f"Error parsing L3 rules CSV: {e}")
            return []

    def deploy_l3_rules(self, target_network_id: str, rules: List[Dict]) -> bool:
        try:
            self.log(f"Deploying {len(rules)} L3 rules to network {target_network_id}")
            self.rate_limiter.wait_if_needed()
            self.dashboard.appliance.updateNetworkApplianceFirewallCellularFirewallRules(
                target_network_id, rules=rules
            )
            self.log(f"Successfully deployed L3 rules to network {target_network_id}")
            return True
        except Exception as e:
            self.log(f"Error deploying L3 rules to network {target_network_id}: {e}")
            return False


class GUI:
    def __init__(self):
        self.meraki = MerakiManager()
        self.selected_baseline: Optional[str] = None
        self.selected_targets: List[str] = []
        self.network_filter: str = ""
        self.sort_ascending: bool = True
        self.l3_rules: List[Dict] = []
        self.current_view: str = ""
        self.console_logs: List[str] = []
        self.max_console_logs = 500  # Maximum number of log entries to keep

    def add_log(self, message: str):
        """Add a log message to the console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.console_logs.append(log_entry)
        
        # Keep only the last max_console_logs entries
        if len(self.console_logs) > self.max_console_logs:
            self.console_logs = self.console_logs[-self.max_console_logs:]
            
        # Update the console display if it exists
        if dpg.does_item_exist("console_text"):
            dpg.set_value("console_text", "\n".join(self.console_logs))
            dpg.set_y_scroll("console_window", -1.0)  # Auto-scroll to bottom

    def setup_gui(self):
        dpg.create_context()

        with dpg.window(
            label="Meraki Authentication",
            tag="auth_window",
            no_resize=True,
            no_move=True,
            no_collapse=True,
        ):
            dpg.add_input_text(
                label="API Key",
                tag="api_key_input",
                password=True,
                callback=lambda s, a: self.authenticate() if a else None,
                on_enter=True,
            )
            dpg.add_button(label="Connect", callback=self.authenticate)

        with dpg.window(
            label="Mirage - V0.2",
            tag="main_window",
            show=False,
            no_resize=True,
            no_move=True,
            no_collapse=True,
            no_close=True,
        ):
            with dpg.menu_bar():
                with dpg.menu(label="Menu"):
                    dpg.add_menu_item(label="Logout", callback=self.logout)
                    dpg.add_menu_item(
                        label="Refresh Networks", callback=self.refresh_networks
                    )
                    dpg.add_menu_item(
                        label="Clear Console", callback=self.clear_console
                    )

            # Main layout with sidebar, content window, and console
            with dpg.group(horizontal=False):
                # Top section with sidebar and content
                with dpg.group(horizontal=True, tag="main_content_group"):
                    with dpg.child_window(width=200, border=False, tag="sidebar_window"):
                        with dpg.collapsing_header(label="Deployment", default_open=True):
                            dpg.add_button(
                                label="L7 Rules", callback=self.show_l7_rules, width=-1
                            )
                            dpg.add_button(
                                label="L3 Rules", callback=self.show_l3_rules, width=-1
                            )
                        with dpg.collapsing_header(label="Assessment", default_open=True):
                            dpg.add_button(
                                label="Public IPs",
                                callback=self.show_public_ips_content,
                                width=-1,
                            )
                            dpg.add_button(
                                label="IPS/IPS Status",
                                callback=self.show_ids_ips_status,
                                width=-1,
                            )
                            dpg.add_button(
                                label="AMP Status", callback=self.show_amp_status, width=-1
                            )
                            dpg.add_button(
                                label="Port Forwarding Check",
                                callback=self.show_port_forwarding_check,
                                width=-1,
                            )

                    with dpg.child_window(tag="content_window", border=False):
                        pass
                
                # Console at the bottom
                with dpg.collapsing_header(label="Console", default_open=True, tag="console_header"):
                    with dpg.child_window(tag="console_window", height=150, horizontal_scrollbar=True):
                        dpg.add_text("", tag="console_text", wrap=0)

        with dpg.window(
            label="Status",
            tag="status_window",
            show=False,
            modal=True,
            no_resize=True,
            no_move=True,
        ):
            dpg.add_text(tag="status_text")
    
    def clear_console(self):
        """Clear the console log"""
        self.console_logs = []
        if dpg.does_item_exist("console_text"):
            dpg.set_value("console_text", "")

    def show_network_selection(self, title: str, multi_select: bool = False):
        self.current_view = f"network_selection_{title}_{multi_select}"
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            with dpg.group(horizontal=True):
                dpg.add_text(title, color=(255, 255, 0))
                dpg.add_input_text(
                    label="Search",
                    tag="network_filter",
                    callback=lambda s, a: self.handle_filter_input(a, multi_select),
                    on_enter=True,
                    default_value=self.network_filter,
                    width=200,
                )
                dpg.add_button(
                    label="Sort (A-Z)" if self.sort_ascending else "Sort (Z-A)",
                    callback=lambda: self.toggle_sort(multi_select),
                )

            if multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Select All", callback=lambda: self.select_all_networks(multi_select)
                    )
                    dpg.add_button(
                        label="Clear Selection", callback=lambda: self.clear_selection(multi_select)
                    )

            dpg.add_table(
                header_row=True,
                borders_innerH=True,
                borders_outerH=True,
                tag="networks_table",
            )

            dpg.add_table_column(label="Network Name", width=400, parent="networks_table")
            dpg.add_table_column(label="Select", width=100, parent="networks_table")

            self.update_network_table(multi_select)

            if multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_text(f"Selected: {len(self.selected_targets)}")
                    dpg.add_button(
                        label="Done",
                        callback=self.handle_multi_select_done,
                        width=100,
                    )

    def handle_multi_select_done(self):
        if "L3" in self.current_view:
            self.show_l3_rules()
        else:
            self.show_l7_deployment_interface()

    def handle_filter_input(self, app_data: str, multi_select: bool):
        self.network_filter = app_data
        self.update_network_table(multi_select)

    def update_network_table(self, multi_select: bool):
        for child in dpg.get_item_children("networks_table", slot=1):
            dpg.delete_item(child)

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

    def show_l7_deployment_interface(self):
        self.current_view = "l7_deployment"
        if not self.selected_baseline:
            self.show_status("No baseline network selected!")
            self.show_network_selection("Select Baseline Network", False)
            return

        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.get_network_name(self.selected_baseline))

            dpg.add_text("Current L7 Rules:", color=(255, 255, 0))
            
            rules = self.meraki.get_l7_rules(self.selected_baseline)

            if rules:
                with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True):
                    dpg.add_table_column(label="Policy", width=100)
                    dpg.add_table_column(label="Type", width=100)
                    dpg.add_table_column(label="Value", width=200)

                    for rule in rules:
                        with dpg.table_row():
                            policy_color = (255, 100, 100) if rule["policy"] == "deny" else (100, 255, 100)
                            dpg.add_text(rule["policy"], color=policy_color)
                            dpg.add_text(rule["type"])
                            dpg.add_text(rule["value"])
            else:
                dpg.add_text("No rules configured", color=(255, 255, 0))

            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Change Baseline", callback=self.reset_baseline, width=150
                )
                dpg.add_button(
                    label="Select Targets",
                    callback=lambda: self.show_network_selection(
                        "Select Target Networks", True
                    ),
                    width=150,
                )

            if self.selected_targets:
                with dpg.group(horizontal=True):
                    dpg.add_text(f"Selected Targets: {len(self.selected_targets)}")
                    dpg.add_button(
                        label="Deploy Config", callback=self.deploy_config, width=150
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

    def show_status(self, message: str, duration: int = 3000):
        dpg.set_value("status_text", message)
        dpg.configure_item("status_window", show=True)
        dpg.set_item_pos(
            "status_window",
            [dpg.get_viewport_width() // 2 - 150, dpg.get_viewport_height() // 2 - 50],
        )
        dpg.split_frame(delay=duration)
        dpg.configure_item("status_window", show=False)

    def toggle_sort(self, multi_select: bool):
        self.sort_ascending = not self.sort_ascending
        self.update_network_table(multi_select)

    def select_baseline(self, network_data: Dict):
        self.selected_baseline = network_data["id"]
        self.show_l7_deployment_interface()

    def reset_baseline(self):
        self.selected_baseline = None
        self.show_network_selection("Select Baseline Network", False)

    def toggle_target_selection(self, network_id: str):
        if network_id in self.selected_targets:
            self.selected_targets.remove(network_id)
        else:
            self.selected_targets.append(network_id)
        
        # Update any selected count text
        if dpg.does_item_exist("content_window"):
            for child in dpg.get_item_children("content_window", slot=1):
                if isinstance(child, list):
                    for item in child:
                        if dpg.get_item_type(item) == "mvText" and "Selected" in dpg.get_item_label(item):
                            dpg.set_value(item, f"Selected: {len(self.selected_targets)}")

    def select_all_networks(self, multi_select: bool):
        self.selected_targets = [n["id"] for n in self.filter_and_sort_networks()]
        self.update_network_table(multi_select)

    def clear_selection(self, multi_select: bool):
        self.selected_targets = []
        self.update_network_table(multi_select)

    def get_network_name(self, network_id: str) -> str:
        for network in self.meraki.networks:
            if network["id"] == network_id:
                return network["name"]
        return "Unknown Network"

    def deploy_config(self):
        if not self.selected_targets:
            self.show_status("Please select target networks first")
            self.add_log("Deployment failed: No target networks selected")
            return

        self.show_status("Starting deployment...")
        self.add_log(f"Starting L7 rules deployment to {len(self.selected_targets)} networks")
        success_count = 0
        total = len(self.selected_targets)

        for idx, target_id in enumerate(self.selected_targets, 1):
            network_name = self.get_network_name(target_id)
            self.show_status(f"Deploying to {network_name} ({idx}/{total})")
            self.add_log(f"Deploying to {network_name} ({idx}/{total})")

            if self.meraki.deploy_l7_rules(target_id):
                success_count += 1

        result_message = f"Deployment complete: {success_count}/{total} successful"
        self.show_status(result_message, duration=5000)
        self.add_log(result_message)

    def authenticate(self):
        api_key = dpg.get_value("api_key_input")
        self.show_status("Let me cook...")
        
        # Set logging callback before API initialization
        self.meraki.set_log_callback(self.add_log)
        
        if self.meraki.initialize_api(api_key):
            dpg.hide_item("auth_window")
            dpg.show_item("main_window")
            self.show_status("Loading networks...")
            self.add_log("Authentication successful, loading networks...")
            self.meraki.get_networks()
            self.show_status("Connected" if self.meraki.networks else "No networks found")
        else:
            self.show_status("Authentication failed!")

    def logout(self):
        self.meraki = MerakiManager()
        self.meraki.set_log_callback(self.add_log)
        self.add_log("Logged out, Bye Bye bosssman")
        self.selected_baseline = None
        self.selected_targets = []
        self.current_view = ""
        dpg.hide_item("main_window")
        dpg.show_item("auth_window")
        dpg.set_value("api_key_input", "")

    def refresh_networks(self):
        self.show_status("Refreshing networks...")
        self.add_log("Refreshing networks...")
        networks = self.meraki.get_networks()
        if networks:
            self.show_status("Networks refreshed!")
            self.add_log(f"Networks refreshed successfully. Found {len(networks)} networks.")
            
            # Refresh current view
            if self.current_view == "l7_deployment":
                self.show_l7_deployment_interface()
            elif self.current_view.startswith("network_selection"):
                if "L3" in self.current_view:
                    self.show_network_selection("Select Target Networks for L3 Rules", True)
                elif "Target" in self.current_view:
                    self.show_network_selection("Select Target Networks", True)
                else:
                    self.show_network_selection("Select Baseline Network", False)
            elif self.current_view == "l3_rules":
                self.show_l3_rules()
            elif self.current_view == "amp_status":
                self.show_amp_status()
            elif self.current_view == "ids_ips_status":
                self.show_ids_ips_status()
            elif self.current_view == "port_forwarding":
                self.show_port_forwarding_check()
            elif self.current_view == "public_ips":
                self.show_public_ips_content()
        else:
            self.show_status("Failed to refresh networks")
            self.add_log("Failed to refresh networks")

    def show_l7_rules(self):
        if not self.selected_baseline:
            self.show_network_selection("Select Baseline Network", False)
        else:
            self.show_l7_deployment_interface()

    def show_public_ips_content(self):
        self.current_view = "public_ips"
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
            self.show_status("No WAN IPs found!")
            return
            
        with dpg.file_dialog(
            label="Save WAN IPs",
            width=600,
            height=400,
            callback=lambda s, a: self.save_raw_wan_ips(a, content),
            show=True,
            modal=True,
            default_path=".",
            default_filename="wan_ips.txt",
            file_count=0,  # This is for saving, not opening
            tag="save_raw_ips_dialog",
            directory_selector=False,
        ):
            dpg.add_file_extension(".txt", color=(0, 255, 0, 255))
    
    def save_raw_wan_ips(self, app_data, content):
        if app_data["file_path_name"]:
            file_path = app_data["file_path_name"]
            with open(file_path, "w") as f:
                f.write(content)
            self.show_status(f"Raw WAN IPs saved to {file_path}!")
            self.add_log(f"Raw WAN IPs saved to {file_path}")
        else:
            self.add_log("Raw WAN IPs save cancelled")

    def extract_detailed_wan_info(self):
        self.add_log("Starting extraction of detailed WAN information...")
        records, csv_content = self.meraki.generate_detailed_wan_info()
        
        if not records:
            self.show_status("No WAN information found!")
            return
            
        with dpg.file_dialog(
            label="Save Detailed WAN Info",
            width=600,
            height=400,
            callback=lambda s, a: self.save_detailed_wan_info(a, csv_content),
            show=True,
            modal=True,
            default_path=".",
            default_filename="wan_ips_detailed.csv",
            file_count=0,  # This is for saving, not opening
            tag="save_detailed_wan_dialog",
            directory_selector=False,
        ):
            dpg.add_file_extension(".csv", color=(0, 255, 0, 255))
    
    def save_detailed_wan_info(self, app_data, content):
        if app_data["file_path_name"]:
            file_path = app_data["file_path_name"]
            with open(file_path, "w", newline="\n") as f:
                f.write(content)
            self.show_status(f"Detailed WAN info saved to {file_path}!")
            self.add_log(f"Detailed WAN information saved to {file_path}")
        else:
            self.add_log("Detailed WAN information save cancelled")

    def show_amp_status(self):
        self.current_view = "amp_status"
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("AMP Status", color=(255, 255, 0))
            
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
                                color=(100, 255, 100) if amp_enabled else (255, 100, 100),
                            )

    def show_ids_ips_status(self):
        self.current_view = "ids_ips_status"
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("IDS/IPS Status", color=(255, 255, 0))
            
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
                            dpg.add_text(
                                status["mode"],
                                color=(100, 255, 100) if status["mode"] == "prevention" else (255, 100, 100),
                            )
                            dpg.add_text(status["ruleset"])

    def show_port_forwarding_check(self):
        self.current_view = "port_forwarding"
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("Port Forwarding Check", color=(255, 255, 0))
            
            insecure_rules = self.meraki.check_port_forwarding_status()

            if not any(insecure_rules.values()):
                dpg.add_text("No insecure port forwarding rules found", color=(255, 255, 0))
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
                                dpg.add_text(str(rules), wrap=400)

    def show_l3_rules(self):
        self.current_view = "l3_rules"
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("L3 Rules Deployment", color=(255, 255, 0))
            
            dpg.add_button(
                label="Load L3 Rules CSV", callback=self.load_l3_rules_csv, width=200
            )

            if self.l3_rules:
                dpg.add_text("Loaded L3 Rules:", color=(255, 255, 0))
                
                with dpg.table(header_row=True, borders_innerH=True):
                    dpg.add_table_column(label="Policy", width=100)
                    dpg.add_table_column(label="Protocol", width=100)
                    dpg.add_table_column(label="Dest Port", width=120)
                    dpg.add_table_column(label="Dest CIDR", width=120)
                    dpg.add_table_column(label="Src Port", width=120)
                    dpg.add_table_column(label="Src CIDR", width=120)

                    for rule in self.l3_rules:
                        with dpg.table_row():
                            dpg.add_text(rule["policy"])
                            dpg.add_text(rule["protocol"])
                            dpg.add_text(rule["destPort"])
                            dpg.add_text(rule["destCidr"])
                            dpg.add_text(rule["srcPort"])
                            dpg.add_text(rule["srcCidr"])

                dpg.add_button(
                    label="Select Target Networks",
                    callback=lambda: self.show_network_selection(
                        "Select Target Networks for L3 Rules", True
                    ),
                    width=200,
                )

                if self.selected_targets:
                    dpg.add_text(f"Selected Targets: {len(self.selected_targets)}")
                    dpg.add_button(
                        label="Deploy L3 Rules",
                        callback=self.deploy_l3_rules,
                        width=200,
                    )

    def load_l3_rules_csv(self):
        with dpg.file_dialog(
            label="Load L3 Rules CSV",
            width=600,
            height=400,
            callback=self.handle_l3_rules_csv_load,
            show=True,
            modal=True,
            default_path=".",
            file_count=1,
            tag="l3_rules_file_dialog",
        ):
            dpg.add_file_extension(".csv", color=(0, 255, 0, 255))

    def handle_l3_rules_csv_load(self, sender, app_data):
        if app_data["file_path_name"]:
            file_path = app_data["file_path_name"]
            self.add_log(f"Loading L3 rules from CSV file: {file_path}")
            self.l3_rules = self.meraki.parse_l3_rules_csv(file_path)
            self.add_log(f"Loaded {len(self.l3_rules)} L3 rules from CSV")
            self.show_l3_rules()

    def deploy_l3_rules(self):
        if not self.selected_targets:
            self.show_status("Please select target networks first")
            self.add_log("L3 rules deployment failed: No target networks selected")
            return

        self.show_status("Starting L3 rules deployment...")
        self.add_log(f"Starting L3 rules deployment to {len(self.selected_targets)} networks")
        success_count = 0
        total = len(self.selected_targets)

        for idx, target_id in enumerate(self.selected_targets, 1):
            network_name = self.get_network_name(target_id)
            self.show_status(f"Deploying to {network_name} ({idx}/{total})")
            self.add_log(f"Deploying L3 rules to {network_name} ({idx}/{total})")

            if self.meraki.deploy_l3_rules(target_id, self.l3_rules):
                success_count += 1

        result_message = f"L3 rules deployment complete: {success_count}/{total} successful"
        self.show_status(result_message, duration=5000)
        self.add_log(result_message)

    def run(self):
        viewport_width = 1024
        viewport_height = 768

        dpg.create_viewport(
            title="Mirage", width=viewport_width, height=viewport_height
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

        dpg.configure_item(
            "main_window", width=viewport_width, height=viewport_height, pos=[0, 0]
        )

        # Calculate heights for content and console areas
        console_height = 150
        main_content_height = viewport_height - console_height - 60  # Accounting for menu bar and padding
        
        # Configure main content group
        dpg.configure_item("main_content_group", height=main_content_height)
        
        # Configure sidebar
        dpg.configure_item("sidebar_window", height=main_content_height)
        
        # Configure content window
        content_width = viewport_width - 200
        dpg.configure_item(
            "content_window", width=content_width, height=main_content_height
        )
        
        # Configure console
        dpg.configure_item("console_window", width=viewport_width-20, height=console_height)

        if dpg.is_item_shown("status_window"):
            status_width = 300
            status_height = 100
            dpg.configure_item(
                "status_window",
                width=status_width,
                height=status_height,
                pos=[
                    (viewport_width - status_width) // 2,
                    (viewport_height - status_height) // 2,
                ],
            )


def main():
    gui = GUI()
    gui.setup_gui()
    gui.run()


if __name__ == "__main__":
    main()
