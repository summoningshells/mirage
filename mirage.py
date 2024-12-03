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

    def wait_if_needed(self):
        now = datetime.now()
        time_since_last = (now - self.last_refill).total_seconds()

        # refill tokens based on time passed
        if time_since_last > 1:
            self.tokens = self.requests_per_second
            self.last_refill = now
        else:
            self.tokens += time_since_last * self.requests_per_second

        # ensure tokens do not exceed the bucket size
        self.tokens = min(self.tokens, self.requests_per_second)

        # wait if no tokens available 
        if self.tokens < 1:
            sleep_time = 1 - time_since_last
            time.sleep(sleep_time)
            self.tokens = 1

        self.tokens -= 1
        self.last_request = datetime.now()


class MerakiManager:
    def __init__(self):
        self.dashboard: Optional[meraki.DashboardAPI] = None
        self.organization_id: Optional[str] = None
        self.networks: List[Dict] = []
        self.baseline_rules: List[Dict] = []
        self.rate_limiter = RateLimiter()

    def initialize_api(self, api_key: str) -> bool:
        try:
            self.dashboard = meraki.DashboardAPI(
                api_key,
                wait_on_rate_limit=True,
                nginx_429_retry_wait_time=15,
                retry_4xx_error=True,
                retry_4xx_error_wait_time=15,
                maximum_retries=3,
            )
            # get first organization (single org use case sorry)
            orgs = self.dashboard.organizations.getOrganizations()
            if not orgs:
                raise Exception("No organizations found D:")
            self.organization_id = orgs[0]["id"]
            return True
        except Exception as e:
            print(f"API initialization failed: {e}")
            return False

    def log_api_call(self, method: str, endpoint: str, status_code: int, response_time: float):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "response_time": response_time
        }
        # log to file for debug(mostlikely too much api usage)
        with open("api_log.txt", "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")

    def get_configuration_changes(self, timespan: int = 3600) -> List[Dict]:
        try:
            self.rate_limiter.wait_if_needed()
            changes = self.dashboard.organizations.getOrganizationConfigurationChanges(
                self.organization_id, timespan=timespan
            )
            return changes
        except Exception as e:
            print(f"Error fetching configuration changes: {e}")
            return []

    def get_networks(self) -> List[Dict]:
        try:
            self.rate_limiter.wait_if_needed()
            self.networks = self.dashboard.organizations.getOrganizationNetworks(
                self.organization_id, total_pages="all"
            )
            return self.networks
        except Exception as e:
            print(f"Error fetching networks: {e}")
            return []

    def get_devices(self) -> List[Dict]:
        try:
            self.rate_limiter.wait_if_needed()
            devices = self.dashboard.organizations.getOrganizationDevices(
                self.organization_id, total_pages="all"
            )
            return devices
        except Exception as e:
            print(f"Error fetching devices: {e}")
            return []


    def create_action_batch(self, actions: List[Dict], confirmed: bool = False, synchronous: bool = False) -> Dict:
        try:
            self.rate_limiter.wait_if_needed()
            response = self.dashboard.organizations.createOrganizationActionBatch(
                self.organization_id, actions=actions, confirmed=confirmed, synchronous=synchronous
            )
            return response
        except Exception as e:
            print(f"Error creating action batch: {e}")
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
            print(f"Error fetching L7 rules: {e}")
            return []

    def deploy_l7_rules(self, target_network_id: str) -> bool:
        try:
            if not self.baseline_rules:
                return False

            self.rate_limiter.wait_if_needed()
            self.dashboard.appliance.updateNetworkApplianceFirewallL7FirewallRules(
                target_network_id, rules=self.baseline_rules
            )
            return True
        except Exception as e:
            print(f"Error deploying L7 rules to network {target_network_id}: {e}")
            return False

    def fetch_uplink_statuses(self) -> list:
        try:
            self.rate_limiter.wait_if_needed()
            appliance_statuses = (
                self.dashboard.appliance.getOrganizationApplianceUplinkStatuses(
                    self.organization_id, total_pages="all"
                )
            )
            networks = self.dashboard.organizations.getOrganizationNetworks(
                self.organization_id, total_pages="all"
            )
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

            return appliance_statuses
        except Exception as e:
            print(f"Error fetching uplink statuses: {e}")
            return []

    def generate_raw_wan_ips(self):
        """Generate txt file with all WAN IPs."""
        statuses = self.fetch_uplink_statuses()
        public_ips = {
            uplink["publicIp"]
            for status in statuses
            for uplink in status.get("uplinks", [])
            if uplink.get("publicIp")
        }

        with open("wan_ips.txt", "w") as f:
            for ip in sorted(public_ips):
                f.write(ip + "\n")
        print("WAN IPs saved to wan_ips.txt")

    def generate_detailed_wan_info(self):
        """Generate CSV file with WAN uplink info."""
        statuses = self.fetch_uplink_statuses()
        output_file = "wan_ips_detailed.csv"

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

        with open(output_file, mode="w", newline="\n") as fp:
            csv_writer = csv.DictWriter(
                fp, field_names, delimiter=",", quotechar='"', quoting=csv.QUOTE_ALL
            )
            csv_writer.writeheader()
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

                csv_writer.writerow(record)
        print("Detailed WAN IPs saved to wan_ips_detailed.csv")


    def check_amp_status(self) -> Dict[str, bool]:
        amp_statuses = {}
        for network in self.networks:
            network_id = network["id"]
            try:
                self.rate_limiter.wait_if_needed()
                response = self.dashboard.appliance.getNetworkApplianceSecurityMalware(
                    network_id
                )
                amp_statuses[network_id] = response.get("mode", "disabled") == "enabled"
            except Exception as e:
                print(f"Error fetching AMP status for network {network_id}: {e}")
                amp_statuses[network_id] = False
        return amp_statuses

    def check_ids_ips_status(self) -> Dict[str, Dict]:
        ids_ips_statuses = {}
        for network in self.networks:
            network_id = network["id"]
            try:
                self.rate_limiter.wait_if_needed()
                response = self.dashboard.appliance.getNetworkApplianceSecurityIntrusion(
                    network_id
                )
                ids_ips_statuses[network_id] = {
                    "mode": response.get("mode", "disabled"),
                    "ruleset": response.get("idsRulesets", "none")
                }
            except Exception as e:
                print(f"Error fetching IDS/IPS status for network {network_id}: {e}")
                ids_ips_statuses[network_id] = {
                    "mode": "error",
                    "ruleset": "error"
                }
        return ids_ips_statuses


    def check_port_forwarding_status(self) -> Dict[str, List[Dict]]:
        insecure_rules = {}
        for network in self.networks:
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
            except Exception as e:
                print(f"Error fetching port forwarding rules for network {network_id}: {e}")
                insecure_rules[network_id] = []
        return insecure_rules


class GUI:
    def __init__(self):
        self.meraki = MerakiManager()
        self.selected_baseline: Optional[str] = None
        self.selected_targets: List[str] = []
        self.network_filter: str = ""
        self.sort_ascending: bool = True

    def setup_gui(self):
        dpg.create_context()

        # authentication
        with dpg.window(
            label="Meraki Authentication",
            tag="auth_window",
            no_resize=True,
            no_move=True,
            no_collapse=True,
        ):
            dpg.add_input_text(label="API Key", tag="api_key_input", password=True)
            dpg.add_button(label="Connect", callback=self.authenticate)

        # main Window
        with dpg.window(
            label="Mirage - V0.1 (i despise rate limits)",
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

            # sidebar menu
            with dpg.group(horizontal=True):
                with dpg.child_window(width=200, border=False):
                    with dpg.collapsing_header(label="Deployment", default_open=True):
                        dpg.add_button(
                            label="L7 Rules", callback=self.show_l7_rules, width=-1
                        )
                        dpg.add_button(label="L3 Rules", width=-1)
                    with dpg.collapsing_header(label="Assessment", default_open=True):
                        dpg.add_button(
                            label="Public IPs",
                            callback=self.show_public_ips_content,
                            width=-1,
                        )
                        dpg.add_button(label="Attack Surface", width=-1)
                        dpg.add_button(label="IPS/IPS Status", callback=self.show_ids_ips_status, width=-1)
                        dpg.add_button(label="AMP Status", callback=self.show_amp_status, width=-1)
                        dpg.add_button(label="Port Forwarding Check", callback=self.show_port_forwarding_check, width=-1)

                # main content area - fills remaining space
                with dpg.child_window(tag="content_window", border=False):
                    pass

        # status window for notifications
        with dpg.window(
            label="Status",
            tag="status_window",
            show=False,
            modal=True,
            no_resize=True,
            no_move=True,
        ):
            dpg.add_text(tag="status_text")

    def show_network_selection(self, title: str, multi_select: bool = False):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            # header 
            with dpg.group(horizontal=True):
                dpg.add_text(title, color=(255, 255, 0))
                dpg.add_spacer(width=20)

                # search n sort controls
                with dpg.group(horizontal=True):
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
                        callback=lambda: self.toggle_sort(title, multi_select),
                    )

            dpg.add_spacer(height=5)

            # controls for multi-select mode
            if multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Select All", callback=self.select_all_networks
                    )
                    dpg.add_spacer(width=5)
                    dpg.add_button(
                        label="Clear Selection", callback=self.clear_selection
                    )

            dpg.add_spacer(height=10)

            
            dpg.add_table(
                header_row=True,
                borders_innerH=True,
                borders_outerH=True,
                borders_innerV=True,
                borders_outerV=True,
                row_background=True,
                tag="networks_table",
                user_data=multi_select,
            )  

            dpg.add_table_column(
                label="Network Name",
                width_fixed=True,
                init_width_or_weight=400,
                parent="networks_table",
            )
            dpg.add_table_column(
                label="Select",
                width_fixed=True,
                init_width_or_weight=100,
                parent="networks_table",
            )

            self.update_network_table(multi_select)

            dpg.add_spacer(height=20)

            # footer 
            if multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_text(f"Selected Networks: {len(self.selected_targets)}")
                    dpg.add_spacer(width=20)
                    dpg.add_button(
                        label="Done",
                        callback=lambda: self.show_l7_deployment_interface(),
                        width=100,
                    )

    def handle_filter_input(self, app_data: str, multi_select: bool):
        """filter input while maintaining focus."""
        self.network_filter = app_data
        self.update_network_table(multi_select)
        dpg.focus_item("network_filter")

    def update_network_table(self, multi_select: bool):
        """update network table based on current filter."""
        # clear existing rows while preserving header
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
                        # unique tag for each checkbox
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
        if not self.selected_baseline:
            self.show_status("No baseline network selected!")
            self.show_network_selection("Select Baseline Network", False)
            return

        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            # header
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.get_network_name(self.selected_baseline))

            # show current L7 rules
            dpg.add_spacer(height=10)
            dpg.add_text("Current L7 Rules:", color=(255, 255, 0))
            dpg.add_spacer(height=5)

            rules = self.meraki.get_l7_rules(self.selected_baseline)

            if rules:
                with dpg.table(
                    header_row=True,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True,
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

            # controls section
            dpg.add_spacer(height=20)
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Change Baseline", callback=self.reset_baseline, width=150
                )
                dpg.add_spacer(width=10)
                dpg.add_button(
                    label="Select Targets",
                    callback=lambda: self.show_network_selection(
                        "Select Target Networks", True
                    ),
                    width=150,
                )

            # deploy section
            if self.selected_targets:
                dpg.add_spacer(height=10)
                with dpg.group(horizontal=True):
                    dpg.add_text(f"Selected Targets: {len(self.selected_targets)}")
                    dpg.add_spacer(width=10)
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

    def update_network_list(self, title: str, multi_select: bool):
        self.network_filter = dpg.get_value("network_filter")
        self.show_network_selection(title, multi_select)

    def toggle_sort(self, title: str, multi_select: bool):
        self.sort_ascending = not self.sort_ascending
        self.show_network_selection(title, multi_select)

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

    def select_all_networks(self):
        self.selected_targets = [n["id"] for n in self.filter_and_sort_networks()]
        self.show_network_selection("Select Target Networks", True)

    def clear_selection(self):
        self.selected_targets = []
        self.show_network_selection("Select Target Networks", True)

    def get_network_name(self, network_id: str) -> str:
        for network in self.meraki.networks:
            if network["id"] == network_id:
                return network["name"]
        return "Unknown Network"

    def deploy_config(self):
        if not self.selected_targets:
            self.show_status("Please select target networks first")
            return

        self.show_status("Starting deployment...")
        success_count = 0
        total = len(self.selected_targets)

        for idx, target_id in enumerate(self.selected_targets, 1):
            network_name = self.get_network_name(target_id)
            self.show_status(f"Deploying to {network_name} ({idx}/{total})")

            if self.meraki.deploy_l7_rules(target_id):
                success_count += 1

        self.show_status(
            f"Deployment complete: {success_count}/{total} successful", duration=5000
        )

    def authenticate(self):
        api_key = dpg.get_value("api_key_input")
        self.show_status("Authenticating...")
        if self.meraki.initialize_api(api_key):
            dpg.hide_item("auth_window")
            dpg.show_item("main_window")
            self.show_status("Let me cook...")
            self.meraki.get_networks()
            if self.meraki.networks:
                self.show_status("Successfully connected!")
            else:
                self.show_status("Connected, but no networks found")
        else:
            self.show_status("Authentication failed!")

    def logout(self):
        self.meraki = MerakiManager()
        self.selected_baseline = None
        self.selected_targets = []
        dpg.hide_item("main_window")
        dpg.show_item("auth_window")
        dpg.set_value("api_key_input", "")

    def refresh_networks(self):
        self.show_status("Refreshing networks list...")
        networks = self.meraki.get_networks()
        if networks:
            self.show_status("Networks refreshed!")
            if hasattr(self, "current_view"):
                # refresh current view if it exists
                if self.selected_baseline:
                    self.show_l7_deployment_interface()
                else:
                    self.show_network_selection("Select Baseline Network", False)
        else:
            self.show_status("Failed to refresh networks (possible rate limit)")

    def show_l7_rules(self):
        if not self.selected_baseline:
            self.show_network_selection("Select Baseline Network", False)
        else:
            self.show_l7_deployment_interface()

    def show_public_ips_content(self):
        dpg.delete_item(
            "content_window", children_only=True
        )  # clear the central content window

        with dpg.group(parent="content_window"):
            dpg.add_text("Public IPs", color=(255, 255, 0), indent=10)
            dpg.add_spacer(height=10)

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

            dpg.add_spacer(height=20)

    def extract_raw_wan_ips(self):
        self.meraki.generate_raw_wan_ips()
        self.show_status("Raw WAN IPs extracted!")

    def extract_detailed_wan_info(self):
        self.meraki.generate_detailed_wan_info()
        self.show_status("Detailed WAN Info extracted!")



    def show_amp_status(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("AMP Status", color=(255, 255, 0), indent=10)
            dpg.add_spacer(height=10)

            amp_statuses = self.meraki.check_amp_status()

            if not amp_statuses:
                dpg.add_text("No AMP statuses found", color=(255, 255, 0))
            else:
                with dpg.table(
                    header_row=True,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True,
                ):
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

            dpg.add_spacer(height=20)

    def show_ids_ips_status(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("IDS/IPS Status", color=(255, 255, 0), indent=10)
            dpg.add_spacer(height=10)

            ids_ips_statuses = self.meraki.check_ids_ips_status()

            if not ids_ips_statuses:
                dpg.add_text("No IDS/IPS statuses found", color=(255, 255, 0))
            else:
                with dpg.table(
                    header_row=True,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True,
                ):
                    dpg.add_table_column(label="Network Name", width=400)
                    dpg.add_table_column(label="Mode", width=100)
                    dpg.add_table_column(label="Ruleset", width=100)

                    for network in self.meraki.networks:
                        network_id = network["id"]
                        status = ids_ips_statuses.get(network_id, {"mode": "error", "ruleset": "error"})
                        with dpg.table_row():
                            dpg.add_text(network["name"])
                            dpg.add_text(
                                status["mode"],
                                color=(100, 255, 100) if status["mode"] == "prevention" else (255, 100, 100),
                            )
                            dpg.add_text(status["ruleset"])

            dpg.add_spacer(height=20)

    def show_port_forwarding_check(self):
        dpg.delete_item("content_window", children_only=True)

        with dpg.group(parent="content_window"):
            dpg.add_text("Port Forwarding Check", color=(255, 255, 0), indent=10)
            dpg.add_spacer(height=10)

            insecure_rules = self.meraki.check_port_forwarding_status()

            if not any(insecure_rules.values()):
                dpg.add_text("No insecure port forwarding rules found", color=(255, 255, 0))
            else:
                with dpg.table(
                    header_row=True,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True,
                ):
                    dpg.add_table_column(label="Network Name", width=400)
                    dpg.add_table_column(label="Insecure Rules", width=400)

                    for network in self.meraki.networks:
                        network_id = network["id"]
                        rules = insecure_rules.get(network_id, [])
                        if rules:
                            with dpg.table_row():
                                dpg.add_text(network["name"])
                                dpg.add_text(str(rules), wrap=400)

            dpg.add_spacer(height=20)


    def run(self):
        viewport_width = 1024
        viewport_height = 768

        dpg.create_viewport(
            title="Mirage", width=viewport_width, height=viewport_height
        )
        dpg.set_viewport_resize_callback(self.resize_windows)

        # initial window positions and sizes
        self.resize_windows(None, [viewport_width, viewport_height])

        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()

    def resize_windows(self, sender, app_data):
        viewport_width = dpg.get_viewport_width()
        viewport_height = dpg.get_viewport_height()

        #  authentication window
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

        #  main window to fill viewport
        dpg.configure_item(
            "main_window", width=viewport_width, height=viewport_height, pos=[0, 0]
        )

        # content window to fill available space
        content_width = viewport_width - 200  # Subtract sidebar width
        dpg.configure_item(
            "content_window", width=content_width, height=viewport_height - 50
        )  # Subtract menu bar height

        # status window
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
