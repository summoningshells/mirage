import dearpygui.dearpygui as dpg
import meraki
from typing import Optional, List, Dict, Callable, Any
import time
from datetime import datetime
import csv
import io


class RateLimiter:
    def __init__(self, requests_per_second: int = 10):
        self.interval = 1.0 / requests_per_second
        self.last_request = time.time()
        
    def wait_if_needed(self):
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_request = time.time()


class MerakiManager:
    def __init__(self):
        self.dashboard: Optional[meraki.DashboardAPI] = None
        self.organization_id: Optional[str] = None
        self.networks: List[Dict] = []
        self.baseline_rules: List[Dict] = []
        self.baseline_content_filtering: Dict = {}
        self.baseline_amp_settings: Dict = {}
        self.baseline_ids_ips_settings: Dict = {}
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

    def call_api(self, func_path, error_msg, *args, **kwargs):
        try:
            self.rate_limiter.wait_if_needed()
            # Dynamically get function from path
            func = self.dashboard
            for part in func_path.split('.'):
                func = getattr(func, part)
            result = func(*args, **kwargs)
            
            # Store baseline data if needed
            if func_path == "appliance.getNetworkApplianceFirewallL7FirewallRules":
                self.baseline_rules = result.get("rules", [])
            elif func_path == "appliance.getNetworkApplianceContentFiltering":
                self.baseline_content_filtering = result
            elif func_path == "appliance.getNetworkApplianceSecurityMalware":
                self.baseline_amp_settings = result
            elif func_path == "appliance.getNetworkApplianceSecurityIntrusion":
                self.baseline_ids_ips_settings = result
                
            return result
        except Exception as e:
            self.log(f"{error_msg}: {e}")
            return [] if isinstance([], type(kwargs.get("default", []))) else {}

    def get_configuration_changes(self, timespan: int = 3600) -> List[Dict]:
        return self.call_api(
            "organizations.getOrganizationConfigurationChanges",
            "Error fetching configuration changes",
            self.organization_id,
            timespan=timespan,
        )

    def get_networks(self) -> List[Dict]:
        self.networks = self.call_api(
            "organizations.getOrganizationNetworks",
            "Error fetching networks",
            self.organization_id,
            total_pages="all",
        )
        return self.networks

    def get_devices(self) -> List[Dict]:
        return self.call_api(
            "organizations.getOrganizationDevices",
            "Error fetching devices",
            self.organization_id,
            total_pages="all",
        )

    def create_action_batch(
        self, actions: List[Dict], confirmed: bool = False, synchronous: bool = False
    ) -> Dict:
        return self.call_api(
            "organizations.createOrganizationActionBatch",
            "Error creating action batch",
            self.organization_id,
            actions=actions,
            confirmed=confirmed,
            synchronous=synchronous,
        )

    def get_l7_rules(self, network_id: str) -> List[Dict]:
        response = self.call_api(
            "appliance.getNetworkApplianceFirewallL7FirewallRules",
            "Error fetching L7 rules",
            network_id,
        )
        return response.get("rules", [])

    def get_content_filtering(self, network_id: str) -> Dict:
        return self.call_api(
            "appliance.getNetworkApplianceContentFiltering",
            "Error fetching content filtering",
            network_id,
        )

    def deploy_config(self, target_network_id: str, config_type: str, config_data=None) -> bool:
        config_data = config_data or {}
        
        if config_type == "l7":
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
                
        elif config_type == "content_filtering":
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
                
        elif config_type == "l3":
            rules = config_data.get("rules", [])
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
                
        elif config_type == "amp":
            amp_enabled = config_data.get("enabled", False)
            try:
                self.rate_limiter.wait_if_needed()
                self.dashboard.appliance.updateNetworkApplianceSecurityMalware(
                    target_network_id, mode="enabled" if amp_enabled else "disabled"
                )
                self.log(
                    f"Successfully deployed AMP settings to network {target_network_id}"
                )
                return True
            except Exception as e:
                self.log(
                    f"Error deploying AMP settings to network {target_network_id}: {e}"
                )
                return False
                
        elif config_type == "ids_ips":
            mode = config_data.get("mode", "disabled")
            ruleset = config_data.get("ruleset", "connectivity")
            try:
                self.rate_limiter.wait_if_needed()
                self.dashboard.appliance.updateNetworkApplianceSecurityIntrusion(
                    target_network_id,
                    mode=mode,
                    idsRulesets=ruleset if mode != "disabled" else "none",
                )
                self.log(
                    f"Successfully deployed IDS/IPS settings to network {target_network_id}"
                )
                return True
            except Exception as e:
                self.log(
                    f"Error deploying IDS/IPS settings to network {target_network_id}: {e}"
                )
                return False
        
        else:
            self.log(f"Unknown config type: {config_type}")
            return False

    def get_l3_rules(self, network_id: str) -> List[Dict]:
        response = self.call_api(
            "appliance.getNetworkApplianceFirewallL3FirewallRules",
            "Error fetching L3 rules",
            network_id,
        )
        return response.get("rules", [])

    def deploy_l3_rules(self, target_network_id: str, rules: List[Dict]) -> bool:
        return self.deploy_config(target_network_id, "l3", {"rules": rules})

    def get_amp_settings(self, network_id: str) -> Dict:
        return self.call_api(
            "appliance.getNetworkApplianceSecurityMalware",
            "Error fetching AMP settings",
            network_id,
        )

    def deploy_amp_settings(self, target_network_id: str, amp_enabled: bool) -> bool:
        return self.deploy_config(target_network_id, "amp", {"enabled": amp_enabled})

    def get_ids_ips_settings(self, network_id: str) -> Dict:
        return self.call_api(
            "appliance.getNetworkApplianceSecurityIntrusion",
            "Error fetching IDS/IPS settings",
            network_id,
        )

    def deploy_ids_ips_settings(
        self, target_network_id: str, mode: str, ruleset: str = "connectivity"
    ) -> bool:
        return self.deploy_config(target_network_id, "ids_ips", {"mode": mode, "ruleset": ruleset})

    def export_import_csv(self, operation: str, network_id: str = None, file_path: str = None, rules: List[Dict] = None):
        try:
            if operation == "export":
                if not network_id or not file_path:
                    return False, "Missing required parameters for export"
                    
                rules = self.get_l3_rules(network_id)
                field_names = [
                    "comment", "policy", "protocol", "srcCidr", "srcPort", 
                    "destCidr", "destPort", "syslogEnabled"
                ]

                with open(file_path, mode="w", newline="\n") as fp:
                    csv_writer = csv.DictWriter(
                        fp, field_names, delimiter=",", quotechar='"', quoting=csv.QUOTE_ALL
                    )
                    csv_writer.writeheader()
                    for rule in rules:
                        rule_row = {field: rule.get(field, "") for field in field_names}
                        csv_writer.writerow(rule_row)

                self.log(f"Successfully exported {len(rules)} L3 rules to {file_path}")
                return True, rules
                
            elif operation == "import":
                if not file_path:
                    return False, "Missing file path for import"
                    
                rules = []
                with open(file_path, mode="r", newline="\n") as fp:
                    csv_reader = csv.DictReader(fp)
                    field_names = csv_reader.fieldnames

                    for row in csv_reader:
                        rule = {}
                        for field in field_names:
                            if field in row:
                                if row[field] == "":
                                    continue

                                if field == "syslogEnabled":
                                    rule[field] = row[field].lower() == "true"
                                else:
                                    rule[field] = row[field]
                        rules.append(rule)

                self.log(f"Successfully imported {len(rules)} L3 rules from {file_path}")
                return True, rules
                
            else:
                return False, f"Unknown operation: {operation}"
                
        except Exception as e:
            self.log(f"Error in {operation} L3 rules: {e}")
            return False, []

    def export_l3_rules_to_csv(self, network_id: str, output_file: str) -> bool:
        success, _ = self.export_import_csv("export", network_id=network_id, file_path=output_file)
        return success

    def import_l3_rules_from_csv(self, input_file: str) -> List[Dict]:
        success, rules = self.export_import_csv("import", file_path=input_file)
        return rules if success else []

    def fetch_uplink_statuses(self) -> list:
        try:
            self.rate_limiter.wait_if_needed()
            self.log("Fetching appliance uplink statuses...")
            appliance_statuses = self.call_api(
                "appliance.getOrganizationApplianceUplinkStatuses",
                "Error fetching uplink statuses",
                self.organization_id, 
                total_pages="all"
            )
            
            self.log("Fetching networks...")
            networks = self.call_api(
                "organizations.getOrganizationNetworks",
                "Error fetching networks",
                self.organization_id, 
                total_pages="all"
            )
            
            self.log("Fetching device statuses...")
            devices = self.call_api(
                "organizations.getOrganizationDevicesStatuses",
                "Error fetching device statuses",
                self.organization_id, 
                total_pages="all"
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

    def generate_wan_info(self, output_type="raw", output_file=None):
        self.log(f"Generating {output_type} WAN info list...")
        statuses = self.fetch_uplink_statuses()
        
        if output_type == "raw":
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
            
        elif output_type == "detailed":
            field_names = [
                "name", "serial", "model", "network", "networkId",
                "wan1_status", "wan1_ip", "wan1_gateway", "wan1_publicIp",
                "wan2_status", "wan2_ip", "wan2_gateway", "wan2_publicIp",
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
        
        return [], ""

    def generate_raw_wan_ips(self, output_file=None):
        return self.generate_wan_info("raw", output_file)

    def generate_detailed_wan_info(self, output_file=None):
        return self.generate_wan_info("detailed", output_file)

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
            response = self.call_api(
                "appliance.getNetworkApplianceSecurityMalware",
                f"Error fetching AMP status for network {network_id}",
                network_id
            )
            return response.get("mode", "disabled") == "enabled"

        return self.check_network_statuses("AMP", get_amp)

    def check_ids_ips_status(self) -> Dict[str, Dict]:
        def get_ids_ips(network_id):
            response = self.call_api(
                "appliance.getNetworkApplianceSecurityIntrusion",
                f"Error fetching IDS/IPS status for network {network_id}",
                network_id
            )
            return {
                "mode": response.get("mode", "disabled"),
                "ruleset": response.get("idsRulesets", "none"),
            }

        return self.check_network_statuses("IDS/IPS", get_ids_ips)

    def check_port_forwarding_status(self) -> Dict[str, List[Dict]]:
        def get_port_forwarding(network_id):
            response = self.call_api(
                "appliance.getNetworkApplianceFirewallPortForwardingRules",
                f"Error fetching port forwarding rules for network {network_id}",
                network_id
            )
            rules = response.get("rules", [])
            return [rule for rule in rules if "any" in rule.get("allowedIps", [])]

        return self.check_network_statuses("port forwarding rules", get_port_forwarding)


class View:
    """Base view class to reduce code duplication in the GUI"""
    
    def __init__(self, gui, parent_tag="content_window"):
        self.gui = gui
        self.meraki = gui.meraki
        self.parent_tag = parent_tag
    
    def render(self):
        """Override this in subclasses to render the view"""
        pass
    
    def add_deployment_buttons(self):
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="Change Baseline", 
                callback=self.gui.reset_baseline, 
                width=150
            )
            dpg.add_button(
                label="Select Targets",
                callback=self.gui.select_deployment_targets,
                width=150,
            )

        if self.gui.selected_targets:
            with dpg.group(horizontal=True):
                dpg.add_text(f"Selected Targets: {len(self.gui.selected_targets)}")
                dpg.add_button(
                    label="Deploy Config", 
                    callback=self.gui.deploy_config, 
                    width=150
                )


class BaseTableView(View):
    """Base class for views that display a table of data"""
    
    def __init__(self, gui, parent_tag="content_window", columns=None, title=None):
        super().__init__(gui, parent_tag)
        self.columns = columns or []
        self.title = title or "Data Table"
        
    def render(self):
        with dpg.group(parent=self.parent_tag):
            dpg.add_text(self.title, color=(255, 255, 0))
            
            data = self.get_data()
            
            if not data:
                dpg.add_text("No data found", color=(255, 255, 0))
                return
                
            self.render_table(data)
    
    def get_data(self):
        """Override in subclasses to provide data for the table"""
        return []
        
    def render_table(self, data):
        with dpg.table(header_row=True, borders_innerH=True, borders_outerH=True):
            for col in self.columns:
                dpg.add_table_column(label=col["label"], width=col.get("width", 100))
                
            for row in data:
                with dpg.table_row():
                    for col in self.columns:
                        value = row.get(col["key"], "")
                        color = col.get("color_func", lambda x: None)(value)
                        dpg.add_text(str(value), color=color)


class L7RulesView(View):
    def render(self):
        if not self.gui.selected_baseline:
            self.gui.add_log("⚠️ No baseline network selected")
            self.gui.show_network_selection(
                "Select Baseline Network", False, self.gui.select_l7_baseline
            )
            return

        with dpg.group(parent=self.parent_tag):
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.gui.get_network_name(self.gui.selected_baseline))

            dpg.add_text("Current L7 Rules:", color=(255, 255, 0))

            rules = self.meraki.get_l7_rules(self.gui.selected_baseline)

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

            self.add_deployment_buttons()


class ContentFilteringView(View):
    def render(self):
        if not self.gui.selected_baseline:
            self.gui.add_log("⚠️ No baseline network selected for content filtering")
            self.gui.show_network_selection(
                "Select Baseline Network for Content Filtering",
                False,
                self.gui.select_content_filtering_baseline,
            )
            return

        with dpg.group(parent=self.parent_tag):
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.gui.get_network_name(self.gui.selected_baseline))

            dpg.add_text("Current Content Filtering Configuration:", color=(255, 255, 0))

            content_filtering = self.meraki.get_content_filtering(self.gui.selected_baseline)

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
                dpg.add_text("No content filtering configuration found", color=(255, 255, 0))

            self.add_deployment_buttons()


class L3RulesView(View):
    def render(self):
        with dpg.group(parent=self.parent_tag):
            dpg.add_text("L3 Firewall Rules", color=(255, 255, 0))

            if not self.gui.selected_baseline:
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Select Network",
                        callback=lambda: self.gui.show_network_selection(
                            "Select Network for L3 Rules",
                            False,
                            self.gui.select_l3_network,
                        ),
                        width=150,
                    )
            else:
                network_name = self.gui.get_network_name(self.gui.selected_baseline)
                dpg.add_text(f"Selected Network: {network_name}")
                
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Change Network",
                        callback=lambda: self.gui.show_network_selection(
                            "Select Network for L3 Rules",
                            False,
                            self.gui.select_l3_network,
                        ),
                        width=150,
                    )
                    dpg.add_button(
                        label="Extract to CSV",
                        callback=self.gui.export_l3_rules,
                        width=150,
                    )
                
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Import from CSV",
                        callback=self.gui.import_l3_rules,
                        width=150,
                    )

                    dpg.add_button(
                        label="Select Targets for Deployment",
                        callback=self.gui.select_l3_deployment_targets,
                        width=200,
                    )

            # Display rules section
            if self.gui.l3_rules:
                if hasattr(self.gui, "rules_imported") and self.gui.rules_imported:
                    dpg.add_text("Imported L3 Firewall Rules:", color=(255, 255, 0))
                else:
                    dpg.add_text("Current L3 Firewall Rules:", color=(255, 255, 0))

                self.display_l3_rules_table()

                if self.gui.selected_targets:
                    with dpg.group(horizontal=True):
                        dpg.add_text(f"Selected Targets: {len(self.gui.selected_targets)}")
                        dpg.add_button(
                            label="Deploy L3 Rules",
                            callback=self.gui.deploy_config,
                            width=150,
                        )
            elif self.gui.selected_baseline:
                self.display_l3_rules(self.gui.selected_baseline)

    def display_l3_rules(self, network_id):
        rules = self.meraki.get_l3_rules(network_id)
        self.gui.l3_rules = rules
        self.gui.rules_imported = False

        if not rules:
            dpg.add_text("No L3 rules found", color=(255, 255, 0))
            return

        self.display_l3_rules_table()

    def display_l3_rules_table(self):
        if not self.gui.l3_rules:
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

            for rule in self.gui.l3_rules:
                with dpg.table_row():
                    dpg.add_text(rule.get("comment", ""))
                    policy = rule.get("policy", "")
                    policy_color = (100, 255, 100) if policy == "allow" else (255, 100, 100)
                    dpg.add_text(policy, color=policy_color)
                    dpg.add_text(rule.get("protocol", ""))
                    dpg.add_text(rule.get("srcCidr", ""))
                    dpg.add_text(rule.get("srcPort", ""))
                    dpg.add_text(rule.get("destCidr", ""))
                    dpg.add_text(rule.get("destPort", ""))
                    dpg.add_text("Yes" if rule.get("syslogEnabled", False) else "No")


class PublicIPsView(View):
    def render(self):
        with dpg.group(parent=self.parent_tag):
            dpg.add_text("Public IPs", color=(255, 255, 0))

            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Extract Raw WAN IPs",
                    callback=self.gui.extract_raw_wan_ips,
                    width=200,
                )
                dpg.add_button(
                    label="Extract Detailed WAN Info",
                    callback=self.gui.extract_detailed_wan_info,
                    width=200,
                )


class AMPDeploymentView(View):
    def render(self):
        if not self.gui.selected_baseline:
            self.gui.add_log("⚠️ No baseline network selected for AMP deployment")
            self.gui.show_network_selection(
                "Select Baseline Network for AMP",
                False,
                self.gui.select_amp_baseline,
            )
            return

        with dpg.group(parent=self.parent_tag):
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.gui.get_network_name(self.gui.selected_baseline))

            dpg.add_text("Current AMP Configuration:", color=(255, 255, 0))

            amp_settings = self.meraki.get_amp_settings(self.gui.selected_baseline)
            amp_enabled = amp_settings.get("mode", "disabled") == "enabled"

            dpg.add_text(
                f"AMP is currently {'ENABLED' if amp_enabled else 'DISABLED'}",
                color=(100, 255, 100) if amp_enabled else (255, 100, 100),
            )

            dpg.add_text("Deployment Configuration:", color=(255, 255, 0))
            dpg.add_checkbox(
                label="Enable Advanced Malware Protection (AMP)",
                tag="amp_enabled_checkbox",
                default_value=amp_enabled,
            )

            self.add_deployment_buttons()


class IDSIPSDeploymentView(View):
    def render(self):
        if not self.gui.selected_baseline:
            self.gui.add_log("⚠️ No baseline network selected for IDS/IPS deployment")
            self.gui.show_network_selection(
                "Select Baseline Network for IDS/IPS",
                False,
                self.gui.select_ids_ips_baseline,
            )
            return

        with dpg.group(parent=self.parent_tag):
            with dpg.group(horizontal=True):
                dpg.add_text("Baseline Network:", color=(255, 255, 0))
                dpg.add_text(self.gui.get_network_name(self.gui.selected_baseline))

            dpg.add_text("Current IDS/IPS Configuration:", color=(255, 255, 0))

            ids_settings = self.meraki.get_ids_ips_settings(self.gui.selected_baseline)
            current_mode = ids_settings.get("mode", "disabled")
            current_ruleset = ids_settings.get("idsRulesets", "none")

            mode_color = (
                (100, 255, 100)
                if current_mode == "prevention"
                else ((255, 255, 0) if current_mode == "detection" else (255, 100, 100))
            )

            dpg.add_text(f"IDS/IPS Mode: {current_mode}", color=mode_color)
            dpg.add_text(f"IDS/IPS Ruleset: {current_ruleset}")

            dpg.add_text("Deployment Configuration:", color=(255, 255, 0))

            dpg.add_combo(
                tag="ids_ips_mode_combo",
                items=["disabled", "detection", "prevention"],
                default_value=current_mode,
                width=200,
                label="IDS/IPS Mode",
            )

            dpg.add_combo(
                tag="ids_ips_ruleset_combo",
                items=["connectivity", "balanced", "security"],
                default_value=current_ruleset if current_ruleset != "none" else "connectivity",
                width=200,
                label="IDS/IPS Ruleset",
            )

            # Add help text
            with dpg.group(horizontal=True):
                dpg.add_text("Mode: ", indent=20)
                dpg.add_text("disabled = off, detection = alert only, prevention = block threats")

            with dpg.group(horizontal=True):
                dpg.add_text("Ruleset: ", indent=20)
                dpg.add_text("connectivity = minimal, balanced = recommended, security = strict")

            self.add_deployment_buttons()


class AMPStatusView(BaseTableView):
    def __init__(self, gui, parent_tag="content_window"):
        columns = [
            {"label": "Network Name", "key": "name", "width": 400},
            {"label": "AMP Enabled", "key": "status", "width": 100, 
             "color_func": lambda x: (100, 255, 100) if x == "Yes" else (255, 100, 100)}
        ]
        super().__init__(gui, parent_tag, columns, "AMP Status")
    
    def get_data(self):
        amp_statuses = self.meraki.check_amp_status()
        
        if not amp_statuses:
            return []
            
        enabled_count = sum(1 for is_enabled in amp_statuses.values() if is_enabled)
        total_count = len(amp_statuses)
        
        self.gui.add_log(
            f"Networks with AMP enabled: {enabled_count}/{total_count}"
        )
            
        data = []
        for network in self.meraki.networks:
            network_id = network["id"]
            amp_enabled = amp_statuses.get(network_id, False)
            data.append({
                "name": network["name"],
                "status": "Yes" if amp_enabled else "No"
            })
            
        return data


class IDSIPSStatusView(BaseTableView):
    def __init__(self, gui, parent_tag="content_window"):
        columns = [
            {"label": "Network Name", "key": "name", "width": 400},
            {"label": "Mode", "key": "mode", "width": 100, 
             "color_func": lambda x: (100, 255, 100) if x == "prevention" else 
                          (255, 255, 0) if x == "detection" else (255, 100, 100)},
            {"label": "Ruleset", "key": "ruleset", "width": 100}
        ]
        super().__init__(gui, parent_tag, columns, "IDS/IPS Status")
    
    def get_data(self):
        ids_ips_statuses = self.meraki.check_ids_ips_status()
        
        if not ids_ips_statuses:
            return []
            
        prevention_count = sum(
            1 for status in ids_ips_statuses.values() if status.get("mode") == "prevention"
        )
        detection_count = sum(
            1 for status in ids_ips_statuses.values() if status.get("mode") == "detection"
        )
        total_count = len(ids_ips_statuses)
        
        self.gui.add_log(
            f"Networks with prevention: {prevention_count}/{total_count}"
        )
        self.gui.add_log(
            f"Networks with detection only: {detection_count}/{total_count}"
        )
            
        data = []
        for network in self.meraki.networks:
            network_id = network["id"]
            status = ids_ips_statuses.get(
                network_id, {"mode": "error", "ruleset": "error"}
            )
            data.append({
                "name": network["name"],
                "mode": status.get("mode", "unknown"),
                "ruleset": status.get("ruleset", "unknown")
            })
            
        return data


class PortForwardingView(View):
    def render(self):
        with dpg.group(parent=self.parent_tag):
            dpg.add_text("Port Forwarding Check", color=(255, 255, 0))
            self.gui.add_log("Checking port forwarding rules for all networks...")

            insecure_rules = self.meraki.check_port_forwarding_status()

            networks_with_issues = sum(1 for rules in insecure_rules.values() if rules)
            total_networks = len(self.meraki.networks)

            dpg.add_text(
                f"Networks with insecure rules: {networks_with_issues}/{total_networks}",
                color=(255, 100, 100) if networks_with_issues > 0 else (100, 255, 100),
            )

            if not any(insecure_rules.values()):
                dpg.add_text("No insecure port forwarding rules found", color=(100, 255, 100))
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

                                rules_text = ""
                                for i, rule in enumerate(rules):
                                    rule_desc = f"{rule.get('name', 'Unnamed')} - "
                                    rule_desc += f"{rule.get('protocol', '?')} {rule.get('publicPort', '?')}"
                                    rule_desc += f" -> {rule.get('localIp', '?')}:{rule.get('localPort', '?')}"
                                    rules_text += rule_desc + "\n"

                                dpg.add_text(rules_text, wrap=400)


class NetworkSelectionView(View):
    def __init__(self, gui, parent_tag="content_window", multi_select=False, title="Select Networks", callback=None):
        super().__init__(gui, parent_tag)
        self.multi_select = multi_select
        self.title = title
        self.callback = callback

    def render(self):
        with dpg.group(parent=self.parent_tag):
            with dpg.group(horizontal=True):
                dpg.add_text(self.title, color=(255, 255, 0))
                dpg.add_input_text(
                    label="Search",
                    tag="network_filter",
                    callback=lambda s, a: self.gui.handle_filter_input(a),
                    on_enter=True,
                    default_value=self.gui.network_filter,
                    width=200,
                )
                dpg.add_button(
                    label="Sort (A-Z)" if self.gui.sort_ascending else "Sort (Z-A)",
                    callback=self.gui.toggle_sort,
                )

            if self.multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Select All", callback=self.gui.select_all_networks)
                    dpg.add_button(label="Clear Selection", callback=self.gui.clear_selection)

            self.create_network_table()

            if self.multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_text(
                        f"Selected: {len(self.gui.selected_targets)}",
                        tag="selected_count_text",
                    )
                    dpg.add_button(
                        label="Done",
                        callback=lambda: self.callback() if self.callback else None,
                        width=100,
                    )

    def create_network_table(self):
        dpg.add_table(
            header_row=True,
            borders_innerH=True,
            borders_outerH=True,
            tag="networks_table",
        )

        dpg.add_table_column(label="Network Name", width=400, parent="networks_table")
        dpg.add_table_column(label="Select", width=100, parent="networks_table")

        filtered_networks = self.gui.filter_and_sort_networks()

        if not filtered_networks:
            with dpg.table_row(parent="networks_table"):
                dpg.add_text("No networks found")
                dpg.add_text("")
        else:
            for network in filtered_networks:
                with dpg.table_row(parent="networks_table"):
                    dpg.add_text(network["name"])
                    if self.multi_select:
                        checkbox_tag = f"checkbox_{network['id']}"
                        dpg.add_checkbox(
                            tag=checkbox_tag,
                            default_value=network["id"] in self.gui.selected_targets,
                            callback=lambda s, a, u: self.gui.toggle_target_selection(u),
                            user_data=network["id"],
                        )
                    else:
                        dpg.add_button(
                            label="Select",
                            callback=lambda s, a, u: self.gui.select_baseline(u),
                            user_data={"id": network["id"], "name": network["name"]},
                        )


class GUI:
    def __init__(self):
        self.meraki = MerakiManager()
        self.selected_baseline: Optional[str] = None
        self.selected_targets: List[str] = []
        self.network_filter: str = ""
        self.sort_ascending: bool = True
        self.l3_rules: List[Dict] = []
        self.console_logs: List[str] = []
        self.max_console_logs = 500
        self.deploy_option: str = "l7"
        self.status_bar_tag = "status_bar"
        self.current_view = None
        self.rules_imported = False
        
        # Map of view names to view classes
        self.views = {
            'l7_rules': L7RulesView,
            'content_filtering': ContentFilteringView,
            'l3_rules': L3RulesView,
            'public_ips': PublicIPsView,
            'amp_deployment': AMPDeploymentView,
            'ids_ips_deployment': IDSIPSDeploymentView,
            'amp_status': AMPStatusView,
            'ids_ips_status': IDSIPSStatusView,
            'port_forwarding': PortForwardingView,
        }

    def add_log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.console_logs.append(log_entry)

        if len(self.console_logs) > self.max_console_logs:
            self.console_logs = self.console_logs[-self.max_console_logs:]

        if dpg.does_item_exist("console_text"):
            dpg.set_value("console_text", "\n".join(self.console_logs))
            dpg.set_y_scroll("console_window", -1.0)

        if dpg.does_item_exist(self.status_bar_tag):
            dpg.set_value(self.status_bar_tag, log_entry)

    def setup_gui(self):
        dpg.create_context()

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

        with dpg.window(
            label="Mirage - V0.5",
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
                with dpg.group(horizontal=True, tag="main_content_group"):
                    with dpg.child_window(
                        width=200, border=False, tag="sidebar_window"
                    ):
                        with dpg.collapsing_header(
                            label="Deployment", default_open=True
                        ):
                            dpg.add_button(
                                label="L7 Rules",
                                callback=lambda: self.change_view('l7_rules'),
                                width=-1,
                            )
                            dpg.add_button(
                                label="Content Filtering",
                                callback=lambda: self.change_view('content_filtering'),
                                width=-1,
                            )
                            dpg.add_button(
                                label="L3 Rules",
                                callback=lambda: self.change_view('l3_rules'),
                                width=-1,
                            )
                            dpg.add_button(
                                label="AMP Deployment",
                                callback=lambda: self.change_view('amp_deployment'),
                                width=-1,
                            )
                            dpg.add_button(
                                label="IDS/IPS Deployment",
                                callback=lambda: self.change_view('ids_ips_deployment'),
                                width=-1,
                            )
                        with dpg.collapsing_header(
                            label="Assessment", default_open=True
                        ):
                            dpg.add_button(
                                label="Public IPs",
                                callback=lambda: self.change_view('public_ips'),
                                width=-1,
                            )
                            dpg.add_button(
                                label="IDS/IPS Status",
                                callback=lambda: self.change_view('ids_ips_status'),
                                width=-1,
                            )
                            dpg.add_button(
                                label="AMP Status",
                                callback=lambda: self.change_view('amp_status'),
                                width=-1,
                            )
                            dpg.add_button(
                                label="Port Forwarding Check",
                                callback=lambda: self.change_view('port_forwarding'),
                                width=-1,
                            )

                    with dpg.child_window(tag="content_window", border=False):
                        pass

                with dpg.collapsing_header(
                    label="Console", default_open=True, tag="console_header"
                ):
                    with dpg.child_window(
                        tag="console_window", height=140, horizontal_scrollbar=True
                    ):
                        dpg.add_text("", tag="console_text", wrap=0)

                dpg.add_text("Ready", tag=self.status_bar_tag)

    def clear_console(self):
        self.console_logs = []
        if dpg.does_item_exist("console_text"):
            dpg.set_value("console_text", "")

    def change_view(self, view_name: str):
        # Clear the current content window
        dpg.delete_item("content_window", children_only=True)
        
        # Set deploy option based on view
        if view_name in ['l7_rules', 'content_filtering', 'l3_rules', 'amp_deployment', 'ids_ips_deployment']:
            self.deploy_option = view_name.split('_')[0] if view_name != 'content_filtering' else 'content_filtering'
        
        # Create and render the appropriate view
        if view_name in self.views:
            view_class = self.views[view_name]
            view = view_class(self)
            view.render()
            self.current_view = view
        elif view_name == 'network_selection':
            # Network selection is a special case that takes additional parameters
            view = NetworkSelectionView(
                self, 
                multi_select=False, 
                title="Select Networks"
            )
            view.render()
            self.current_view = view

    def show_network_selection(self, title: str, multi_select: bool = False, callback: Callable = None):
        view = NetworkSelectionView(
            self, 
            multi_select=multi_select, 
            title=title,
            callback=callback
        )
        view.render()
        self.current_view = view

    def handle_filter_input(self, app_data: str):
        self.network_filter = app_data
        if self.current_view and isinstance(self.current_view, NetworkSelectionView):
            self.update_network_table(self.current_view.multi_select)

    def update_network_table(self, multi_select: bool):
        if dpg.does_item_exist("networks_table"):
            children = dpg.get_item_children("networks_table", slot=1)
            if children:
                for child in children:
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
        if self.current_view and isinstance(self.current_view, NetworkSelectionView):
            self.update_network_table(self.current_view.multi_select)

    # Callbacks for network selection
    def select_l7_baseline(self):
        self.change_view('l7_rules')
    
    def select_content_filtering_baseline(self):
        self.change_view('content_filtering')
    
    def select_amp_baseline(self):
        self.change_view('amp_deployment')
    
    def select_ids_ips_baseline(self):
        self.change_view('ids_ips_deployment')
    
    def select_l3_network(self):
        if self.selected_baseline:
            self.l3_rules = self.meraki.get_l3_rules(self.selected_baseline)
            self.change_view('l3_rules')

    def select_baseline(self, network_data: Dict):
        self.selected_baseline = network_data["id"]
        self.add_log(f"Selected baseline network: {network_data['name']}")

        # Refresh the current view with the new baseline
        if self.deploy_option == "l7":
            self.change_view('l7_rules')
        elif self.deploy_option == "content_filtering":
            self.change_view('content_filtering')
        elif self.deploy_option == "l3":
            self.change_view('l3_rules')
        elif self.deploy_option == "amp":
            self.change_view('amp_deployment')
        elif self.deploy_option == "ids_ips":
            self.change_view('ids_ips_deployment')

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
        if self.current_view and isinstance(self.current_view, NetworkSelectionView):
            self.update_network_table(True)

    def clear_selection(self):
        self.selected_targets = []
        if self.current_view and isinstance(self.current_view, NetworkSelectionView):
            self.update_network_table(True)

    def get_network_name(self, network_id: str) -> str:
        for network in self.meraki.networks:
            if network["id"] == network_id:
                return network["name"]
        return "Unknown Network"

    def reset_baseline(self):
        self.selected_baseline = None
        # Refresh the current view
        self.change_view(self.deploy_option + ('_deployment' if self.deploy_option in ['amp', 'ids_ips'] else '_rules'))

    def select_deployment_targets(self):
        def callback():
            # Refresh the current view
            self.change_view(self.deploy_option + ('_deployment' if self.deploy_option in ['amp', 'ids_ips'] else '_rules'))
        
        self.show_network_selection("Select Target Networks", True, callback)

    def select_l3_deployment_targets(self):
        if not self.selected_baseline and not self.l3_rules:
            self.add_log("⚠️ First select a network or import rules to deploy")
            return
            
        if not self.l3_rules and self.selected_baseline:
            # If the network is selected but rules aren't loaded yet, load them
            self.l3_rules = self.meraki.get_l3_rules(self.selected_baseline)
            
        if not self.l3_rules:
            self.add_log("⚠️ No L3 rules to deploy")
            return
        
        def callback():
            self.change_view('l3_rules')
        
        self.show_network_selection("Select Target Networks for L3 Rules Deployment", True, callback)

    def deploy_config(self):
        if not self.selected_targets:
            self.add_log("⚠️ Deployment failed: No target networks selected")
            return

        deploy_type = self.deploy_option
        config_data = {}

        if deploy_type == "l3":
            if not self.l3_rules:
                self.add_log("⚠️ Deployment failed: No L3 rules to deploy")
                return
            config_data["rules"] = self.l3_rules
        elif deploy_type == "amp":
            config_data["enabled"] = dpg.get_value("amp_enabled_checkbox")
        elif deploy_type == "ids_ips":
            config_data["mode"] = dpg.get_value("ids_ips_mode_combo")
            config_data["ruleset"] = dpg.get_value("ids_ips_ruleset_combo")

        self.add_log(
            f"Starting {deploy_type} deployment to {len(self.selected_targets)} networks"
        )
        success_count = 0
        total = len(self.selected_targets)

        for idx, target_id in enumerate(self.selected_targets, 1):
            network_name = self.get_network_name(target_id)
            self.add_log(f"Deploying to {network_name} ({idx}/{total})")

            if self.meraki.deploy_config(target_id, deploy_type, config_data):
                success_count += 1

        result_message = f"{deploy_type} deployment complete: {success_count}/{total} successful"
        self.add_log(result_message)

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
            if self.current_view:
                current_view_name = self.current_view.__class__.__name__.lower().replace('view', '')
                for name, cls in self.views.items():
                    if cls.__name__.lower() == current_view_name + 'view':
                        self.change_view(name)
                        break
        else:
            self.add_log("⚠️ Failed to refresh networks")

    # File operations
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
            # clear the baseline - we now using imported rules instead(they take precedence)
            self.l3_rules = imported_rules
            self.add_log(f"Successfully imported {len(self.l3_rules)} L3 rules")
            self.change_view('l3_rules')
        else:
            self.add_log("⚠️ Failed to import L3 rules")

    # WAN IP operations
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

    def run(self):
        viewport_width = 1024
        viewport_height = 768

        dpg.create_viewport(
            title="Mirage v0.5", width=viewport_width, height=viewport_height
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

        console_height = 150
        main_content_height = viewport_height - console_height - 80

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
