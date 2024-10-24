import dearpygui.dearpygui as dpg
import meraki
from typing import Optional, List, Dict
import time
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.last_request = datetime.now()
        
    def wait_if_needed(self):
        """Ensure we don't exceed 10 requests per second and maintain 100ms spacing."""
        now = datetime.now()
        time_since_last = (now - self.last_request).total_seconds()
        
        # Ensure minimum 100ms between requests
        if time_since_last < 0.1:
            time.sleep(0.1 - time_since_last)
            
        self.last_request = datetime.now()

class MerakiManager:
    def __init__(self):
        self.dashboard: Optional[meraki.DashboardAPI] = None
        self.organization_id: Optional[str] = None
        self.networks: List[Dict] = []
        self.baseline_rules: List[Dict] = []
        self.rate_limiter = RateLimiter()

    def initialize_api(self, api_key: str) -> bool:
        """Initialize the Meraki Dashboard API with the provided key."""
        try:
            self.dashboard = meraki.DashboardAPI(
                api_key,
                wait_on_rate_limit=True,
                nginx_429_retry_wait_time=15,
                retry_4xx_error=True,
                retry_4xx_error_wait_time=15,
                maximum_retries=3
            )
            # Get first organization (single org use case)
            orgs = self.dashboard.organizations.getOrganizations()
            if not orgs:
                raise Exception("No organizations found")
            self.organization_id = orgs[0]['id']
            return True
        except Exception as e:
            print(f"API initialization failed: {e}")
            return False

    def get_networks(self) -> List[Dict]:
        """Fetch all networks from the organization."""
        try:
            self.rate_limiter.wait_if_needed()
            self.networks = self.dashboard.organizations.getOrganizationNetworks(
                self.organization_id,
                total_pages='all'  # Get all networks in one request
            )
            return self.networks
        except Exception as e:
            print(f"Error fetching networks: {e}")
            return []

    def get_l7_rules(self, network_id: str) -> List[Dict]:
        """Get L7 firewall rules for a specific network."""
        try:
            self.rate_limiter.wait_if_needed()
            response = self.dashboard.appliance.getNetworkApplianceFirewallL7FirewallRules(network_id)
            # Extract rules array from response
            rules = response.get('rules', [])
            self.baseline_rules = rules
            return rules
        except Exception as e:
            print(f"Error fetching L7 rules: {e}")
            return []

    def deploy_l7_rules(self, target_network_id: str) -> bool:
        """Deploy L7 rules to a target network."""
        try:
            if not self.baseline_rules:
                return False
            
            self.rate_limiter.wait_if_needed()
            self.dashboard.appliance.updateNetworkApplianceFirewallL7FirewallRules(
                target_network_id,
                rules=self.baseline_rules
            )
            return True
        except Exception as e:
            print(f"Error deploying L7 rules to network {target_network_id}: {e}")
            return False

class GUI:
    def __init__(self):
        self.meraki = MerakiManager()
        self.selected_baseline: Optional[str] = None
        self.selected_targets: List[str] = []
        self.network_filter: str = ""
        self.sort_ascending: bool = True
        
    def setup_gui(self):
        dpg.create_context()
        
        # Authentication Window
        with dpg.window(label="Meraki Authentication", tag="auth_window", width=400, height=150):
            dpg.add_input_text(label="API Key", tag="api_key_input", password=True)
            dpg.add_button(label="Connect", callback=self.authenticate)
            
        # Main Window (hidden initially)
        with dpg.window(label="Mirage - V0.1 (i hate rate limits edition)", tag="main_window", show=False):
            with dpg.menu_bar():
                with dpg.menu(label="Menu"):
                    dpg.add_menu_item(label="Logout", callback=self.logout)
                    dpg.add_menu_item(label="Refresh Networks", callback=self.refresh_networks)
            
            # Left sidebar
            with dpg.group(horizontal=True):
                with dpg.child_window(width=200, height=600):
                    with dpg.collapsing_header(label="Deployment", default_open=True):
                        dpg.add_button(label="L7 Rules", callback=self.show_l7_rules)
                        dpg.add_button(label="L3 Rules")
                        dpg.add_button(label="Port Forwarding")
                
                # Main content area
                with dpg.child_window(tag="content_window", width=800, height=600):
                    pass

        # Status window for notifications
        with dpg.window(label="Status", tag="status_window", show=False, 
                       pos=(200, 200), width=300, height=100):
            dpg.add_text(tag="status_text")

    def show_l7_rules(self):
        """Show L7 rules interface."""
        if not self.selected_baseline:
            self.show_network_selection("Select Baseline Network", False)
        else:
            self.show_l7_deployment_interface()

    def show_network_selection(self, title: str, multi_select: bool = False):
        """Show network selection interface."""
        dpg.delete_item("content_window", children_only=True)
        
        with dpg.group(parent="content_window"):
            dpg.add_text(title)
            
            # Filter and sort controls
            with dpg.group(horizontal=True):
                dpg.add_input_text(
                    label="Search",
                    tag="network_filter",
                    callback=lambda s, a: self.update_network_list(title, multi_select),
                    default_value=self.network_filter
                )
                dpg.add_button(
                    label="Sort (A-Z)" if self.sort_ascending else "Sort (Z-A)",
                    callback=lambda: self.toggle_sort(title, multi_select)
                )
            
            if multi_select:
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Select All", callback=self.select_all_networks)
                    dpg.add_button(label="Clear Selection", callback=self.clear_selection)
            
            # Network selection table
            with dpg.table(header_row=True):
                dpg.add_table_column(label="Network Name")
                dpg.add_table_column(label="Select")
                
                filtered_networks = self.filter_and_sort_networks()
                
                if not filtered_networks:
                    dpg.add_text("No networks found")
                    return
                
                for network in filtered_networks:
                    with dpg.table_row():
                        dpg.add_text(network['name'])
                        if multi_select:
                            dpg.add_checkbox(
                                default_value=network['id'] in self.selected_targets,
                                callback=lambda s, a, u: self.toggle_target_selection(u),
                                user_data=network['id']
                            )
                        else:
                            # callback to handle the network ID 
                            dpg.add_button(
                                label="Select",
                                callback=lambda s, a, u: self.select_baseline(u),
                                user_data={'id': network['id'], 'name': network['name']}  # Pass both id and name
                            )
    
    def show_l7_deployment_interface(self):
        """Show the L7 rules deployment interface."""
        dpg.delete_item("content_window", children_only=True)
        
        with dpg.group(parent="content_window"):
            dpg.add_text(f"Baseline Network: {self.get_network_name(self.selected_baseline)}")
            
            # Display current L7 rules
            rules = self.meraki.get_l7_rules(self.selected_baseline)
            
            # spacing and header
            dpg.add_spacing(count=5)
            dpg.add_text("Current L7 Rules:", color=(255, 255, 0))  # Yellow header
            dpg.add_spacing(count=5)
            
            if rules:
                with dpg.table(header_row=True):
                    # columns with specific widths
                    dpg.add_table_column(label="Policy", width=100)
                    dpg.add_table_column(label="Type", width=100)
                    dpg.add_table_column(label="Value", width=200)
                    
                    for rule in rules:
                        with dpg.table_row():
                            # color coding for policies
                            policy_color = (255, 100, 100) if rule['policy'] == 'deny' else (100, 255, 100)
                            dpg.add_text(rule['policy'], color=policy_color)
                            dpg.add_text(rule['type'])
                            dpg.add_text(rule['value'])
            else:
                dpg.add_text("No rules configured", color=(255, 255, 0))
            
            # controls
            dpg.add_spacing(count=10)
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Change Baseline", 
                    callback=self.reset_baseline,
                    width=150
                )
                dpg.add_button(
                    label="Select Targets", 
                    callback=lambda: self.show_network_selection("Select Target Networks", True),
                    width=150
                )
            
            if self.selected_targets:
                dpg.add_spacing(count=5)
                dpg.add_text(f"Selected Targets: {len(self.selected_targets)}")
                dpg.add_button(
                    label="Deploy Config", 
                    callback=self.deploy_config,
                    width=150
                )

    def filter_and_sort_networks(self) -> List[Dict]:
        """Filter and sort networks based on current settings."""
        networks = self.meraki.networks
        if self.network_filter:
            networks = [n for n in networks if self.network_filter.lower() in n['name'].lower()]
        return sorted(networks, key=lambda x: x['name'], reverse=not self.sort_ascending)

    def show_status(self, message: str, duration: int = 3000):
        """Show status message in popup window."""
        dpg.set_value("status_text", message)
        dpg.configure_item("status_window", show=True)
        dpg.set_item_pos("status_window", 
                        [dpg.get_viewport_width()//2 - 150,
                         dpg.get_viewport_height()//2 - 50])
        dpg.split_frame(delay=duration)
        dpg.configure_item("status_window", show=False)

    def update_network_list(self, title: str, multi_select: bool):
        """Update the network list based on current filter."""
        self.network_filter = dpg.get_value("network_filter")
        self.show_network_selection(title, multi_select)

    def toggle_sort(self, title: str, multi_select: bool):
        """Toggle sort order and refresh the network list."""
        self.sort_ascending = not self.sort_ascending
        self.show_network_selection(title, multi_select)

    def refresh_networks(self):
        """Refresh the networks list from the API."""
        self.show_status("Refreshing networks list...")
        networks = self.meraki.get_networks()
        if networks:
            self.show_status("Networks refreshed!")
        else:
            self.show_status("Failed to refresh networks")

    def select_baseline(self, network_data: Dict):
        """Set the baseline network and show its L7 rules."""
        self.selected_baseline = network_data['id']  # access the id from the dictionay
        self.show_l7_deployment_interface()

    def reset_baseline(self):
        """Clear baseline selection and return to network selection."""
        self.selected_baseline = None
        self.show_network_selection("Select Baseline Network", False)

    def toggle_target_selection(self, network_id: str):
        """Toggle selection of a target network."""
        if network_id in self.selected_targets:
            self.selected_targets.remove(network_id)
        else:
            self.selected_targets.append(network_id)

    def select_all_networks(self):
        """Select all currently filtered networks as targets."""
        self.selected_targets = [n['id'] for n in self.filter_and_sort_networks()]
        self.show_network_selection("Select Target Networks", True)

    def clear_selection(self):
        """Clear all selected target networks."""
        self.selected_targets = []
        self.show_network_selection("Select Target Networks", True)

    def get_network_name(self, network_id: str) -> str:
        """Get network name from network ID."""
        for network in self.meraki.networks:
            if network['id'] == network_id:
                return network['name']
        return "Unknown Network"

    def deploy_config(self):
        """Deploy L7 rules to all selected target networks."""
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

        self.show_status(f"Deployment complete: {success_count}/{total} successful", duration=5000)


    def authenticate(self):
        """Authenticate with the Meraki API."""
        api_key = dpg.get_value("api_key_input")
        self.show_status("Authenticating...")
        if self.meraki.initialize_api(api_key):
            dpg.hide_item("auth_window")
            dpg.show_item("main_window")
            self.show_status("Loading networks...")
            self.meraki.get_networks()
            if self.meraki.networks:
                self.show_status("Successfully connected!")
            else:
                self.show_status("Connected, but no networks found")
        else:
            self.show_status("Authentication failed!")

    def logout(self):
        """Reset the application state and return to login."""
        self.meraki = MerakiManager()
        self.selected_baseline = None
        self.selected_targets = []
        dpg.hide_item("main_window")
        dpg.show_item("auth_window")
        dpg.set_value("api_key_input", "")

    def run(self):
        """Start the GUI application."""
        dpg.create_viewport(title="Mirage", width=1024, height=768)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()

if __name__ == "__main__":
    gui = GUI()
    gui.setup_gui()
    gui.run()