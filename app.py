from datetime import date

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Configure the browser tab and page layout.
st.set_page_config(
    page_title="CampusShield",
    page_icon="🛡️",
    layout="wide",
)

# Add custom visual styling.
st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }

        .hero {
            padding: 28px;
            margin-bottom: 22px;
            border-radius: 20px;
            color: white;
            background: linear-gradient(
                120deg,
                #082f49,
                #0369a1,
                #0f766e
            );
            box-shadow: 0 12px 30px rgba(2, 132, 199, 0.20);
        }

        .hero h1 {
            margin: 0;
            font-size: 2.5rem;
        }

        .hero p {
            margin: 8px 0 0 0;
            color: #e0f2fe;
            font-size: 1.05rem;
        }

        div[data-testid="stMetric"] {
            padding: 16px;
            border: 1px solid rgba(14, 165, 233, 0.35);
            border-radius: 14px;
            background: rgba(14, 165, 233, 0.08);
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# Systems included in the college's hybrid environment.
SYSTEMS = [
    "Internet",
    "Remote Faculty",
    "Admin Workstation",
    "Zero-Trust Gateway",
    "Identity Service",
    "DMZ Load Balancer",
    "On-Prem Application",
    "Cloud API",
    "Student Database",
    "SIEM",
]

# Attack movement possible in the segmented zero-trust design.
SECURE_ATTACK_EDGES = [
    ("Internet", "DMZ Load Balancer"),
    ("DMZ Load Balancer", "On-Prem Application"),
    ("On-Prem Application", "Student Database"),
]

# Additional movement possible in the unsafe legacy network.
LEGACY_ATTACK_EDGES = SECURE_ATTACK_EDGES + [
    ("Internet", "On-Prem Application"),
    ("Internet", "Student Database"),
    ("On-Prem Application", "Cloud API"),
    ("On-Prem Application", "Identity Service"),
    ("Student Database", "Cloud API"),
    ("Cloud API", "Identity Service"),
    ("Identity Service", "Zero-Trust Gateway"),
    ("Zero-Trust Gateway", "Admin Workstation"),
    ("Remote Faculty", "Zero-Trust Gateway"),
    ("Remote Faculty", "Admin Workstation"),
]


def calculate_attack_path(starting_system, attack_edges):
    """Calculate systems reachable from a compromised system."""

    attack_graph = nx.DiGraph()

    attack_graph.add_nodes_from(SYSTEMS)
    attack_graph.add_edges_from(attack_edges)

    reachable_systems = nx.descendants(
        attack_graph,
        starting_system,
    )

    affected_systems = {
        starting_system
    } | reachable_systems

    possible_targets = len(SYSTEMS) - 1
    reached_targets = len(affected_systems) - 1

    blast_percentage = round(
        (reached_targets / possible_targets) * 100
    )

    return affected_systems, blast_percentage

def create_network_diagram(
    attack_edges,
    affected_systems,
    starting_system,
):
    """Create an interactive diagram of potential attack movement."""

    node_positions = {
        "Internet": (-3.0, 1.2),
        "Remote Faculty": (-3.0, -1.2),
        "Zero-Trust Gateway": (-1.5, -1.2),
        "DMZ Load Balancer": (-1.5, 1.2),
        "On-Prem Application": (0.0, 1.2),
        "Student Database": (1.5, 0.4),
        "Cloud API": (1.5, 1.7),
        "Identity Service": (0.0, -1.2),
        "Admin Workstation": (1.5, -1.2),
        "SIEM": (3.0, 0.0),
    }

    system_zones = {
        "Internet": "External",
        "Remote Faculty": "User Access",
        "Admin Workstation": "Management",
        "Zero-Trust Gateway": "Security Gateway",
        "Identity Service": "Identity",
        "DMZ Load Balancer": "DMZ",
        "On-Prem Application": "Application",
        "Cloud API": "Public Cloud",
        "Student Database": "Restricted Data",
        "SIEM": "Monitoring",
    }

    edge_x = []
    edge_y = []

    for source, destination in attack_edges:
        source_x, source_y = node_positions[source]
        destination_x, destination_y = node_positions[destination]

        edge_x.extend(
            [
                source_x,
                destination_x,
                None,
            ]
        )

        edge_y.extend(
            [
                source_y,
                destination_y,
                None,
            ]
        )

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line={
            "width": 2,
            "color": "#64748b",
        },
        hoverinfo="none",
    )

    node_x = []
    node_y = []
    node_labels = []
    hover_labels = []
    node_colors = []
    node_sizes = []

    for system in SYSTEMS:
        system_x, system_y = node_positions[system]

        node_x.append(system_x)
        node_y.append(system_y)
        node_labels.append(system)

        hover_labels.append(
            f"<b>{system}</b><br>"
            f"Zone: {system_zones[system]}"
        )

        if system == starting_system:
            node_colors.append("#f59e0b")
            node_sizes.append(34)
        elif system in affected_systems:
            node_colors.append("#ef4444")
            node_sizes.append(30)
        else:
            node_colors.append("#0ea5e9")
            node_sizes.append(26)

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=node_labels,
        textposition="top center",
        hovertext=hover_labels,
        hoverinfo="text",
        marker={
            "size": node_sizes,
            "color": node_colors,
            "line": {
                "width": 2,
                "color": "#e2e8f0",
            },
        },
    )

    network_figure = go.Figure(
        data=[
            edge_trace,
            node_trace,
        ]
    )

    network_figure.update_layout(
        height=560,
        showlegend=False,
        hovermode="closest",
        margin={
            "l": 20,
            "r": 20,
            "t": 30,
            "b": 20,
        },
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={
            "color": "#e2e8f0",
            "size": 13,
        },
        xaxis={
            "visible": False,
            "range": [-3.6, 3.6],
        },
        yaxis={
            "visible": False,
            "range": [-1.8, 2.2],
        },
    )

    return network_figure


# Sidebar controls.
st.sidebar.title("🛡️ Simulation Controls")

client_name = st.sidebar.text_input(
    "Client name",
    value="Northbridge College",
)

architecture_mode = st.sidebar.radio(
    "Choose architecture",
    [
        "Proposed zero-trust design",
        "Legacy flat network",
    ],
)

compromised_system = st.sidebar.selectbox(
    "Choose compromised system",
    SYSTEMS,
)

st.sidebar.divider()

st.sidebar.caption(
    "CampusShield is an architecture simulation. "
    "It does not perform real attacks."
)

# Select the attack relationships for the chosen architecture.
if architecture_mode == "Proposed zero-trust design":
    selected_attack_edges = SECURE_ATTACK_EDGES
    high_risk_rules = 0
    public_exposures = 0
else:
    selected_attack_edges = LEGACY_ATTACK_EDGES
    high_risk_rules = 7
    public_exposures = 2

# Calculate the affected systems and blast radius.
affected_systems, blast_radius = calculate_attack_path(
    compromised_system,
    selected_attack_edges,
)

# Calculate a security score using the simulation result.
security_score = max(
    0,
    round(
        100
        - (high_risk_rules * 8)
        - (blast_radius * 0.2)
    ),
)


# Main dashboard header.
st.markdown(
    f"""
    <div class="hero">
        <h1>🛡️ CampusShield</h1>
        <p>
            Hybrid Data Center Security and Attack-Path Simulator
            for {client_name}
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Executive metrics.
column1, column2, column3, column4 = st.columns(4)

column1.metric(
    "Security Score",
    f"{security_score}/100",
)

column2.metric(
    "High-Risk Rules",
    high_risk_rules,
)

column3.metric(
    "Public Exposures",
    public_exposures,
)

column4.metric(
    "Attack Blast Radius",
    f"{blast_radius}%",
)

# Navigation tabs.
(
    executive_tab,
    architecture_tab,
    iam_tab,
    simulation_tab,
    report_tab,
) = st.tabs(
    [
        "Executive View",
        "Architecture",
        "IAM",
        "Attack Simulation",
        "Client Report",
    ]
)

with executive_tab:
    st.subheader("Client Security Overview")

    if architecture_mode == "Proposed zero-trust design":
        st.success(
            "The proposed design uses identity verification, "
            "least privilege, network segmentation and central monitoring."
        )
    else:
        st.error(
            "The legacy network contains broad trust relationships "
            "that could allow an attack to spread."
        )

    st.markdown(
        """
        **Client objectives**

        - Give faculty secure access from home or campus.
        - Protect student and research information.
        - Prevent direct public access to internal databases.
        - Restrict communication between application layers.
        - Record important events in a central monitoring system.
        """
    )

with architecture_tab:
    st.subheader("Hybrid Network Security Policy")

    st.write(
        "Only the network connections listed below are permitted. "
        "All other traffic is denied by default."
    )
    st.subheader("Potential Attack Movement Map")

    network_diagram = create_network_diagram(
        selected_attack_edges,
        affected_systems,
        compromised_system,
    )

    st.plotly_chart(
        network_diagram,
        width="stretch",
        config={
            "displayModeBar": False,
        },
    )

    legend_column1, legend_column2, legend_column3 = st.columns(3)

    legend_column1.markdown(
        "🟠 **Compromised starting point**"
    )

    legend_column2.markdown(
        "🔴 **Potentially reachable**"
    )

    legend_column3.markdown(
        "🔵 **Currently isolated**"
    )

    st.caption(
        "Lines represent possible attack movement. "
        "Change the architecture or compromised system using the sidebar."
    )

    st.divider()

    secure_rules = [
        [
            "Internet",
            "DMZ Load Balancer",
            "TCP",
            "443",
            "Public HTTPS traffic",
            "Medium",
        ],
        [
            "Remote Faculty",
            "Zero-Trust Gateway",
            "TCP",
            "443",
            "Secure remote access with MFA",
            "Low",
        ],
        [
            "Admin Workstation",
            "Zero-Trust Gateway",
            "TCP",
            "443",
            "Approved administration",
            "Low",
        ],
        [
            "Zero-Trust Gateway",
            "Identity Service",
            "TCP",
            "443",
            "Identity verification",
            "Low",
        ],
        [
            "Zero-Trust Gateway",
            "DMZ Load Balancer",
            "TCP",
            "443",
            "Approved application access",
            "Low",
        ],
        [
            "DMZ Load Balancer",
            "On-Prem Application",
            "TCP",
            "8443",
            "Mutual TLS application traffic",
            "Medium",
        ],
        [
            "On-Prem Application",
            "Cloud API",
            "TCP",
            "443",
            "Signed service request",
            "Low",
        ],
        [
            "On-Prem Application",
            "Student Database",
            "TCP",
            "5432",
            "Dedicated service account",
            "Medium",
        ],
        [
            "On-Prem Application",
            "SIEM",
            "TCP",
            "6514",
            "Encrypted security logs",
            "Low",
        ],
    ]

    legacy_rules = [
        [
            "Internet",
            "On-Prem Application",
            "Any",
            "Any",
            "Legacy public access",
            "Critical",
        ],
        [
            "Internet",
            "Student Database",
            "TCP",
            "5432",
            "Accidental database exposure",
            "Critical",
        ],
        [
            "DMZ Load Balancer",
            "Student Database",
            "Any",
            "Any",
            "Over-permissive internal rule",
            "High",
        ],
        [
            "On-Prem Application",
            "Identity Service",
            "Any",
            "Any",
            "Unrestricted internal trust",
            "High",
        ],
        [
            "Student Database",
            "Cloud API",
            "Any",
            "Any",
            "Unrestricted outbound access",
            "High",
        ],
        [
            "Cloud API",
            "Identity Service",
            "Any",
            "Any",
            "Shared administrative access",
            "High",
        ],
        [
            "Remote Faculty",
            "Admin Workstation",
            "Any",
            "Any",
            "Flat internal network",
            "Critical",
        ],
    ]

    if architecture_mode == "Proposed zero-trust design":
        selected_rules = secure_rules

        st.success(
            "The proposed policy permits only required communication "
            "between specific application layers."
        )
    else:
        selected_rules = secure_rules + legacy_rules

        st.error(
            "The legacy policy contains public exposures, unrestricted "
            "ports and dangerous internal trust relationships."
        )

    policy_dataframe = pd.DataFrame(
        selected_rules,
        columns=[
            "Source",
            "Destination",
            "Protocol",
            "Port",
            "Business Purpose",
            "Risk",
        ],
    )

    st.dataframe(
        policy_dataframe,
        hide_index=True,
        width="stretch",
    )

    with st.expander("How to read this policy"):
        st.markdown(
            """
            - **Source:** The system that starts the connection.
            - **Destination:** The system receiving the connection.
            - **Protocol:** The communication type, such as TCP.
            - **Port:** The specific service opening.
            - **Business Purpose:** Why the connection is required.
            - **Risk:** The danger created by allowing that connection.
            - **Any/Any:** A dangerously broad rule that should be removed.
            """
        )

    st.caption(
        "Production implementation: translate these rows into cloud "
        "security groups, firewall rules and Kubernetes NetworkPolicies."
    )



with iam_tab:
    st.subheader("Identity and Access Management")

    st.write(
        "Each person receives only the permissions needed for their job. "
        "Sensitive access requires stronger authentication and expires automatically."
    )

    iam_data = [
        {
            "Role": "Faculty Member",
            "Allowed Resource": "Teaching applications",
            "Permitted Action": "View and submit content",
            "Authentication": "Password + MFA",
            "Access Duration": "Normal session",
        },
        {
            "Role": "Application Developer",
            "Allowed Resource": "Development namespace",
            "Permitted Action": "Deploy non-production applications",
            "Authentication": "Password + MFA",
            "Access Duration": "Normal session",
        },
        {
            "Role": "Network Engineer",
            "Allowed Resource": "VPC and security rules",
            "Permitted Action": "Create approved network rules",
            "Authentication": "Phishing-resistant MFA",
            "Access Duration": "Time-limited",
        },
        {
            "Role": "Kubernetes Engineer",
            "Allowed Resource": "Application namespaces",
            "Permitted Action": "Manage container workloads",
            "Authentication": "Password + MFA",
            "Access Duration": "Time-limited",
        },
        {
            "Role": "Security Analyst",
            "Allowed Resource": "SIEM and audit logs",
            "Permitted Action": "Read and investigate alerts",
            "Authentication": "Password + MFA",
            "Access Duration": "Normal session",
        },
        {
            "Role": "Cloud Administrator",
            "Allowed Resource": "Production cloud account",
            "Permitted Action": "Emergency administration",
            "Authentication": "Hardware security key",
            "Access Duration": "Dual-approved access",
        },
    ]

    iam_dataframe = pd.DataFrame(iam_data)

    st.dataframe(
        iam_dataframe,
        hide_index=True,
        width="stretch",
    )

    st.success(
        "Least privilege: faculty cannot administer infrastructure, "
        "developers cannot read production data, and administrators "
        "do not receive permanent unrestricted access."
    )

    st.warning(
        "Applications must use separate service identities. "
        "Human passwords must never be stored inside application code."
    )


with simulation_tab:
    st.subheader("Attack-Path Simulation")

    st.write(
        f"CampusShield is simulating an incident beginning at "
        f"**{compromised_system}**."
    )

    result_column1, result_column2, result_column3 = st.columns(3)

    result_column1.metric(
        "Potential Blast Radius",
        f"{blast_radius}%",
    )

    result_column2.metric(
        "Systems Potentially Affected",
        len(affected_systems),
    )

    result_column3.metric(
        "Architecture",
        (
            "Zero Trust"
            if architecture_mode == "Proposed zero-trust design"
            else "Legacy"
        ),
    )

    st.progress(
        blast_radius / 100,
        text="Potential attack propagation",
    )

    st.subheader("Affected Systems")

    system_zones = {
        "Internet": "External",
        "Remote Faculty": "User Access",
        "Admin Workstation": "Management",
        "Zero-Trust Gateway": "Security Gateway",
        "Identity Service": "Identity",
        "DMZ Load Balancer": "DMZ",
        "On-Prem Application": "Application",
        "Cloud API": "Public Cloud",
        "Student Database": "Restricted Data",
        "SIEM": "Monitoring",
    }

    affected_table = pd.DataFrame(
        [
            {
                "System": system,
                "Security Zone": system_zones[system],
                "Simulation Status": (
                    "Compromised Starting Point"
                    if system == compromised_system
                    else "Potentially Reachable"
                ),
            }
            for system in sorted(affected_systems)
        ]
    )

    st.dataframe(
        affected_table,
        hide_index=True,
        width="stretch",
    )

    if blast_radius == 0:
        st.success(
            "No additional systems are reachable from the selected "
            "starting point."
        )
    elif blast_radius <= 35:
        st.success(
            "The incident is reasonably contained by network "
            "segmentation and identity controls."
        )
    elif blast_radius <= 60:
        st.warning(
            "The incident has a moderate blast radius. "
            "Additional service isolation is recommended."
        )
    else:
        st.error(
            "The incident has a dangerous blast radius and may "
            "spread across multiple security zones."
        )

    st.subheader("Recommended Incident Response")

    st.markdown(
        f"""
        1. **Isolate {compromised_system}** from the network.
        2. Disable user and service credentials associated with the system.
        3. Search SIEM logs for unusual authentication and network activity.
        4. Review the network rules that enabled the attack path.
        5. Rotate affected application secrets and access keys.
        6. Check whether student or research information was accessed.
        7. Document the incident and obtain approval before restoring access.
        """
    )

    if architecture_mode == "Legacy flat network":
        st.warning(
            "Priority recommendation: replace broad Any/Any rules "
            "with specific sources, destinations and ports."
        )
    else:
        st.info(
            "Continue testing the design from different starting points "
            "to confirm that sensitive systems remain isolated."
        )

    with st.expander("Important simulation limitation"):
        st.write(
            "CampusShield models permitted network movement. "
            "It does not exploit vulnerabilities, inspect real traffic, "
            "or prove that a reachable system would be compromised."
        )

    st.caption(
        "This is a defensive architecture and decision-support prototype."
    )

    # Create a client-ready assessment report.
affected_system_lines = "\n".join(
    f"- {system}"
    for system in sorted(affected_systems)
)

report_markdown = f"""# CampusShield Security Assessment

**Client:** {client_name}  
**Assessment date:** {date.today().isoformat()}  
**Architecture evaluated:** {architecture_mode}  
**Simulated compromise:** {compromised_system}

## Executive Summary

CampusShield evaluated the client's hybrid data center security design,
identity controls, permitted network connections and potential attack paths.

The current simulation produced a security score of
**{security_score}/100** and a potential blast radius of
**{blast_radius}%**.

## Assessment Results

- High-risk network rules: {high_risk_rules}
- Public sensitive-system exposures: {public_exposures}
- Systems potentially affected: {len(affected_systems)}
- Selected starting point: {compromised_system}

## Potentially Affected Systems

{affected_system_lines}

## Recommended Security Controls

1. Require multi-factor authentication for faculty and administrators.
2. Validate identity and device condition before application access.
3. Keep student databases in private restricted-data subnets.
4. Remove unrestricted Any/Any network rules.
5. Allow communication only between explicitly approved systems and ports.
6. Give each application a separate service identity.
7. Use time-limited production administration.
8. Send authentication, application and network logs to a central SIEM.
9. Apply default-deny Kubernetes NetworkPolicies.
10. Test incident containment after every significant architecture change.

## Incident Response Priorities

1. Isolate the compromised system.
2. Disable related user and service credentials.
3. Review SIEM logs and cloud audit records.
4. Rotate exposed secrets and access keys.
5. Determine whether student or research data was accessed.
6. Document the incident and obtain approval before restoration.

## Production Implementation Mapping

- Security policy rows become cloud security groups and firewall rules.
- IAM table entries become cloud IAM roles and identity-provider groups.
- Zero-Trust Gateway represents identity-aware remote access.
- Application isolation becomes VPC, subnet and Kubernetes segmentation.
- SIEM connections represent centralized security logging and alerting.

## Important Limitation

CampusShield is an architecture decision-support prototype. It models
permitted network movement but does not perform exploitation, inspect real
traffic or replace a production security assessment.
"""


with report_tab:
    st.subheader("Client Security Assessment")

    st.write(
        "Review the generated assessment below, then download it "
        "for the client or interview presentation."
    )

    st.markdown(report_markdown)

    report_column1, report_column2 = st.columns(2)

    report_column1.download_button(
        label="Download Security Assessment",
        data=report_markdown,
        file_name="campusshield-security-assessment.md",
        mime="text/markdown",
        width="stretch",
    )

    policy_csv = policy_dataframe.to_csv(
        index=False
    )

    report_column2.download_button(
        label="Download Network Policy",
        data=policy_csv,
        file_name="campusshield-network-policy.csv",
        mime="text/csv",
        width="stretch",
    )

    st.success(
        "The assessment automatically updates when the architecture "
        "or compromised system changes."
    )