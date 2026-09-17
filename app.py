"""
app.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

Redesigned Interface:
Provides a professional CyberShield landing screen allowing users to choose
between URL analysis and Email analysis.

Architecture:
This UI module acts strictly as a presentation layer:
    - Renders the main CyberShield selection dashboard (render_home)
    - Renders the existing verified URL analyzer (render_url_analyzer)
    - Renders the placeholder structure for Email analysis (render_email_analyzer)

Verified Core Backend Modules (Unmodified):
    1. core/parser.py -> Static decomposition & RFC 3986 validation
    2. core/rules.py  -> 6 independent heuristic security checks
    3. core/risk.py   -> Deterministic weighted scoring & continuous categories

Safety Assurance:
Zero network traffic. All analysis evaluates input strings purely in memory.
"""

import streamlit as st

# Import the existing, verified core backend modules
from core.parser import parse_url
from core.rules import run_all_rules
from core.risk import calculate_risk_score, HEURISTIC_DISCLAIMER

# Import the Phase 2 email backend modules
from core.email_parser import parse_email
from core.email_rules import run_all_email_rules
from core.email_risk import calculate_email_risk_score, HEURISTIC_EMAIL_DISCLAIMER


# ------------------------------------------------------------------------------
# 1. Streamlit Page Configuration & Professional Styling
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield – Explainable Phishing URL & Email Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Professional Cybersecurity Dashboard Styling
st.markdown(
    """
    <style>
    /* Main container styling */
    .main-header {
        font-size: 2.4rem;
        font-weight: 800;
        color: #0f172a;
        margin-bottom: 0.2rem;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .sub-header {
        font-size: 1.18rem;
        color: #334155;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    .intro-text {
        font-size: 1.02rem;
        color: #64748b;
        margin-bottom: 1.5rem;
        line-height: 1.5;
    }
    .safety-badge {
        background-color: #f0fdf4;
        border-left: 4px solid #16a34a;
        padding: 12px 16px;
        border-radius: 6px;
        color: #166534;
        font-size: 0.92rem;
        margin-bottom: 1.5rem;
    }
    
    /* Mode Selection Cards */
    .mode-card {
        background: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 12px;
        padding: 24px;
        min-height: 170px;
        margin-bottom: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .mode-card:hover {
        border-color: #3b82f6;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.08);
    }
    .mode-card-title {
        font-size: 1.35rem;
        font-weight: 700;
        color: #0f172a;
        margin-bottom: 6px;
    }
    .mode-card-subtitle {
        font-size: 1rem;
        font-weight: 600;
        color: #1e293b;
        margin-bottom: 8px;
        line-height: 1.4;
    }
    .mode-card-desc {
        font-size: 0.9rem;
        color: #64748b;
        line-height: 1.45;
    }

    /* Result card styling */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .rule-card {
        background-color: #fffaf0;
        border-left: 4px solid #dd6b20;
        padding: 14px 18px;
        border-radius: 6px;
        margin-bottom: 12px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.04);
    }
    .rule-card-title {
        font-weight: 700;
        color: #9c4221;
        font-size: 1.05rem;
    }
    .rule-evidence {
        font-family: monospace;
        background: #f7fafc;
        padding: 3px 6px;
        border-radius: 4px;
        border: 1px solid #e2e8f0;
        color: #2d3748;
    }
    .pipeline-step {
        background: #f8fafc;
        border: 1px solid #cbd5e1;
        padding: 10px 14px;
        border-radius: 6px;
        font-size: 0.95rem;
        margin-bottom: 8px;
    }
    .disclaimer-box {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-left: 4px solid #64748b;
        padding: 14px 18px;
        border-radius: 6px;
        font-size: 0.88rem;
        color: #475569;
        margin-top: 1.5rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------------------------
# 2. Sidebar Navigation & Contextual Info
# ------------------------------------------------------------------------------
def render_sidebar():
    """Renders contextual sidebar content based on the active analysis mode."""
    with st.sidebar:
        st.markdown("### 🛡️ About CyberShield")
        st.write(
            "CyberShield is an **explainable cybersecurity analyzer** designed "
            "to examine suspicious digital content using transparent, rule-based security checks."
        )
        st.markdown("---")

        current_mode = st.session_state.get("analysis_mode", "home")

        if current_mode != "home":
            if st.button("← Back to Analysis Selection", key="sidebar_back_btn", use_container_width=True):
                st.session_state.analysis_mode = "home"
                st.rerun()
            st.markdown("---")

        if current_mode == "home":
            st.markdown("### 📌 Available Modes")
            st.markdown("• **🔗 URL Analyzer:** Active & Verified")
            st.markdown("• **📧 Email Analyzer:** Module in Preparation")
            st.markdown("---")
            st.markdown("### 🔒 Safe Static Guarantee")
            st.caption(
                "All analyses evaluate text syntax entirely in memory. CyberShield never connects "
                "to external servers, executes code, or visits target websites."
            )

        elif current_mode == "url":
            st.markdown("### 🔄 URL Analysis Pipeline")
            st.markdown(
                """
                <div class="pipeline-step"><b>1. URL Input</b><br><small>Raw string entered by analyst</small></div>
                <div class="pipeline-step"><b>2. URL Parsing</b><br><small>Static decomposition via <code>parser.py</code></small></div>
                <div class="pipeline-step"><b>3. Heuristic Detection</b><br><small>6 isolated checks via <code>rules.py</code></small></div>
                <div class="pipeline-step"><b>4. Risk Scoring</b><br><small>Weighted model (0–100) via <code>risk.py</code></small></div>
                <div class="pipeline-step"><b>5. Explainable Report</b><br><small>Transparent findings with evidence</small></div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown("---")

            st.markdown("### 📐 Continuous Risk Tiers")
            st.markdown("• **0 – 20:** Low Concern (🟢)")
            st.markdown("• **21 – 59:** Review Recommended (🟠)")
            st.markdown("• **60 – 100:** Higher Concern (🔴)")
            st.markdown("---")

            st.markdown("### ⚠️ Key Limitations")
            st.markdown(
                """
                - **No Network Visits:** CyberShield does not connect to target servers or fetch HTML/JS.
                - **No Live Malware Execution:** Does not scan runtime page behavior.
                - **Heuristic Indicators:** Scores reflect structural anomalies, not proof of malicious intent.
                - **No Probability Claims:** The score is not an AI probability percentage.
                - **False Positives/Negatives:** Both are possible in heuristic systems.
                """
            )

        elif current_mode == "email":
            st.markdown("### 🔄 Email Analysis Pipeline")
            st.markdown(
                """
                <div class="pipeline-step"><b>1. Email Input</b><br><small>Sender, subject & body text</small></div>
                <div class="pipeline-step"><b>2. Decomposition</b><br><small>Static parsing via <code>email_parser.py</code></small></div>
                <div class="pipeline-step"><b>3. URL Correlation</b><br><small>Embedded URLs verified via URL engine</small></div>
                <div class="pipeline-step"><b>4. Heuristic Detection</b><br><small>10 security rules via <code>email_rules.py</code></small></div>
                <div class="pipeline-step"><b>5. Risk Scoring</b><br><small>Weighted model (0–100) via <code>email_risk.py</code></small></div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown("---")

            st.markdown("### 📐 Continuous Risk Tiers")
            st.markdown("• **0 – 20:** Low Concern (🟢)")
            st.markdown("• **21 – 59:** Review Recommended (🟠)")
            st.markdown("• **60 – 100:** Higher Concern (🔴)")
            st.markdown("---")

            st.markdown("### ⚠️ Key Limitations")
            st.markdown(
                """
                - **No Mail Server Access:** Evaluates text purely in memory.
                - **No URL Visits:** Embedded links are parsed statically, never visited.
                - **No Attachment Execution:** Scans text for filename extensions only.
                - **Heuristic Indicators:** High score indicates structural risk, not proof of malice.
                """
            )


# ------------------------------------------------------------------------------
# 3. Mode 1: CyberShield Landing / Dashboard Screen (Home)
# ------------------------------------------------------------------------------
def render_home():
    """
    Renders the primary CyberShield landing screen allowing users
    to choose between URL Analyzer and Email Analyzer.
    """
    st.markdown('<div class="main-header">🛡️ CyberShield</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Explainable Phishing URL & Email Security Analyzer</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="intro-text">Choose an analysis mode to examine suspicious digital content using transparent, rule-based security checks.</div>',
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.markdown(
            """
            <div class="mode-card">
                <div class="mode-card-title">🔗 URL ANALYZER</div>
                <div class="mode-card-subtitle">Analyze a suspicious URL using explainable security indicators.</div>
                <div class="mode-card-desc">
                    Decomposes URL structures statically (RFC 3986) to inspect for unencrypted protocols, 
                    raw IP hostnames, @ symbol spoofing, length anomalies, and suspicious patterns.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Choose URL Analyzer", use_container_width=True, key="btn_choose_url"):
            st.session_state.analysis_mode = "url"
            st.rerun()

    with col2:
        st.markdown(
            """
            <div class="mode-card">
                <div class="mode-card-title">📧 EMAIL ANALYZER</div>
                <div class="mode-card-subtitle">Analyze a suspicious email for phishing-related indicators.</div>
                <div class="mode-card-desc">
                    Examines email sender domains, urgency cues, manipulative social engineering 
                    tactics, and deceptive phishing indicators in message headers and bodies.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Choose Email Analyzer", use_container_width=True, key="btn_choose_email"):
            st.session_state.analysis_mode = "email"
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class="safety-badge">
            🔒 <b>Safe Static Inspection:</b> CyberShield evaluates structural indicators purely in memory. 
            It never visits target websites, resolves DNS records, or makes external network connections.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------------------
# 4. Mode 2: Existing URL Security Analyzer
# ------------------------------------------------------------------------------
def render_url_analyzer():
    """
    Renders the complete, unmodified URL Security Analyzer interface.
    Preserves all existing functionality, test presets, and core analysis logic.
    """
    col_back, _ = st.columns([2.5, 7.5])
    with col_back:
        if st.button("← Back to Analysis Selection", key="back_from_url"):
            st.session_state.analysis_mode = "home"
            st.rerun()

    st.markdown('<div class="main-header">🛡️ CyberShield – URL Analyzer</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Explainable Phishing URL Security Analyzer — '
        'Analyze suspicious URL structures without visiting the target website.</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="safety-badge">
            🔒 <b>Safe Static Mode Active:</b> This tool evaluates the syntactic structure of URL strings 
            entirely in memory. It <b>never</b> visits the URL, sends HTTP requests, resolves DNS records, 
            or contacts external APIs.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Safe Test Examples
    if "input_url" not in st.session_state:
        st.session_state.input_url = "https://example.com/login"

    st.markdown("#### 🧪 Safe Test Scenarios")
    st.caption("Click any preset to insert sample text into the analysis field:")

    col_ex1, col_ex2, col_ex3, col_ex4 = st.columns(4)

    with col_ex1:
        if st.button("🌐 Normal HTTPS", use_container_width=True):
            st.session_state.input_url = "https://www.google.com/search?q=cybersecurity"

    with col_ex2:
        if st.button("⚠️ Unencrypted HTTP", use_container_width=True):
            st.session_state.input_url = "http://example.com/login"

    with col_ex3:
        if st.button("🚨 Raw IP Hostname", use_container_width=True):
            st.session_state.input_url = "http://192.168.1.1/admin"

    with col_ex4:
        if st.button("🎯 @ Symbol Spoof", use_container_width=True):
            st.session_state.input_url = "http://paypal.com@verify-account-update.xyz/login.php"

    # Input Field & Controls
    st.markdown("---")
    st.markdown("### 🔎 URL Analysis Workspace")

    url_input = st.text_input(
        label="Enter or paste a URL string to analyze:",
        value=st.session_state.input_url,
        placeholder="https://example.com/login",
        help="Supports standard URLs, schemeless domains, and defanged indicators (e.g. hxxps://example[.]com).",
    )

    btn_col1, btn_col2, _ = st.columns([1.2, 1.2, 4])

    with btn_col1:
        analyze_clicked = st.button("🚀 Analyze URL", type="primary", use_container_width=True)

    with btn_col2:
        if st.button("🔄 Clear Input", use_container_width=True):
            st.session_state.input_url = ""
            st.rerun()

    # Pipeline Execution & Results Presentation
    if analyze_clicked or (url_input and url_input.strip()):
        if not url_input or not url_input.strip():
            st.warning("⚠️ Please enter a URL string to begin analysis.")
        else:
            # Step A: Parse URL via core/parser.py
            parsed = parse_url(url_input)

            # Handle parser error gracefully (malformed syntax, illegal port, etc.)
            if not parsed.get("is_valid", False):
                st.error(
                    f"❌ **Invalid URL Structure:** {parsed.get('error_message', 'Could not parse URL.')}"
                )
                st.caption("Please check the input syntax. Analysis stopped at the parser validation stage.")

            else:
                # Step B: Run 6 Heuristic Detection Rules via core/rules.py
                rule_findings = run_all_rules(parsed)

                # Step C: Compute Weighted Risk Score via core/risk.py
                assessment = calculate_risk_score(rule_findings)

                score = assessment["total_score"]
                max_score = assessment["max_score"]
                category = assessment["category"]
                cat_description = assessment["category_description"]
                triggered_rules = assessment["triggered_rules"]

                st.markdown("---")
                st.markdown("## 📊 Security Assessment Report")

                # Primary Metrics Row
                m_col1, m_col2, m_col3 = st.columns([1, 1.5, 1.2])

                with m_col1:
                    st.metric(label="Risk Score", value=f"{score} / {max_score}")

                with m_col2:
                    if category == "Low Concern":
                        badge = "🟢 Low Concern"
                    elif category == "Review Recommended":
                        badge = "🟠 Review Recommended"
                    else:
                        badge = "🔴 Higher Concern"

                    st.metric(label="Assessed Category", value=badge)

                with m_col3:
                    st.metric(label="Triggered Indicators", value=f"{len(triggered_rules)} of 6")

                # Visual Progress Bar & Continuous Scale
                st.markdown("##### Continuous Risk Scale Position")
                st.progress(score / 100.0)

                scale_col1, scale_col2, scale_col3 = st.columns(3)
                with scale_col1:
                    st.caption("🟢 **0 – 20:** Low Concern")
                with scale_col2:
                    st.caption("🟠 **21 – 59:** Review Recommended")
                with scale_col3:
                    st.caption("🔴 **60 – 100:** Higher Concern")

                # Explanation of Category
                if category == "Low Concern":
                    st.success(f"**Assessment Interpretation:** {cat_description}")
                elif category == "Review Recommended":
                    st.warning(f"**Assessment Interpretation:** {cat_description}")
                else:
                    st.error(f"**Assessment Interpretation:** {cat_description}")

                # Section: Triggered Indicators Breakdown
                st.markdown("### ⚠️ Triggered Security Indicators")

                if triggered_rules:
                    for rule in triggered_rules:
                        r_name = rule["rule_name"]
                        r_pts = rule["points_contributed"]
                        r_evid = rule["evidence"]
                        r_expl = rule["explanation"]

                        st.markdown(
                            f"""
                            <div class="rule-card">
                                <div class="rule-card-title">• {r_name} (+{r_pts} pts)</div>
                                <div style="margin-top: 6px; color: #2d3748;">
                                    <b>Observed Evidence:</b> <span class="rule-evidence">{r_evid}</span>
                                </div>
                                <div style="margin-top: 6px; color: #4a5568; font-size: 0.92rem;">
                                    <b>Security Implication:</b> {r_expl}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                else:
                    st.success(
                        "✅ **No suspicious heuristic indicators triggered.** "
                        "The URL structure conforms to standard web patterns."
                    )

                # Section: Passed Checks Overview
                safe_rules = [r for r in rule_findings if not r["triggered"]]
                with st.expander(f"✅ View Passed Checks ({len(safe_rules)} of 6 passed)"):
                    for s_rule in safe_rules:
                        st.markdown(
                            f"• **{s_rule['rule_name']}:** {s_rule['explanation']} (`+0 pts`)"
                        )

                # Section: Parsed Components Inspection (RFC 3986)
                with st.expander("🔍 View Parsed URL Components (RFC 3986)"):
                    st.caption("These components were decomposed purely statically by `core/parser.py`:")
                    comp_col1, comp_col2 = st.columns(2)

                    with comp_col1:
                        st.write(f"**Scheme (Protocol):** `{parsed.get('scheme')}`")
                        st.write(f"**Hostname / Domain:** `{parsed.get('hostname')}`")
                        st.write(f"**Network Port:** `{parsed.get('port') or 'Default (80/443)'}`")
                        st.write(f"**Defanged Input Detected?:** `{parsed.get('is_defanged', False)}`")

                    with comp_col2:
                        st.write(f"**Path:** `{parsed.get('path')}`")
                        st.write(f"**Query Parameters:** `{parsed.get('query') or 'None'}`")
                        st.write(f"**Fragment Anchor:** `{parsed.get('fragment') or 'None'}`")
                        st.write(f"**Full Authority (netloc):** `{parsed.get('netloc')}`")

                # Section: Mandatory Security Disclaimer & Limitations
                st.markdown(
                    f"""
                    <div class="disclaimer-box">
                        🛡️ <b>Security Disclaimer & Ethical Use Notice:</b><br>
                        {HEURISTIC_DISCLAIMER}
                        CyberShield is designed as an explainable heuristic triage aid. 
                        A low score does not guarantee that a destination is safe, and a higher score 
                        reflects anomalous structural patterns rather than conclusive proof of malice.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


# ------------------------------------------------------------------------------
# 5. Mode 3: Email Phishing Analyzer (Phase 3 Presentation Layer)
# ------------------------------------------------------------------------------
def render_email_analyzer():
    """
    Renders the complete Email Phishing Analyzer interface.
    Connects to core/email_parser.py, core/email_rules.py, and core/email_risk.py,
    and correlates extracted URLs with the existing URL security analyzer.
    """
    col_back, _ = st.columns([2.5, 7.5])
    with col_back:
        if st.button("← Back to Analysis Selection", key="back_from_email"):
            st.session_state.analysis_mode = "home"
            st.rerun()

    st.markdown('<div class="main-header">📧 Email Phishing Analyzer</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Analyze suspicious email content using transparent, rule-based security indicators.</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="safety-badge">
            🔒 <b>Safe Static Mode Active:</b> This tool evaluates email text purely in memory. 
            It <b>never</b> connects to mail servers, downloads attachments, contacts external APIs, 
            or visits links found inside the text.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Initialize Session State for Email Inputs
    if "email_sender" not in st.session_state:
        st.session_state.email_sender = "support@example.com"
    if "email_subject" not in st.session_state:
        st.session_state.email_subject = "Meeting Reminder"
    if "email_body" not in st.session_state:
        st.session_state.email_body = (
            "Hello,\n"
            "This is a reminder about our meeting tomorrow.\n"
            "Please review the agenda before the meeting."
        )

    # Safe Email Test Scenarios matching specification
    st.markdown("#### 🧪 Safe Test Scenarios")
    st.caption("Click any preset to load synthetic sample email text:")

    col_e1, col_e2, col_e3, col_e4 = st.columns(4)

    with col_e1:
        if st.button("📝 TEST 1: Normal Email", use_container_width=True):
            st.session_state.email_sender = "support@example.com"
            st.session_state.email_subject = "Meeting Reminder"
            st.session_state.email_body = (
                "Hello,\n"
                "This is a reminder about our meeting tomorrow.\n"
                "Please review the agenda before the meeting."
            )
            st.rerun()

    with col_e2:
        if st.button("🚨 TEST 2: Urgent Account", use_container_width=True):
            st.session_state.email_sender = "support@example.com"
            st.session_state.email_subject = "URGENT: Verify Your Account"
            st.session_state.email_body = (
                "Your account will be suspended immediately.\n"
                "Please verify your password now."
            )
            st.rerun()

    with col_e3:
        if st.button("🔗 TEST 3: Email With URL", use_container_width=True):
            st.session_state.email_sender = "security@example.com"
            st.session_state.email_subject = "Security Verification"
            st.session_state.email_body = (
                "Please verify your account using:\n"
                "https://example.com/login"
            )
            st.rerun()

    with col_e4:
        if st.button("⚠️ TEST 4: Multiple Flags", use_container_width=True):
            st.session_state.email_sender = "security@example.com"
            st.session_state.email_subject = "FINAL WARNING!!!"
            st.session_state.email_body = (
                "Dear customer,\n"
                "Your account will be suspended immediately.\n"
                "Verify your password and OTP now.\n"
                "Payment verification is required.\n"
                "Click the link below:\n"
                "http://192.168.1.1/login"
            )
            st.rerun()

    # Input Fields
    st.markdown("---")
    st.markdown("### 📥 Email Input")

    sender_input = st.text_input(
        label="Sender Email:",
        value=st.session_state.email_sender,
        placeholder="e.g. support@example.com or Support Team <support@example.com>",
        help="Optional: The sender email address or display name.",
    )

    subject_input = st.text_input(
        label="Subject:",
        value=st.session_state.email_subject,
        placeholder="e.g. Urgent: Account Verification Required",
        help="The subject line of the email.",
    )

    body_input = st.text_area(
        label="Email Body:",
        value=st.session_state.email_body,
        placeholder="Paste the email content, greetings, body text, or links here...",
        height=180,
        help="The plain text content of the email.",
    )

    btn_col1, btn_col2, _ = st.columns([1.5, 1.2, 4])

    with btn_col1:
        analyze_email_clicked = st.button("🔍 Analyze Email", type="primary", use_container_width=True)

    with btn_col2:
        if st.button("🔄 Clear Input", key="clear_email_btn", use_container_width=True):
            st.session_state.email_sender = ""
            st.session_state.email_subject = ""
            st.session_state.email_body = ""
            st.rerun()

    # Pipeline Execution & Results Presentation
    has_input = bool(
        (sender_input and sender_input.strip())
        or (subject_input and subject_input.strip())
        or (body_input and body_input.strip())
    )

    if analyze_email_clicked or has_input:
        # Check for completely empty input
        if not has_input:
            st.warning("⚠️ Please provide email content (sender, subject, or body) to begin analysis.")
            return

        try:
            # Step A: Parse email text via core/email_parser.py
            parsed_email = parse_email(sender_input, subject_input, body_input)

            if not parsed_email.get("is_valid", False):
                st.warning("⚠️ " + parsed_email.get("error_message", "Please enter email content to begin analysis."))
                return

            # Step B: Analyze each extracted URL using the EXISTING CyberShield URL Analyzer
            # Zero network traffic: Purely static string evaluation via core/parser.py -> core/rules.py -> core/risk.py
            analyzed_urls = []
            for raw_url in parsed_email.get("extracted_urls", []):
                parsed_u = parse_url(raw_url)
                if parsed_u.get("is_valid", False):
                    u_rules = run_all_rules(parsed_u)
                    u_assessment = calculate_risk_score(u_rules)
                    analyzed_urls.append({
                        "raw_url": raw_url,
                        "parsed": parsed_u,
                        "total_score": u_assessment["total_score"],
                        "max_score": u_assessment["max_score"],
                        "category": u_assessment["category"],
                        "triggered_rules": u_assessment["triggered_rules"],
                    })
                else:
                    analyzed_urls.append({
                        "raw_url": raw_url,
                        "parsed": parsed_u,
                        "total_score": 0,
                        "max_score": 100,
                        "category": "Invalid URL Structure",
                        "triggered_rules": [],
                    })

            # Step C: Evaluate 10 Email Security Rules via core/email_rules.py
            rule_findings = run_all_email_rules(parsed_email, analyzed_urls)

            # Step D: Compute Weighted Risk Score via core/email_risk.py
            assessment = calculate_email_risk_score(rule_findings, analyzed_urls)

            score = assessment["total_score"]
            max_score = assessment["max_score"]
            category = assessment["category"]
            cat_description = assessment["category_description"]
            triggered_rules = assessment["triggered_rules"]

            st.markdown("---")
            st.markdown("## 📊 Email Risk Assessment")

            # Primary Metrics Row
            m_col1, m_col2, m_col3 = st.columns([1, 1.5, 1.2])

            with m_col1:
                st.metric(label="Risk Score", value=f"{score} / {max_score}")

            with m_col2:
                if category == "Low Concern":
                    badge = "🟢 Low Concern"
                elif category == "Review Recommended":
                    badge = "🟠 Review Recommended"
                else:
                    badge = "🔴 Higher Concern"

                st.metric(label="Category", value=badge)

            with m_col3:
                st.metric(label="Triggered Indicators", value=f"{len(triggered_rules)} of 10")

            # Visual Progress Bar & Continuous Scale
            st.markdown("##### Continuous Risk Scale Position")
            st.progress(score / 100.0)

            scale_col1, scale_col2, scale_col3 = st.columns(3)
            with scale_col1:
                st.caption("🟢 **0 – 20:** Low Concern")
            with scale_col2:
                st.caption("🟠 **21 – 59:** Review Recommended")
            with scale_col3:
                st.caption("🔴 **60 – 100:** Higher Concern")

            # Category Interpretation
            if category == "Low Concern":
                st.success(f"**Assessment Interpretation:** {cat_description}")
            elif category == "Review Recommended":
                st.warning(f"**Assessment Interpretation:** {cat_description}")
            else:
                st.error(f"**Assessment Interpretation:** {cat_description}")

            # ------------------------------------------------------------------
            # Section: Combined Result Breakdown (Email Indicators vs URL Indicators)
            # ------------------------------------------------------------------
            st.markdown("### 📑 Combined Risk Score Breakdown")
            
            # Aggregate URL-level indicators across all extracted URLs
            url_indicators_list = []
            for u_entry in analyzed_urls:
                for tr in u_entry.get("triggered_rules", []):
                    url_indicators_list.append({
                        "url": u_entry["raw_url"],
                        "rule_name": tr["rule_name"],
                        "points": tr["points_contributed"],
                        "evidence": tr["evidence"],
                    })

            brk_col1, brk_col2 = st.columns(2)

            with brk_col1:
                st.markdown("##### 📧 Email Indicators Contributed:")
                if triggered_rules:
                    for r in triggered_rules:
                        st.markdown(f"• **{r['rule_name']}**: `+{r['points_contributed']} pts`")
                else:
                    st.caption("• None (0 pts)")

            with brk_col2:
                st.markdown("##### 🔗 URL Indicators (from Embedded Links):")
                if url_indicators_list:
                    for u_ind in url_indicators_list:
                        st.markdown(f"• **{u_ind['rule_name']}**: `+{u_ind['points']} pts` (*{u_ind['url']}*)")
                else:
                    st.caption("• None (0 pts)")

            st.caption(
                f"**Overall Risk Calculation:** Total points accumulated are deterministically evaluated "
                f"and strictly clamped to a maximum of 100 (`{score} / 100`). "
                "Email and URL indicators are clearly separated to prevent duplicate inflation."
            )

            # ------------------------------------------------------------------
            # Section: Triggered Indicators Cards
            # ------------------------------------------------------------------
            st.markdown("### ⚠️ Triggered Email Indicators")

            if triggered_rules:
                for rule in triggered_rules:
                    r_name = rule["rule_name"]
                    r_pts = rule["points_contributed"]
                    r_evid = rule["evidence"]
                    r_expl = rule["explanation"]

                    st.markdown(
                        f"""
                        <div class="rule-card">
                            <div class="rule-card-title">⚠️ {r_name} (+{r_pts} points)</div>
                            <div style="margin-top: 6px; color: #2d3748;">
                                <b>Evidence:</b> <span class="rule-evidence">{r_evid}</span>
                            </div>
                            <div style="margin-top: 6px; color: #4a5568; font-size: 0.92rem;">
                                <b>Reason:</b> {r_expl}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.success(
                    "✅ **No suspicious heuristic email indicators triggered.** "
                    "The email content conforms to standard communication conventions."
                )

            # ------------------------------------------------------------------
            # Section: Extracted URLs Section
            # ------------------------------------------------------------------
            st.markdown("### 🔗 Extracted URLs")
            if analyzed_urls:
                st.caption(
                    f"Discovered **{len(analyzed_urls)} embedded link(s)**. "
                    "Each URL was evaluated purely statically through the CyberShield URL Analyzer without network connections:"
                )
                for u_data in analyzed_urls:
                    u_url = u_data["raw_url"]
                    u_score = u_data["total_score"]
                    u_cat = u_data["category"]
                    u_trig = u_data.get("triggered_rules", [])

                    badge_color = "🟢" if u_score <= 20 else ("🟠" if u_score <= 59 else "🔴")
                    with st.container():
                        st.markdown(
                            f"""
                            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 10px;">
                                <div style="font-weight: 700; color: #0f172a; word-break: break-all;">
                                    {badge_color} <span style="font-family: monospace;">{u_url}</span>
                                </div>
                                <div style="margin-top: 6px; color: #475569; font-size: 0.92rem;">
                                    <b>URL Score:</b> {u_score} / 100 &nbsp;|&nbsp; 
                                    <b>Category:</b> {u_cat} &nbsp;|&nbsp; 
                                    <b>Triggered URL Checks:</b> {len(u_trig)} of 6
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        if u_trig:
                            for tr in u_trig:
                                st.caption(f"&nbsp;&nbsp;&nbsp;&nbsp;• **{tr['rule_name']} (+{tr['points_contributed']} pts):** {tr['evidence']}")
                        else:
                            st.caption("&nbsp;&nbsp;&nbsp;&nbsp;• *No suspicious URL indicators triggered (Low Concern)*")
            else:
                st.info("ℹ️ No embedded URLs were detected within the email subject or body text.")

            # ------------------------------------------------------------------
            # Section: Parsed Email Information (Expander)
            # ------------------------------------------------------------------
            with st.expander("📄 Parsed Email Information"):
                st.caption("Statically extracted and normalized components via `core/email_parser.py`:")
                info_col1, info_col2 = st.columns(2)

                with info_col1:
                    st.write(f"**Sender:** `{parsed_email.get('sender') or 'None (Omitted)'}`")
                    st.write(f"**Sender Domain:** `{parsed_email.get('sender_domain') or 'None'}`")
                    st.write(f"**Subject:** `{parsed_email.get('subject') or 'None'}`")

                with info_col2:
                    st.write(f"**Number of Extracted URLs:** `{parsed_email.get('url_count', 0)}`")
                    st.write(f"**Email Body Character Count:** `{len(parsed_email.get('body', ''))} characters`")
                    st.write(f"**Email Body Word Count:** `{parsed_email.get('basic_stats', {}).get('word_count', 0)} words`")

            # ------------------------------------------------------------------
            # Section: Passed Checks (Expander)
            # ------------------------------------------------------------------
            safe_email_rules = [r for r in rule_findings if not r["triggered"]]
            with st.expander(f"✅ Passed Checks ({len(safe_email_rules)} of 10 passed)"):
                st.caption("These rules evaluated the email content and passed without triggering indicators:")
                for s_rule in safe_email_rules:
                    st.markdown(
                        f"• **{s_rule['rule_name']}:** {s_rule['explanation']} (`+0 pts`)"
                    )

            # ------------------------------------------------------------------
            # Section: Security Disclaimer
            # ------------------------------------------------------------------
            st.markdown(
                f"""
                <div class="disclaimer-box">
                    🛡️ <b>Security Disclaimer & Ethical Use Notice:</b><br>
                    {HEURISTIC_EMAIL_DISCLAIMER}
                    CyberShield evaluates syntactic and lexical indicators purely as text in memory. 
                    It does not connect to mail servers, resolve DNS records, or scan live mailbox sessions.
                </div>
                """,
                unsafe_allow_html=True,
            )

        except Exception:
            st.error("❌ An error occurred during email analysis. Please verify your input text.")


# ------------------------------------------------------------------------------
# 6. Main Application Router
# ------------------------------------------------------------------------------
def main():
    if "analysis_mode" not in st.session_state:
        st.session_state.analysis_mode = "home"

    # Contextual Sidebar
    render_sidebar()

    # Route based on selected analysis mode
    if st.session_state.analysis_mode == "url":
        render_url_analyzer()
    elif st.session_state.analysis_mode == "email":
        render_email_analyzer()
    else:
        render_home()


if __name__ == "__main__":
    main()
