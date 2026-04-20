THEME = {
    "color": "#FFD700",
    "accent": "#FF6B00",
    "bg": "#0C0A04",
    "panel": "#13100A",
    "border": "#2A2200",
    "muted": "#6B5C00",
    "success": "#4CAF50",
    "warning": "#FF9800",
    "danger": "#F44336",
    "text": "#E8D48A",
}

CSS = """
<style>
/* === GLOBAL BACKGROUND === */
.stApp, .stApp > header, section[data-testid="stSidebar"] {
    background-color: #0C0A04 !important;
}

/* === SIDEBAR === */
section[data-testid="stSidebar"] {
    background-color: #13100A !important;
    border-right: 1px solid #2A2200 !important;
}

/* === MAIN CONTENT AREA === */
.block-container {
    background-color: #0C0A04 !important;
    padding: 2rem 2rem 2rem !important;
}

/* === ALL TEXT === */
h1, h2, h3, h4, h5, h6, label, p, span, div {
    color: #E8D48A !important;
}

/* === PRIMARY HEADINGS === */
h1 { color: #FFD700 !important; font-size: 2rem !important; font-weight: 700 !important; }
h2 { color: #FFD700 !important; font-size: 1.4rem !important; }
h3 { color: #E8D48A !important; font-size: 1.1rem !important; }

/* === CARDS / METRIC CONTAINERS === */
[data-testid="stMetricValue"] { color: #FFD700 !important; font-size: 2.2rem !important; font-weight: 700 !important; }
[data-testid="stMetricLabel"] { color: #6B5C00 !important; font-size: 0.8rem !important; }
[data-testid="stMetricDelta"] { color: #FF6B00 !important; }

/* === BUTTONS === */
.stButton > button {
    background-color: #2A2200 !important;
    color: #FFD700 !important;
    border: 1px solid #FFD700 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    transition: all 0.2s ease;
}
.stButton > button:hover {
    background-color: #FFD700 !important;
    color: #0C0A04 !important;
}

/* === PRIMARY BUTTON (accent) === */
.stButton > button[kind="primary"] {
    background-color: #FF6B00 !important;
    color: #0C0A04 !important;
    border: none !important;
}

/* === FILE UPLOADER === */
[data-testid="stFileUploader"] {
    background-color: #13100A !important;
    border: 2px dashed #2A2200 !important;
    border-radius: 8px !important;
}

/* === DATAFRAME / TABLE === */
[data-testid="stDataFrame"] { background-color: #13100A !important; }
.dvn-scroller { background-color: #13100A !important; }

/* === SELECTBOX / INPUT === */
.stSelectbox > div, .stTextInput > div > input, .stNumberInput > div > input {
    background-color: #13100A !important;
    border-color: #2A2200 !important;
    color: #E8D48A !important;
}

/* === TABS === */
.stTabs [role="tab"] { color: #6B5C00 !important; background: transparent !important; border-bottom: 2px solid transparent !important; }
.stTabs [role="tab"][aria-selected="true"] { color: #FFD700 !important; border-bottom: 2px solid #FFD700 !important; }

/* === EXPANDER === */
.streamlit-expanderHeader { background-color: #13100A !important; color: #FFD700 !important; border: 1px solid #2A2200 !important; border-radius: 6px !important; }

/* === PROGRESS BAR === */
.stProgress > div > div { background-color: #FF6B00 !important; }

/* === DIVIDER === */
hr { border-color: #2A2200 !important; }

/* === SIDEBAR NAV ITEMS === */
[data-testid="stSidebarNavLink"] { color: #E8D48A !important; }
[data-testid="stSidebarNavLink"]:hover { color: #FFD700 !important; background: #2A2200 !important; }

/* === BADGE / TAG COMPONENT (custom HTML) === */
.risk-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}
.risk-high   { background: #3B0000; color: #F44336; border: 1px solid #F44336; }
.risk-medium { background: #2A1500; color: #FF9800; border: 1px solid #FF9800; }
.risk-low    { background: #001A00; color: #4CAF50; border: 1px solid #4CAF50; }

/* === CARD COMPONENT (custom HTML) === */
.dna-card {
    background: #13100A;
    border: 1px solid #2A2200;
    border-radius: 10px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 1rem;
}
.dna-card:hover { border-color: #FFD700; transition: border-color 0.2s; }
.dna-card .card-title { color: #FFD700; font-size: 1rem; font-weight: 700; margin-bottom: 0.3rem; }
.dna-card .card-sub   { color: #6B5C00; font-size: 0.8rem; }
.dna-card .card-val   { color: #FF6B00; font-size: 1.5rem; font-weight: 700; }

/* === EXPOSURE SCORE RING (custom HTML) === */
.score-ring {
    width: 120px; height: 120px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 2rem; font-weight: 800;
    margin: 0 auto;
}
.score-low    { border: 6px solid #4CAF50; color: #4CAF50; background: #001A00; }
.score-medium { border: 6px solid #FF9800; color: #FF9800; background: #2A1500; }
.score-high   { border: 6px solid #F44336; color: #F44336; background: #3B0000; }
</style>
"""


def apply_theme(st):
    st.markdown(CSS, unsafe_allow_html=True)
