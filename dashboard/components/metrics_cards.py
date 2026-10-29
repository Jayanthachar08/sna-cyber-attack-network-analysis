"""
Metrics Cards and UI styling helper for the Streamlit cybersecurity dashboard.
"""

from typing import Any
import streamlit as st


def apply_custom_css():
    """Apply modern dark slate cybersecurity theme styling."""
    st.markdown("""
    <style>
    /* Global Styles */
    .stApp {
        background-color: #0e1117;
        color: #e0e6ed;
    }
    
    /* Metrics Card */
    .metric-container {
        background: linear-gradient(135deg, #1a1f2c 0%, #131722 100%);
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .metric-label {
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
        line-height: 1.2;
    }
    .metric-sub {
        font-size: 0.78rem;
        color: #64748b;
        margin-top: 4px;
    }
    
    /* Priority Badges */
    .badge-critical {
        background-color: #7f1d1d;
        color: #fecaca;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-high {
        background-color: #c2410c;
        color: #ffedd5;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-infra {
        background-color: #1e3a8a;
        color: #dbeafe;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-low {
        background-color: #14532d;
        color: #dcfce7;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
    }
    
    /* Section Headers */
    .cyber-header {
        border-left: 4px solid #38bdf8;
        padding-left: 10px;
        margin-top: 15px;
        margin-bottom: 15px;
        font-weight: 600;
    }
    </style>
    """, unsafe_allow_html=True)


def render_metric_card(label: str, value: Any, subtext: str = ""):
    """Render a styled metric tile."""
    sub_html = f'<div class="metric-sub">{subtext}</div>' if subtext else ""
    st.markdown(f"""
    <div class="metric-container">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        {sub_html}
    </div>
    """, unsafe_allow_html=True)
