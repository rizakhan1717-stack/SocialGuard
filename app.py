import pandas as pd
import streamlit as st
import plotly.express as px
from socialguard.collectors import load_csv, collect_reddit_demo, collect_twitter_demo
from socialguard.pipeline import process_dataframe, summary_metrics, build_intelligence_report

try:
    from streamlit_autorefresh import st_autorefresh
except Exception:  # app still works if optional dependency is not installed
    st_autorefresh = None

st.set_page_config(page_title='SocialGuard Threat Intelligence Tool', layout='wide')
st.title('SocialGuard - Social Media Threat Intelligence Monitoring Tool')
st.caption('Prototype for collecting, analysing, scoring, mapping, and visualising potential social media cyber-threat indicators.')

with st.sidebar:
    st.header('Data source')
    source_mode = st.radio('Choose input mode', ['Demo: Twitter/X + Reddit', 'Upload CSV'], index=0)
    uploaded = None
    if source_mode == 'Upload CSV':
        uploaded = st.file_uploader('Upload CSV with columns: id, source, user, text, timestamp, post_count, account_age_days, follower_count', type='csv')

    st.header('Near-real-time mode')
    auto_refresh = st.checkbox('Auto refresh every 30 seconds', value=False)
    if auto_refresh:
        if st_autorefresh is not None:
            st_autorefresh(interval=30000, key='socialguard_refresh')
            st.success('Near-real-time refresh enabled')
        else:
            st.warning('Install streamlit-autorefresh to enable automatic refresh.')

    st.header('Filters')
    risk_filter = st.multiselect(
        'Risk level',
        ['Critical Risk', 'High Risk', 'Medium Risk', 'Low Risk'],
        default=['Critical Risk', 'High Risk', 'Medium Risk', 'Low Risk']
    )
    threat_filter = st.multiselect('Threat type', [])
    keyword_search = st.text_input('Search processed text')

if source_mode == 'Upload CSV' and uploaded is not None:
    raw_df = load_csv(uploaded)
else:
    raw_df = pd.concat([collect_twitter_demo(), collect_reddit_demo()], ignore_index=True)

processed = process_dataframe(raw_df)
metrics = summary_metrics(processed)

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric('Total records', metrics['total'])
c2.metric('Critical risk', metrics['critical'])
c3.metric('High risk', metrics['high'])
c4.metric('Medium risk', metrics['medium'])
c5.metric('Low risk', metrics['low'])

if processed.empty:
    st.warning('No valid records were available for analysis.')
    st.stop()

# Threat type filter is placed after processing so it can be populated dynamically.
all_threat_types = sorted(processed['threat_type'].dropna().unique().tolist())
with st.sidebar:
    selected_threat_types = st.multiselect('Filter by threat type', all_threat_types, default=all_threat_types)

filtered = processed[processed['classification'].isin(risk_filter)]
filtered = filtered[filtered['threat_type'].isin(selected_threat_types)]
if keyword_search:
    filtered = filtered[filtered['clean_text'].str.contains(keyword_search.lower(), na=False)]

left, right = st.columns([2, 1])
with left:
    st.subheader('Prioritised alerts')
    alert_cols = [
        'source', 'user', 'text', 'threat_type', 'mitre_technique', 'mitre_tactic',
        'keywords_detected', 'behaviour_flags', 'watchlist_matches', 'risk_score',
        'classification', 'analyst_recommendation'
    ]
    st.dataframe(filtered[alert_cols], width='stretch')

with right:
    st.subheader('Risk distribution')
    fig = px.pie(processed, names='classification', title='Alert categories')
    st.plotly_chart(fig, width='stretch')

    st.subheader('Threat categories')
    cat_counts = processed['threat_type'].value_counts().reset_index()
    cat_counts.columns = ['Threat Type', 'Count']
    bar1 = px.bar(cat_counts, x='Threat Type', y='Count', title='Threat type classification')
    st.plotly_chart(bar1, width='stretch')

    st.subheader('MITRE tactic mapping')
    mitre_counts = processed['mitre_tactic'].value_counts().reset_index()
    mitre_counts.columns = ['MITRE Tactic', 'Count']
    bar2 = px.bar(mitre_counts, x='MITRE Tactic', y='Count', title='Mapped MITRE ATT&CK tactics')
    st.plotly_chart(bar2, width='stretch')

st.subheader('Top risk scores')
bar = px.bar(filtered.head(10), x='user', y='risk_score', color='classification', hover_data=['threat_type', 'mitre_technique'])
st.plotly_chart(bar, width='stretch')

st.subheader('Export intelligence reports')
col_a, col_b = st.columns(2)
with col_a:
    st.download_button(
        'Download filtered alerts as CSV',
        filtered.to_csv(index=False).encode('utf-8'),
        'socialguard_alert_report.csv',
        'text/csv'
    )
with col_b:
    report_text = build_intelligence_report(filtered)
    st.download_button(
        'Download analyst report as TXT',
        report_text.encode('utf-8'),
        'socialguard_intelligence_report.txt',
        'text/plain'
    )

with st.expander('Detection logic and enhancements'):
    st.write('Risk score combines keyword indicators, behavioural indicators, and watchlist matches. Scores >= 8 are Critical Risk; scores >= 5 are High Risk; scores >= 2 are Medium Risk; otherwise Low Risk.')
    st.write('New enhancements include threat type classification, MITRE ATT&CK tactic/technique mapping, watchlist matching, analyst recommendations, CSV export, TXT intelligence report export, and optional near-real-time dashboard refresh.')
