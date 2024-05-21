from myapp.urlana import pri_domain,abnormal_url,httpSecure,digit_count,special_count,letter_count,URL_Shortening,having_ip
import plotly.express as px

def hamspambar(df):
    bar_plot = px.bar(x=df['Result'].value_counts().index, y=df['Result'].value_counts().values, 
                  color=df['Result'].value_counts().index,
                  labels={'x': 'Result', 'y': 'Count'}, title='Count of Spam and Ham URLs')
    return bar_plot

def charcount(df):
    fig = px.histogram(df, x="char count", color="Result", marginal="rug",
                   hover_data=df.columns)
    return fig

def scatter(df):
    fig = px.scatter(x=df["special_count"], y=df["char count"], color=df["Result"],
                 size=df['special_count'])
    fig.update_xaxes(title_text="Special Character Count")

# Update y-axis label
    fig.update_yaxes(title_text="Character Count")
    return fig

def charcounths(df):
    char_count_plot = px.bar(x=df["Result"], y=df["char count"], color=df["Result"],
                         title="Character Count by Result")
    char_count_plot.update_xaxes(title_text="Result")
    char_count_plot.update_yaxes(title_text="char count")
    return char_count_plot