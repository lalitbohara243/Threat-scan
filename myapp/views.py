from django.shortcuts import render, redirect
from django.contrib.auth import get_user
from django.contrib.auth.decorators import login_required
import warnings
warnings.filterwarnings('ignore')
import tensorflow_hub as hub
import json
import pprint
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from myapp.urlana import pri_domain,abnormal_url,httpSecure,digit_count,special_count,letter_count,URL_Shortening,having_ip
capabilities = DesiredCapabilities.CHROME
import pdb

# capabilities["loggingPrefs"] = {"performance": "ALL"}  # chromedriver < ~75
capabilities["goog:loggingPrefs"] = {"performance": "ALL"}  # chromedriver 75+

driver = webdriver.Chrome(
    r"/Users/lalitbohara/Desktop/chromedriver",
    desired_capabilities=capabilities,
)


def process_browser_logs_for_network_events(logs):
    """
    Return only logs which have a method that start with "Network.response", "Network.request", or "Network.webSocket"
    since we're interested in the network events specifically.
    """
    for entry in logs:
        log = json.loads(entry["message"])["message"]
       
        if (
                "Network.response" in log["method"]
                or "Network.request" in log["method"]
                or "Network.webSocket" in log["method"]
        ):
            yield log
import pickle
with open("url_model.pkl", "rb") as file:
    logreg = pickle.load(file)
# embed = hub.load("https://tfhub.dev/google/universal-sentence-encoder/4")
# def preprocess_email(email_text):
#     email_embedding = embed([email_text])
#     return email_embedding

# import tensorflow.keras as keras
# loaded_model = keras.models.load_model("universal_sentence_encoder_model.h5")
# @login_required
def index(request):
    
    context={}
    if request.method=='POST' and request.POST.get('choice')=='1' or request.POST.get('choice')=='2' or request.POST.get('choice')=='3':
        ch=request.POST.get('choice')

        print("first choice")
        print(ch)
       
    if request.method=='POST' and request.POST.get('choice1')=='FREE' or request.POST.get('choice1')=='LEVEL1' or request.POST.get('choice1')=='LEVEL2':
    # if request.method=='POST' and request.POST.get('choice1')=='FREE':
        ch=request.POST.get('choice1')
        print("second choice")
        print(ch)
        return redirect("myapp:fileupload")
    return render(request,"index.html")
def threatscan(request):
    if request.method=='POST':
        ch=request.POST.get("threat")
        if ch=='1':
            return redirect("myapp:email")
        if ch=='2':
            return redirect("myapp:url")
     
        if ch==3:
            pass
        print(ch)
    return render(request,"type.html")
def email(request):
    if request.method=='POST':
        ch=request.POST.get("input")
        print(ch)
    return render(request,"analysis/emailresult.html")

def url(request):
    dt=[]
    results = []
    context={}
    chart1 = None
    chart2 = None
    chart3 = None
    chart4=None
    if request.method=='POST':
        ch=request.POST.get("input")
        driver.get(ch)
        
        logs = driver.get_log("performance")
        events = process_browser_logs_for_network_events(logs)
        with open("log_entries.txt", "wt") as out:
            for event in events:
                pprint.pprint(event, stream=out)
        file_path = 'log_entries.txt'
        # Let's open and read the contents
        with open(file_path, 'r') as file:
            contents = file.readlines()
        # Extract URLs assuming they follow the pattern 'url': '<URL>'
        import re

        # Regex pattern to find URLs in the given pattern
        pattern = r"'url':\s*'(https?://[^\s']*)'"

        # Finding all URLs using regex
        urls = re.findall(pattern, ''.join(contents))
        pattern = r"'url':\s*'(https?://[^\s']*)'"

        # Use a set to store unique URLs
        unique_urls = set(re.findall(pattern, ''.join(contents)))

        # Print or process the unique URLs
        features = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
        for url in unique_urls:
            dt.append(url)

        for url in dt:
            # Preprocess the URL and extract features
            url_features = [url.count(a) for a in features]
            # url_features.append(pri_domain(url))
            url_features.append(abnormal_url(url))
            url_features.append(httpSecure(url))
            url_features.append(digit_count(url))
            url_features.append(special_count(url))
            url_features.append(letter_count(url))
            url_features.append(URL_Shortening(url))
            url_features.append(having_ip(url))

            # Make predictions using the trained model
            prediction = logreg.predict([url_features])[0]

            # Append URL and prediction to the results list
            results.append({"URL": url, "Result": "Spam" if prediction == 0 else "Ham"})

        # Convert results list to JSON format
        # results=results[:5]
        # json_results = json.dumps(results, indent=4)
        import pandas as pd
        df = pd.DataFrame(results)
        df['special_count'] = df['URL'].apply(special_count)
        df['digit_count'] = df['URL'].apply(digit_count)
        df['abnormal_url'] = df['URL'].apply(abnormal_url)
        df['having_ip'] = df['URL'].apply(having_ip)
        df['char count'] = df['URL'].apply(letter_count)
        from myapp.urlsplot import hamspambar,charcount,scatter,charcounths
        chart1 = hamspambar(df).to_html()
        chart2 = charcount(df).to_html()
        chart3 = scatter(df).to_html()
        chart4 = charcounths(df).to_html()

    return render(request,"analysis/urlresult.html",{"results": results,"chart1":chart1,"chart2":chart2,"chart3":chart3,"chart4":chart4})
