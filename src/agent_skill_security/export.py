from datetime import datetime


def generate_html_report(report_text):

    html = f"""
<!DOCTYPE html>
<html>

<head>

<title>
Agent Skill Security Report
</title>


<style>

body {{

    font-family: Arial;
    background:#f5f5f5;
    padding:40px;

}}


.container {{

    background:white;
    padding:30px;
    border-radius:10px;

}}


pre {{

    white-space:pre-wrap;

}}

</style>


</head>


<body>


<div class="container">


<h1>
🛡️ Agent Skill Security Report
</h1>


<p>
Generated:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</p>



<pre>

{report_text}

</pre>



</div>


</body>


</html>

"""


    return html