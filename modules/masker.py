import re

def mask_data(content):
    content = re.sub(r'password=\\S+', 'password=****', content)
    content = re.sub(r'api_key=\\S+', 'api_key=****', content)
    return content