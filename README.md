CSPinator
=========

Generate CSP headers while surfing your websitez through burp! How cool is that?

    Steps:
    
    1. Check everything off in the Burp's Proxy Filter
    2. Enable proxy request logging (options > misc > logging)
    3. python generate.py proxylog.log www.host.com
    4. ???
    5. Profit? Kinda...


Example
=======

    omar[~/CSPinator]$ python generate.py whatismyip.log www.whatismyip.com
    X-WebKit-CSP: default-src self *.tynt.com; script-src *.addthis.com *.tynt.com www.google-analytics.com; img-src m.addthisedge.com www.google-analytics.com; style-src ct5.addthis.com; 
    X-Content-Security-Policy: default-src self *.tynt.com; script-src *.addthis.com *.tynt.com www.google-analytics.com; img-src m.addthisedge.com www.google-analytics.com; style-src ct5.addthis.com;

It's not done so don't judge me!!