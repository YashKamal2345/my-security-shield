# ============================================
# WEBSITE SECURITY SHIELD
# ============================================
# How it works:
# 1. You enter your website URL
# 2. System creates a proxy in front of your website
# 3. Every visitor goes through security check first
# 4. Safe visitors see your real website
# 5. Malicious visitors get blocked and see denial message
# ============================================

from flask import Flask, request
import requests
import time
import json
from collections import defaultdict

app = Flask(__name__)

# ============================================
# CONFIGURATION
# ============================================
TARGET_WEBSITE = ""
MAX_REQUESTS_PER_MINUTE = 60
SUSPICIOUS_PORTS = [22, 23, 445, 3389, 5900, 8080, 8443]

# Known malicious IP ranges
MALICIOUS_RANGES = [45, 94, 103, 154, 185, 193, 5, 31, 46, 80, 109]

# ============================================
# DATA STORAGE
# ============================================
ip_requests = defaultdict(list)
blocked_ips = set()
access_log = []

stats = {
    'total_visitors': 0,
    'blocked': 0,
    'allowed': 0
}

# ============================================
# SECURITY CHECK FUNCTION
# ============================================
def check_visitor(ip):
    """Check if visitor is safe or malicious"""
    
    now = time.time()
    
    # Rate limiting check (DDoS protection)
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < 60]
    ip_requests[ip].append(now)
    request_rate = len(ip_requests[ip])
    
    if request_rate > MAX_REQUESTS_PER_MINUTE:
        blocked_ips.add(ip)
        return False, "BLOCKED: Rate limit exceeded ({} requests/minute)".format(request_rate)
    
    if ip in blocked_ips:
        return False, "BLOCKED: IP is in blacklist"
    
    # Check against malicious IP ranges
    try:
        first_octet = int(ip.split('.')[0])
        if first_octet in MALICIOUS_RANGES:
            blocked_ips.add(ip)
            return False, "BLOCKED: Malicious IP range detected ({}.x.x.x)".format(first_octet)
    except:
        pass
    
    return True, "ALLOWED: Visitor is safe"

# ============================================
# PROXY ROUTE - FORWARDS TO YOUR REAL WEBSITE
# ============================================
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy(path):
    """Every visitor goes through security check before seeing your website"""
    
    # Get visitor's real IP
    visitor_ip = request.remote_addr
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        visitor_ip = forwarded.split(',')[0].strip()
    
    # Security check
    is_safe, message = check_visitor(visitor_ip)
    
    # Log the visit
    log_entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'ip': visitor_ip,
        'path': path,
        'status': 'ALLOWED' if is_safe else 'BLOCKED',
        'reason': message
    }
    access_log.append(log_entry)
    
    # Update statistics
    stats['total_visitors'] += 1
    if is_safe:
        stats['allowed'] += 1
    else:
        stats['blocked'] += 1
    
    print("\n" + "="*60)
    print("VISITOR: {}".format(visitor_ip))
    print("RESULT: {}".format(message))
    print("STATS: {} total | {} blocked".format(stats['total_visitors'], stats['blocked']))
    print("="*60)
    
    # If visitor is malicious - BLOCK them
    if not is_safe:
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Access Denied</title></head>
        <body style="font-family: Arial; padding: 50px; text-align: center; background: #1a1a2e;">
            <div style="max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
                <h1 style="color: #dc3545;">Access Denied</h1>
                <p>Your request has been blocked by the security system.</p>
                <p><strong>Your IP:</strong> {}</p>
                <p><strong>Reason:</strong> {}</p>
                <hr>
                <small>Security event has been logged</small>
            </div>
        </body>
        </html>
        """.format(visitor_ip, message), 403
    
    # If visitor is safe - FORWARD to your real website
    try:
        if path:
            target_url = "{}/{}".format(TARGET_WEBSITE, path)
        else:
            target_url = TARGET_WEBSITE
        
        response = requests.get(target_url, headers={
            'User-Agent': request.headers.get('User-Agent', '')
        })
        
        return response.content, 200, {'Content-Type': 'text/html'}
        
    except Exception as e:
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Proxy Error</title></head>
        <body style="font-family: Arial; padding: 50px; text-align: center;">
            <div style="max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
                <h1 style="color: #ffc107;">Proxy Error</h1>
                <p>Could not reach the website.</p>
                <p><strong>Error:</strong> {}</p>
            </div>
        </body>
        </html>
        """.format(str(e)), 500


# ============================================
# DASHBOARD - SEE ALL VISITORS AND BLOCKED IPS
# ============================================
@app.route('/security-dashboard')
def dashboard():
    """See all visitors and blocked IPs"""
    
    # Calculate block rate
    if stats['total_visitors'] > 0:
        block_rate = (stats['blocked'] / stats['total_visitors']) * 100
    else:
        block_rate = 0
    
    # Build blocked IPs display
    if blocked_ips:
        blocked_ips_display = json.dumps(list(blocked_ips), indent=2)
    else:
        blocked_ips_display = "No IPs blocked yet"
    
    # Build table rows
    table_rows = ""
    for log in access_log[-30:]:
        status_class = "good" if log['status'] == 'ALLOWED' else "bad"
        table_rows += """
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td class="{}">{}</td>
            <td>{}</td>
        </tr>
        """.format(log['timestamp'], log['ip'], log['path'], status_class, log['status'], log['reason'][:50])
    
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Dashboard - {}</title>
        <style>
            body {{ font-family: 'Courier New', monospace; padding: 20px; background: #1e1e1e; color: #d4d4d4; }}
            h1 {{ color: #4ec9b0; }}
            .stats {{ background: #2d2d2d; padding: 15px; border-radius: 5px; margin: 10px 0; }}
            .good {{ color: #4ec9b0; }}
            .bad {{ color: #f48771; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #444; }}
            th {{ background: #333; color: #4ec9b0; }}
        </style>
    </head>
    <body>
        <h1>Security Dashboard</h1>
        <p>Protecting: <strong class="good">{}</strong></p>
        
        <div class="stats">
            <h2>Live Statistics</h2>
            <pre>
Total Visitors: {}
Allowed: {}
Blocked: {}
Block Rate: {:.1f}%
Active Blacklist: {} IPs
            </pre>
        </div>
        
        <div class="stats">
            <h2>Blocked IPs ({})</h2>
            <pre>{}</pre>
        </div>
        
        <div class="stats">
            <h2>Recent Visitor Logs</h2>
            <table>
                <tr>
                    <th>Time</th>
                    <th>IP Address</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Reason</th>
                </tr>
                {}
            </table>
        </div>
    </body>
    </html>
    """.format(TARGET_WEBSITE, TARGET_WEBSITE, stats['total_visitors'], 
               stats['allowed'], stats['blocked'], block_rate, len(blocked_ips),
               len(blocked_ips), blocked_ips_display, table_rows)


# ============================================
# MAIN - ASKS FOR YOUR WEBSITE URL
# ============================================
if __name__ == "__main__":
    print("\n" + "="*70)
    print("WEBSITE SECURITY SHIELD - REAL PROTECTION")
    print("="*70)
    print("\nHOW IT WORKS:")
    print("   1. Enter your website URL below")
    print("   2. This security shield sits in front of your website")
    print("   3. Every visitor is checked for threats")
    print("   4. Safe visitors get your real website")
    print("   5. Malicious visitors get blocked")
    print("\n" + "="*70)
    
    # Get website URL
    website_url = input("\nEnter your website URL: ").strip()
    if not website_url:
        website_url = "https://portfolio-1-j1jd.vercel.app"
    
    TARGET_WEBSITE = website_url
    print("\nProtecting: {}".format(TARGET_WEBSITE))
    
    # Get port
    port_input = input("Enter port (default 8080): ").strip()
    if port_input:
        port = int(port_input)
    else:
        port = 8080
    
    print("\n" + "="*70)
    print("SECURITY SHIELD ACTIVE!")
    print("   Protecting: {}".format(TARGET_WEBSITE))
    print("   Access your protected site: http://localhost:{}".format(port))
    print("   Dashboard: http://localhost:{}/security-dashboard".format(port))
    print("\nIMPORTANT: All traffic now goes through security check")
    print("   Safe visitors see your REAL website")
    print("   Malicious visitors are BLOCKED")
    print("\n   Press Ctrl+C to stop")
    print("="*70)
    
    # Run the server
    app.run(host='0.0.0.0', port=port, debug=False)
