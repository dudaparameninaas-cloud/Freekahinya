from flask import Flask, render_template, request, jsonify, send_from_directory
import requests
import json
import os
import re
import time
import secrets
from functools import wraps
from datetime import timedelta

app = Flask(__name__)

# Render için gerekli ayarlar
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER') else False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Rate limiting için (basit bellek içi, render için yeterli)
rate_limit_storage = {}
RATE_LIMIT = 30  # Dakikada maksimum istek
RATE_LIMIT_WINDOW = 60  # Saniye

def rate_limit(f):
    """IP bazlı rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        current_time = time.time()
        
        if client_ip not in rate_limit_storage:
            rate_limit_storage[client_ip] = []
        
        rate_limit_storage[client_ip] = [
            req_time for req_time in rate_limit_storage[client_ip]
            if current_time - req_time < RATE_LIMIT_WINDOW
        ]
        
        if len(rate_limit_storage[client_ip]) >= RATE_LIMIT:
            return jsonify({
                'success': False,
                'message': 'Çok fazla istek gönderdiniz. Lütfen 1 dakika bekleyin.'
            }), 429
        
        rate_limit_storage[client_ip].append(current_time)
        return f(*args, **kwargs)
    return decorated_function

def validate_tc(tc):
    """TC kimlik validasyonu"""
    if not tc or not tc.isdigit():
        return False
    if len(tc) != 11:
        return False
    if tc[0] == '0':
        return False
    try:
        digits = [int(d) for d in tc]
        odd_sum = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
        even_sum = digits[1] + digits[3] + digits[5] + digits[7]
        check1 = (odd_sum * 7 - even_sum) % 10
        if digits[9] != check1:
            return False
        check2 = sum(digits[:10]) % 10
        if digits[10] != check2:
            return False
        return True
    except:
        return False

def validate_gsm(gsm):
    """GSM validasyonu"""
    if not gsm:
        return False
    gsm_clean = re.sub(r'\D', '', str(gsm))
    if len(gsm_clean) == 10:
        gsm_clean = '0' + gsm_clean
    if len(gsm_clean) != 11:
        return False
    if not gsm_clean.startswith('05'):
        return False
    return gsm_clean

def sanitize_input(value):
    """Girdi temizleme"""
    if not value:
        return ''
    value = str(value).strip()
    value = re.sub(r'[<>]', '', value)
    value = re.sub(r'[^a-zA-Z0-9ğüşıöçĞÜŞİÖÇ\s\-]', '', value)
    return value.upper()

def validate_ad_soyad(name):
    """Ad/Soyad validasyonu"""
    if not name:
        return False
    name = str(name).strip()
    if len(name) < 2 or len(name) > 50:
        return False
    if not re.match(r'^[a-zA-ZğüşıöçĞÜŞİÖÇ\s]+$', name):
        return False
    return True

def safe_request(url, params, timeout=15):
    """Güvenli HTTP isteği"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
        'Accept-Language': 'tr-TR,tr;q=0.9'
    }
    try:
        response = requests.get(url, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except:
        return {'success': False, 'message': 'Bağlantı hatası'}

@app.route('/')
@rate_limit
def index():
    return render_template('index.html')

@app.route('/query')
@rate_limit
def query_page():
    sorgu_tip = request.args.get('type', 'adsoyad')
    valid_queries = [
        'adsoyad', 'adsoyadpro', 'tcpro', 'cocuk', 'ailepro', 'aile',
        'adres', 'kardes', 'sulale', 'adililce', 'tcgsm', 'gsmtc', 'operator'
    ]
    if sorgu_tip not in valid_queries:
        sorgu_tip = 'adsoyad'
    return render_template('query.html', sorgu_tip=sorgu_tip)

API_BASE = "https://apiservices.alwaysdata.net/apiservices"

@app.route('/api/adsoyad')
@rate_limit
def adsoyad():
    ad = request.args.get('ad', '').strip().upper()
    soyad = request.args.get('soyad', '').strip().upper()
    
    if not ad or not soyad:
        return jsonify({'success': False, 'message': 'Ad ve soyad zorunludur', 'results': []})
    if not validate_ad_soyad(ad) or not validate_ad_soyad(soyad):
        return jsonify({'success': False, 'message': 'Geçersiz ad/soyad', 'results': []})
    
    ad = sanitize_input(ad)
    soyad = sanitize_input(soyad)
    
    data = safe_request(f"{API_BASE}/adsoyad.php", {'ad': ad, 'soyad': soyad})
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/adsoyadpro')
@rate_limit
def adsoyadpro():
    ad = request.args.get('ad', '').strip().upper()
    soyad = request.args.get('soyad', '').strip().upper()
    il = request.args.get('il', '').strip().upper()
    
    if not ad or not soyad:
        return jsonify({'success': False, 'message': 'Ad ve soyad zorunludur', 'results': []})
    if not validate_ad_soyad(ad) or not validate_ad_soyad(soyad):
        return jsonify({'success': False, 'message': 'Geçersiz ad/soyad', 'results': []})
    
    ad = sanitize_input(ad)
    soyad = sanitize_input(soyad)
    il = sanitize_input(il) if il else ''
    
    params = {'ad': ad, 'soyad': soyad}
    if il:
        params['il'] = il
    
    data = safe_request(f"{API_BASE}/adsoyadpro.php", params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/tcpro')
@rate_limit
def tcpro():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/tcpro.php", {'tc': tc})
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/cocuk')
@rate_limit
def cocuk():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/cocuk.php", {'tc': tc})
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': data.get('count', len(data['results']))})
    return jsonify({'success': False, 'message': 'Çocuk bulunamadı', 'results': []})

@app.route('/api/ailepro')
@rate_limit
def ailepro():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/ailepro.php", {'tc': tc})
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/aile')
@rate_limit
def aile():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/aile.php", {'tc': tc})
    
    if data.get('success'):
        kayitlar = data.get('aile_bilgileri', {}).get('kayitlar', [])
        return jsonify({'success': True, 'results': kayitlar, 'count': len(kayitlar)})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/adres')
@rate_limit
def adres():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/adres.php", {'tc': tc})
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Adres bulunamadı', 'results': []})

@app.route('/api/kardes')
@rate_limit
def kardes():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/kardes.php", {'tc': tc})
    
    if data.get('success') and data.get('kardesler'):
        return jsonify({'success': True, 'results': data['kardesler'], 'count': data.get('toplam_kardes', len(data['kardesler']))})
    return jsonify({'success': False, 'message': 'Kardeş bulunamadı', 'results': []})

@app.route('/api/sulale')
@rate_limit
def sulale():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/sulale.php", {'tc': tc})
    
    if data.get('success') and data.get('results'):
        results = data['results'][:50]
        return jsonify({'success': True, 'results': results, 'count': len(results)})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/adililce')
@rate_limit
def adililce():
    ad = request.args.get('ad', '').strip().upper()
    il = request.args.get('il', '').strip().upper()
    ilce = request.args.get('ilce', '').strip().upper()
    
    if not ad:
        return jsonify({'success': False, 'message': 'Ad zorunludur', 'results': []})
    if not validate_ad_soyad(ad):
        return jsonify({'success': False, 'message': 'Geçersiz ad', 'results': []})
    
    ad = sanitize_input(ad)
    params = {'ad': ad}
    if il:
        params['il'] = sanitize_input(il)
    if ilce:
        params['ilce'] = sanitize_input(ilce)
    
    data = safe_request(f"{API_BASE}/adililce.php", params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': data.get('count', len(data['results']))})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/tcgsm')
@rate_limit
def tcgsm():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC zorunludur', 'results': []})
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC', 'results': []})
    
    data = safe_request(f"{API_BASE}/tcgsm.php", {'tc': tc})
    
    if data.get('success'):
        gsmler = data.get('gsmler', [])[:20]
        result = [{'TC': data.get('tc'), 'GSM': gsm} for gsm in gsmler]
        return jsonify({'success': True, 'results': result, 'count': len(gsmler)})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/gsmtc')
@rate_limit
def gsmtc():
    gsm = request.args.get('gsm', '').strip()
    
    if not gsm:
        return jsonify({'success': False, 'message': 'GSM zorunludur', 'results': []})
    
    gsm_valid = validate_gsm(gsm)
    if not gsm_valid:
        return jsonify({'success': False, 'message': 'Geçersiz GSM', 'results': []})
    
    data = safe_request(f"{API_BASE}/gsmtc.php", {'gsm': gsm_valid})
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

@app.route('/api/operator')
@rate_limit
def operator():
    numara = request.args.get('numara', '').strip()
    
    if not numara:
        return jsonify({'success': False, 'message': 'GSM zorunludur', 'results': []})
    
    numara_valid = validate_gsm(numara)
    if not numara_valid:
        return jsonify({'success': False, 'message': 'Geçersiz GSM', 'results': []})
    
    data = safe_request(f"{API_BASE}/gncloperator.php", {'numara': numara_valid})
    
    if data.get('status'):
        return jsonify({'success': True, 'results': [data.get('data', {})], 'count': 1})
    return jsonify({'success': False, 'message': 'Operatör bulunamadı', 'results': []})

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.errorhandler(404)
def not_found(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'message': 'Sunucu hatası'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
