from flask import Flask, render_template, request, jsonify, send_from_directory, session
import requests
import json
import os
import re
import time
import hashlib
import secrets
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Rate limiting için veri yapısı
rate_limit_storage = {}
RATE_LIMIT = 30  # Dakikada maksimum istek
RATE_LIMIT_WINDOW = 60  # Saniye cinsinden pencere

def rate_limit(f):
    """IP bazlı rate limiting decorator'ü"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Client IP'yi al
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        current_time = time.time()
        
        # IP'nin kaydını kontrol et
        if client_ip not in rate_limit_storage:
            rate_limit_storage[client_ip] = []
        
        # Eski kayıtları temizle
        rate_limit_storage[client_ip] = [
            req_time for req_time in rate_limit_storage[client_ip]
            if current_time - req_time < RATE_LIMIT_WINDOW
        ]
        
        # Rate limit kontrolü
        if len(rate_limit_storage[client_ip]) >= RATE_LIMIT:
            return jsonify({
                'success': False,
                'message': 'Çok fazla istek gönderdiniz. Lütfen 1 dakika bekleyin.'
            }), 429
        
        # Yeni isteği kaydet
        rate_limit_storage[client_ip].append(current_time)
        return f(*args, **kwargs)
    return decorated_function

def validate_tc(tc):
    """TC kimlik numarası validasyonu"""
    if not tc or not tc.isdigit():
        return False
    if len(tc) != 11:
        return False
    if tc[0] == '0':
        return False
    
    # TC algoritması kontrolü (basit)
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
    """GSM numarası validasyonu"""
    if not gsm:
        return False
    # Sadece rakamları al
    gsm_clean = re.sub(r'\D', '', str(gsm))
    if len(gsm_clean) == 10:
        gsm_clean = '0' + gsm_clean
    if len(gsm_clean) != 11:
        return False
    if not gsm_clean.startswith('05'):
        return False
    return gsm_clean

def sanitize_input(value):
    """Girdi temizleme - XSS koruması"""
    if not value:
        return ''
    # Sadece harf, rakam, boşluk ve belirli karakterlere izin ver
    value = str(value).strip()
    # HTML entity'lerini temizle
    value = re.sub(r'[<>]', '', value)
    # Sadece alfanumerik, türkçe karakterler, boşluk ve tire
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
        response = requests.get(
            url, 
            params=params, 
            headers=headers, 
            timeout=timeout,
            verify=True  # SSL sertifikası kontrolü
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'İstek zaman aşımına uğradı'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'message': 'Bağlantı hatası'}
    except json.JSONDecodeError:
        return {'success': False, 'message': 'Geçersiz yanıt formatı'}

# Ana sayfa
@app.route('/')
@rate_limit
def index():
    return render_template('index.html')

# Sorgu sayfası
@app.route('/query')
@rate_limit
def query_page():
    sorgu_tip = request.args.get('type', 'adsoyad')
    
    # Sorgu tipi validasyonu
    valid_queries = [
        'adsoyad', 'adsoyadpro', 'tcpro', 'cocuk', 'ailepro', 'aile',
        'adres', 'kardes', 'sulale', 'adililce', 'tcgsm', 'gsmtc', 'operator'
    ]
    
    if sorgu_tip not in valid_queries:
        sorgu_tip = 'adsoyad'
    
    return render_template('query.html', sorgu_tip=sorgu_tip)

# API endpoint'leri
API_BASE = "https://apiservices.alwaysdata.net/apiservices"

# Ad Soyad Sorgu
@app.route('/api/adsoyad')
@rate_limit
def adsoyad():
    ad = request.args.get('ad', '').strip().upper()
    soyad = request.args.get('soyad', '').strip().upper()
    
    # Validasyon
    if not ad or not soyad:
        return jsonify({'success': False, 'message': 'Ad ve soyad alanları zorunludur', 'results': []})
    
    if not validate_ad_soyad(ad) or not validate_ad_soyad(soyad):
        return jsonify({'success': False, 'message': 'Geçersiz ad veya soyad formatı', 'results': []})
    
    ad = sanitize_input(ad)
    soyad = sanitize_input(soyad)
    
    url = f"{API_BASE}/adsoyad.php"
    params = {'ad': ad, 'soyad': soyad}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# Ad Soyad Pro Sorgu
@app.route('/api/adsoyadpro')
@rate_limit
def adsoyadpro():
    ad = request.args.get('ad', '').strip().upper()
    soyad = request.args.get('soyad', '').strip().upper()
    il = request.args.get('il', '').strip().upper()
    
    # Validasyon
    if not ad or not soyad:
        return jsonify({'success': False, 'message': 'Ad ve soyad alanları zorunludur', 'results': []})
    
    if not validate_ad_soyad(ad) or not validate_ad_soyad(soyad):
        return jsonify({'success': False, 'message': 'Geçersiz ad veya soyad formatı', 'results': []})
    
    ad = sanitize_input(ad)
    soyad = sanitize_input(soyad)
    il = sanitize_input(il) if il else ''
    
    url = f"{API_BASE}/adsoyadpro.php"
    params = {'ad': ad, 'soyad': soyad}
    if il:
        params['il'] = il
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# TC Pro Sorgu
@app.route('/api/tcpro')
@rate_limit
def tcpro():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/tcpro.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# Çocuk Sorgu
@app.route('/api/cocuk')
@rate_limit
def cocuk():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/cocuk.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': data.get('count', len(data['results']))})
    return jsonify({'success': False, 'message': 'Çocuk bulunamadı', 'results': []})

# Aile Pro Sorgu
@app.route('/api/ailepro')
@rate_limit
def ailepro():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/ailepro.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# Aile Sorgu
@app.route('/api/aile')
@rate_limit
def aile():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/aile.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success'):
        kayitlar = data.get('aile_bilgileri', {}).get('kayitlar', [])
        return jsonify({'success': True, 'results': kayitlar, 'count': len(kayitlar)})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# Adres Sorgu
@app.route('/api/adres')
@rate_limit
def adres():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/adres.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Adres bulunamadı', 'results': []})

# Kardeş Sorgu
@app.route('/api/kardes')
@rate_limit
def kardes():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/kardes.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('kardesler'):
        return jsonify({'success': True, 'results': data['kardesler'], 'count': data.get('toplam_kardes', len(data['kardesler']))})
    return jsonify({'success': False, 'message': 'Kardeş bulunamadı', 'results': []})

# Sülale Sorgu
@app.route('/api/sulale')
@rate_limit
def sulale():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/sulale.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        # Sülale sonuçlarını sınırla (çok fazla veri olabilir)
        results = data['results'][:50]
        return jsonify({'success': True, 'results': results, 'count': len(results)})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# Ad İl İlçe Sorgu
@app.route('/api/adililce')
@rate_limit
def adililce():
    ad = request.args.get('ad', '').strip().upper()
    il = request.args.get('il', '').strip().upper()
    ilce = request.args.get('ilce', '').strip().upper()
    
    if not ad:
        return jsonify({'success': False, 'message': 'Ad alanı zorunludur', 'results': []})
    
    if not validate_ad_soyad(ad):
        return jsonify({'success': False, 'message': 'Geçersiz ad formatı', 'results': []})
    
    ad = sanitize_input(ad)
    il = sanitize_input(il) if il else ''
    ilce = sanitize_input(ilce) if ilce else ''
    
    url = f"{API_BASE}/adililce.php"
    params = {'ad': ad}
    if il:
        params['il'] = il
    if ilce:
        params['ilce'] = ilce
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': data.get('count', len(data['results']))})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# TC GSM Sorgu
@app.route('/api/tcgsm')
@rate_limit
def tcgsm():
    tc = request.args.get('tc', '').strip()
    
    if not tc:
        return jsonify({'success': False, 'message': 'TC kimlik numarası zorunludur', 'results': []})
    
    if not validate_tc(tc):
        return jsonify({'success': False, 'message': 'Geçersiz TC kimlik numarası', 'results': []})
    
    url = f"{API_BASE}/tcgsm.php"
    params = {'tc': tc}
    
    data = safe_request(url, params)
    
    if data.get('success'):
        gsmler = data.get('gsmler', [])[:20]  # En fazla 20 GSM göster
        result = [{'TC': data.get('tc'), 'GSM': gsm} for gsm in gsmler]
        return jsonify({'success': True, 'results': result, 'count': len(gsmler)})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# GSM TC Sorgu
@app.route('/api/gsmtc')
@rate_limit
def gsmtc():
    gsm = request.args.get('gsm', '').strip()
    
    if not gsm:
        return jsonify({'success': False, 'message': 'GSM numarası zorunludur', 'results': []})
    
    gsm_valid = validate_gsm(gsm)
    if not gsm_valid:
        return jsonify({'success': False, 'message': 'Geçersiz GSM numarası formatı', 'results': []})
    
    url = f"{API_BASE}/gsmtc.php"
    params = {'gsm': gsm_valid}
    
    data = safe_request(url, params)
    
    if data.get('success') and data.get('results'):
        return jsonify({'success': True, 'results': data['results'], 'count': len(data['results'])})
    return jsonify({'success': False, 'message': 'Sonuç bulunamadı', 'results': []})

# Güncel Operatör Sorgu
@app.route('/api/operator')
@rate_limit
def operator():
    numara = request.args.get('numara', '').strip()
    
    if not numara:
        return jsonify({'success': False, 'message': 'GSM numarası zorunludur', 'results': []})
    
    numara_valid = validate_gsm(numara)
    if not numara_valid:
        return jsonify({'success': False, 'message': 'Geçersiz GSM numarası formatı', 'results': []})
    
    url = f"{API_BASE}/gncloperator.php"
    params = {'numara': numara_valid}
    
    data = safe_request(url, params)
    
    if data.get('status'):
        return jsonify({'success': True, 'results': [data.get('data', {})], 'count': 1})
    return jsonify({'success': False, 'message': 'Operatör bilgisi bulunamadı', 'results': []})

# Statik dosyalar
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# Hata sayfası
@app.errorhandler(404)
def not_found(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'message': 'Sunucu hatası'}), 500

if __name__ == '__main__':
    # Production için debug=False
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
