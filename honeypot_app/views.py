from django.shortcuts import render, redirect
from django.db.models import Count
from .models import Attack, Attacker, Setting
from .utils import detect_attack, get_country_from_ip
from django.views.decorators.csrf import csrf_exempt
from django.db.models.functions import ExtractWeekDay


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR', '127.0.0.1:8000')


def update_attacker(ip):
    country = get_country_from_ip(ip)
    attacker, created = Attacker.objects.get_or_create(ip_address=ip, defaults={
        'country': country,
        'total_attacks': 1
    })

    if not created:
        attacker.total_attacks += 1
        attacker.save()


def dashboard(request):
    attacks = Attack.objects.order_by('-time')[:5]

    total_attacks = Attack.objects.count()
    today_attacks = Attack.objects.count()
    sql_count = Attack.objects.filter(attack_type='SQL Injection').count()
    brute_count = Attack.objects.filter(attack_type='Brute Force').count()
    recent_attacks = Attack.objects.order_by('-time')[:5]

    context = {
        'attacks': attacks,
        'total_attacks': total_attacks,
        'today_attacks': today_attacks,
        'sql_count': sql_count,
        'brute_count': brute_count,
        'recent_attacks': recent_attacks,
    }
    return render(request, 'index.html', context)


def logs_view(request):
    attacks = Attack.objects.order_by('-time')
    return render(request, 'logs.html', {'attacks': attacks})


def monitor_view(request):
    attacks = Attack.objects.order_by('-time')[:20]
    return render(request, 'monitor.html', {'attacks': attacks})


def attackers_view(request):
    attackers = Attacker.objects.order_by('-total_attacks')
    return render(request, 'attackers.html', {'attackers': attackers})


def analysis_view(request):
    sql_count = Attack.objects.filter(attack_type='SQL Injection').count()
    xss_count = Attack.objects.filter(attack_type='XSS').count()
    brute_count = Attack.objects.filter(attack_type='Brute Force').count()
    cmd_count = Attack.objects.filter(attack_type='Command Injection').count()

    # Weekday wise attacks count
    weekday_data = (
        Attack.objects
        .annotate(weekday=ExtractWeekDay('time'))
        .values('weekday')
        .annotate(total=Count('id'))
        .order_by('weekday')
    )

    day_counts = {
        2: 0,  # Mon
        3: 0,  # Tue
        4: 0,  # Wed
        5: 0,  # Thu
        6: 0,  # Fri
        7: 0,  # Sat
        1: 0,  # Sun
    }

    for item in weekday_data:
        day_counts[item['weekday']] = item['total']

    context = {
        'sql_count': sql_count,
        'xss_count': xss_count,
        'brute_count': brute_count,
        'cmd_count': cmd_count,

        'mon': day_counts[2],
        'tue': day_counts[3],
        'wed': day_counts[4],
        'thu': day_counts[5],
        'fri': day_counts[6],
        'sat': day_counts[7],
        'sun': day_counts[1],
    }

    return render(request, 'analysis.html', context)

def settings_view(request):
    setting, created = Setting.objects.get_or_create(id=1)

    if request.method == "POST":
        email_alerts = request.POST.get('email_alerts')
        blocked_ip = request.POST.get('blocked_ip')
        admin_password = request.POST.get('admin_password')

        setting.email_alerts = True if email_alerts == 'Enabled' else False
        setting.blocked_ip = blocked_ip
        if admin_password:
            setting.admin_password = admin_password
        setting.save()

        return redirect('settings')

    return render(request, 'settings.html', {'setting': setting})

@csrf_exempt
def honeypot_login(request):
    message = ""

    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        payload = f"{username} {password}"

        ip = get_client_ip(request)
        attack_type = detect_attack(payload)

        Attack.objects.create(
            ip_address=ip,
            attack_type=attack_type,
            payload=payload,
            target="Login Form",
            status="Blocked" if attack_type != "Normal" else "Detected"
        )

        update_attacker(ip)

        message = "Login Failed!"

    return render(request, 'login.html', {'message': message})