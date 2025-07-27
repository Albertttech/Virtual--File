from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from vcfviewer.models import Contact, VCFFile
from django.utils import timezone
from datetime import timedelta
from django.db import models

@login_required
def contact_growth_data(request):
    range_type = request.GET.get('range', 'month')
    now = timezone.now()
    labels = []
    data = []
    vcf_types = ['premium', 'free']
    vcf_ids = VCFFile.objects.filter(vcf_type__in=vcf_types).values_list('id', flat=True)
    if range_type == 'day':
        for i in range(6, -1, -1):
            day = now - timedelta(days=i)
            count = Contact.objects.filter(vcf_file_id__in=vcf_ids, created_at__date=day.date()).count()
            labels.append(day.strftime('%a'))
            data.append(count)
    elif range_type == 'week':
        for i in range(3, -1, -1):
            start = now - timedelta(weeks=i)
            week_start = start - timedelta(days=start.weekday())
            week_end = week_start + timedelta(days=6)
            count = Contact.objects.filter(vcf_file_id__in=vcf_ids, created_at__date__gte=week_start.date(), created_at__date__lte=week_end.date()).count()
            labels.append(f"Week {week_start.strftime('%W')}")
            data.append(count)
    elif range_type == 'year':
        for i in range(11, -1, -1):
            month = (now - timedelta(days=30*i)).replace(day=1)
            next_month = (month + timedelta(days=32)).replace(day=1)
            count = Contact.objects.filter(vcf_file_id__in=vcf_ids, created_at__gte=month, created_at__lt=next_month).count()
            labels.append(month.strftime('%b'))
            data.append(count)
    else:
        for i in range(5, -1, -1):
            month = (now - timedelta(days=30*i)).replace(day=1)
            next_month = (month + timedelta(days=32)).replace(day=1)
            count = Contact.objects.filter(vcf_file_id__in=vcf_ids, created_at__gte=month, created_at__lt=next_month).count()
            labels.append(month.strftime('%b'))
            data.append(count)
    return JsonResponse({'labels': labels, 'data': data})
