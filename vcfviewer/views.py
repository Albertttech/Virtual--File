from django.shortcuts import render, redirect, get_object_or_404
from .forms import VCFUploadForm, VCFFileForm, ContactForm
import vobject
from .utils import parse_name
from .models import VCFFile, Contact
from django.db import IntegrityError


def home(request):
    vcfs = VCFFile.objects.all()
    return render(request, 'vcfviewer/home.html', {'vcfs': vcfs})

def create_vcf(request):
    if request.method == 'POST':
        form = VCFFileForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('home')
    else:
        form = VCFFileForm()
    return render(request, 'vcfviewer/create_vcf.html', {'form': form})

def view_vcf(request, pk):
    vcf = get_object_or_404(VCFFile, pk=pk)
    contacts = vcf.contacts.all()
    current = contacts.count()
    maximum = vcf.max_contacts
    progress = int((current / maximum) * 100) if maximum > 0 else 0

    form = ContactForm()
    error = None
    success = None

    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            if current >= maximum:
                error = "Maximum contact limit reached."
            else:
                name = form.cleaned_data['name']
                country_code = form.cleaned_data['country_code']
                number = form.cleaned_data['phone']
                full_phone = f"{country_code}{number}"

                if Contact.objects.filter(vcf_file=vcf, phone=full_phone).exists():
                    error = "This phone number already exists in this VCF file."
                else:
                    Contact.objects.create(
                        vcf_file=vcf,
                        name=name,
                        phone=full_phone
                    )
                    success = "Contact added successfully."
                    return redirect('view_vcf', pk=vcf.pk)

    return render(request, 'vcfviewer/view_vcf.html', {
        'vcf': vcf,
        'contacts': contacts,
        'progress': progress,
        'current_count': current,
        'max_count': maximum,
        'form': form,
        'error': error,
        'success': success,
    })




def upload_vcf(request):
    contact_data = []
    if request.method == 'POST':
        form = VCFUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['vcf_file']
            try:
                content = file.read().decode('utf-8', errors='ignore')
                vcards = vobject.readComponents(content)

                for vcard in vcards:
                    name = parse_name(vcard)
                    phone = vcard.tel.value if hasattr(vcard, 'tel') else 'N/A'
                    contact_data.append({'name': name, 'phone': phone})

            except Exception as e:
                contact_data.append({'error': str(e)})
    else:
        form = VCFUploadForm()

    return render(request, 'vcfviewer/upload.html', {'form': form, 'contacts': contact_data})


from django.http import HttpResponse
def save_vcf(request):
    # Example of writing a vCard to download
    response = HttpResponse(content_type='text/vcard')
    response['Content-Disposition'] = 'attachment; filename="new_contact.vcf"'

    card = vobject.vCard()
    card.add('fn').value = "Test User 😊"
    card.add('tel').value = "+123456789"
    response.write(card.serialize())

    return response
