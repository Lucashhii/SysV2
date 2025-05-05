
from flask import Blueprint, render_template, request, flash, send_file, current_app
import logging
import os
import psutil
import cpuinfo
from io import BytesIO


try:
    import pythoncom
    import wmi
    def get_gpu_names():
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            names = [gpu.Name for gpu in c.Win32_VideoController()]
        except Exception:
            names = []
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
        return names
except ImportError:
    def get_gpu_names():
        return []

def coletar_hardware():
    logging.debug("Coletando hardware, PID=%d", os.getpid())
    info = {}
    cpu = cpuinfo.get_cpu_info()
    info['CPU'] = cpu.get('brand_raw', 'Desconhecido')
    vm = psutil.virtual_memory()
    info['RAM_GB'] = f"{vm.total / (1024 ** 3):.2f}"
    part = psutil.disk_partitions()[0]
    usage = psutil.disk_usage(part.mountpoint)
    info['DISCO'] = f"{usage.used / (1024 ** 3):.2f}/{usage.total / (1024 ** 3):.2f}"
    
    gpus = get_gpu_names()
    info['GPU'] = ", ".join(gpus) if gpus else "Não detectada"
    logging.debug("Hardware coletado: %s", info)
    return info


sysinfo_bp = Blueprint('sysinfo', __name__, template_folder='templates')

@sysinfo_bp.route('/dashboard/sysinfo', methods=['GET', 'POST'])
def sysinfo():
    hw_info = None
    report_bytes = None

    if request.method == 'POST':
        action = request.form.get('action')

        
        if action == 'coletar':
            hw_info = coletar_hardware()
        
        elif action == 'salvar':
            
            hw_info = coletar_hardware()
            
            nome = request.form.get('nome') or 'Não informado'
            setor = request.form.get('setor') or 'Não informado'
            
            peripherals = {}
            for key in ['Mouse','Teclado','Headset/Fone','Monitor 1','Monitor 2','Outros']:
                if request.form.get(f'chk_{key}'):
                    desc = request.form.get(f'txt_{key}')
                    if not desc:
                        flash(f'Descreva o periférico: {key}', 'warning')
                        return render_template('sysinfo.html', hw=hw_info)
                    peripherals[key] = desc
            
            lines = [f"Usuário: {nome}", f"Setor: {setor}", '', '--- Hardware Detectado ---']
            for k,v in hw_info.items():
                suffix = ' GB' if k == 'RAM_GB' else ''
                lines.append(f"{k}: {v}{suffix}")
            lines.append('')
            lines.append('--- Periféricos Informados ---')
            for k,v in peripherals.items():
                lines.append(f"{k}: {v}")
            content = "\n".join(lines)
            
            buffer = BytesIO()
            buffer.write(content.encode('utf-8'))
            buffer.seek(0)
            filename = f"relatorio_{nome.replace(' ', '_')}.txt"
            return send_file(buffer, as_attachment=True, download_name=filename, mimetype='text/plain')

    return render_template('sysinfo.html', hw=hw_info)


