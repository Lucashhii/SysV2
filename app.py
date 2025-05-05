
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

import matplotlib.pyplot as plt
import base64
from io import BytesIO

from flask_migrate import Migrate

from collections import defaultdict

from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, Ticket, Hardware, Software, Periferico, Acessos, EmailAcesso
from sqlalchemy.orm import joinedload

import pytz

import os

from sysinf import sysinfo_bp



app = Flask(__name__)

migrate = Migrate(app, db)
app.config['SECRET_KEY'] = 'aBa3f6d9b7e4c5f2d1a8b0c3e7d6f4a1b2c5e6d7f8a9b0c3e2f1a4d5c6b7e8f9'


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://tickets_db_74ye_user:LwckbTpd8MPv5EbfTU6hm09iRzCP3Q6C@dpg-cve0e4hc1ekc73eb1sc0-a/tickets_db_74ye'
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma_string_super_secreta_e_aleatoria')
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tickets.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app) 



datatime_corrigir = pytz.timezone("America/Sao_Paulo")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.register_blueprint(sysinfo_bp)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/')

def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/formulario', methods=['GET','POST'])
def formulario():
    return render_template('cadastros_tickets.html')

@app.route('/submit_ticket', methods=['POST'])
def criar_ticket():
    try:
        nome= request.form.get('nome')
        problema= request.form.get('problema')
        prioridade = request.form.get('prioridade')

        if not nome or not problema or not prioridade:
            flash("Todos os campos são obrigatórios!", "danger")
            return redirect(url_for('formulario'))
        
        novo_ticket = Ticket(nome=nome, problema=problema, prioridade=prioridade, user_id=current_user.id)
        db.session.add(novo_ticket)
        db.session.commit()

        flash("Ticket criado com sucesso!","success")
        return redirect(url_for('formulario'))
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao criar ticket:{str(e)}',"danger")
        return redirect(url_for('formulario'))
    
@app.route('/tickets', methods=['GET'])
@login_required
def listar_tickets():
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('dashboard'))
        
    status = request.args.get('status')
    data = request.args.get('data')
    prioridade = request.args.get('prioridade')
    nome = request.args.get('nome')

    query = Ticket.query

    if nome:
        query = query.filter(Ticket.nome == nome)
    if status:
        query = query.filter(Ticket.status == status)
    if data:
        query = query.filter(Ticket.data_criacao.like(f"{data}%"))
    if prioridade:
        query = query.filter(Ticket.prioridade == prioridade)

    query = query.options(joinedload(Ticket.user))
    query = query.order_by(Ticket.prioridade.asc())
    tickets = query.all()


    return render_template('tickets.html', tickets=tickets)

@app.route('/acessos', methods=['GET', 'POST'])
def listar_acessos():
    # Se o formulário de cadastro foi submetido via POST, processa o novo acesso
    if request.method == 'POST':
        data_entrada_str = request.form.get('data_entrada', '').strip()
        nome = request.form['nome']
        tipo = request.form['tipo']
        setor = request.form['setor']
        
        data_entrada = datetime.strptime(data_entrada_str, '%Y-%m-%d').date() if data_entrada_str else None
        novo_acesso = Acessos(data_entrada=data_entrada, nome=nome, tipo=tipo, setor=setor)
        db.session.add(novo_acesso)
        db.session.commit()
        flash('Acesso cadastrado com sucesso!', 'success')
        return redirect(url_for('listar_acessos'))
    
    # Para o método GET, obtém os filtros dos parâmetros da URL
    nome_filter = request.args.get('nome', '')
    tipo_filter = request.args.get('tipo', '')
    setor_filter = request.args.get('setor', '')

    # Cria a query inicial
    query = Acessos.query

    if nome_filter:
        query = query.filter(Acessos.nome.ilike(f'%{nome_filter}%'))
    if tipo_filter:
        query = query.filter(Acessos.tipo.ilike(f'%{tipo_filter}%'))
    if setor_filter:
        query = query.filter(Acessos.setor.ilike(f'%{setor_filter}%'))

    acessos = query.all()
    
    return render_template('acessos.html', acessos=acessos)
    


@app.route('/atualizar_email', methods=['POST'])
def atualizar_email():
    email_id   = request.form.get('email_id')
    novo_email = request.form.get('novo_email')
    nova_senha = request.form.get('nova_senha')  # <— capturando a senha

    if not email_id or not novo_email:
        return jsonify({'success': False, 'message': 'Dados insuficientes'}), 400

    email_registro = EmailAcesso.query.get_or_404(email_id)
    email_registro.email = novo_email
    if nova_senha is not None:
        email_registro.senha = nova_senha
    db.session.commit()

    return jsonify({
        'success': True,
        'novo_email': novo_email,
        'nova_senha': nova_senha
    })

@app.route('/adicionar_emails/<int:id>', methods=['POST'])
def adicionar_emails(id):
    acesso = Acessos.query.get_or_404(id)
    emails = request.form.getlist('emails[]')
    senhas = request.form.getlist('senhas[]')

    for idx, email in enumerate(emails):
        texto = email.strip()
        if not texto:
            continue
        senha = senhas[idx] if idx < len(senhas) else ''
        db.session.add(EmailAcesso(email=texto, senha=senha, acesso_id=acesso.id))

    db.session.commit()
    flash(f'{len(emails)} e-mail(s) adicionados com sucesso!', 'success')
    return redirect(url_for('listar_acessos'))



# Rotas para editar e deletar acesso (exemplo)
@app.route('/editar_acesso/<int:id>', methods=['GET', 'POST'])
def editar_acesso(id):
    acesso = Acessos.query.get_or_404(id)

    if request.method == 'POST':
        acesso.nome = request.form['nome']
        acesso.tipo = request.form['tipo']
        acesso.setor = request.form['setor']
        data_entrada_str = request.form.get('data_entrada', '').strip()
        
        acesso.data_entrada = datetime.strptime(data_entrada_str, '%Y-%m-%d').date() if data_entrada_str else None

        db.session.commit()
        flash('Acesso atualizado com sucesso!', 'success')
        return redirect(url_for('listar_acessos'))
    
    return render_template('editar_acesso.html', acesso=acesso)


@app.route('/deletar_acesso/<int:id>')
def deletar_acesso(id):
    acesso = Acessos.query.get(id)
    db.session.delete(acesso)
    db.session.commit()
    return redirect(url_for('listar_acessos'))

@app.route('/hardware', methods=['GET', 'POST'])
@login_required
def gerenciar_hardware():
    if request.method == 'POST':
        nome = request.form['nome']
        tipo = request.form['tipo']
        processador = request.form.get('processador')
        memoria = request.form.get('memoria')
        armazenamento = request.form.get('armazenamento')
        setor = request.form.get('setor')
        status = request.form['status']
        data_entrada_str = request.form.get('data_entrada', '').strip()

        # Convertendo a data de entrada
        data_entrada = datetime.strptime(data_entrada_str, '%Y-%m-%d').date() if data_entrada_str else None
        
        usuario_id = request.form.get('usuario_id')

        novo_hardware = Hardware(
            nome=nome,
            tipo=tipo,
            processador=processador,
            memoria=memoria,
            armazenamento=armazenamento,
            setor=setor,
            status=status,
            data_entrada=data_entrada,
            usuario_id=usuario_id,
        )

        db.session.add(novo_hardware)
        db.session.commit()
        flash("Hardware cadastrado!", "success")

    # **Aplicando Filtros**
    query = Hardware.query

    nome_filtro = request.args.get('nome', '').strip()
    tipo_filtro = request.args.get('tipo', '').strip()
    setor_filtro = request.args.get('setor', '').strip()
    status_filtro = request.args.get('status', '').strip()

    if nome_filtro:
        query = query.filter(Hardware.nome.ilike(f"%{nome_filtro}%"))
    if tipo_filtro:
        query = query.filter(Hardware.tipo == tipo_filtro)
    if setor_filtro:
        query = query.filter(Hardware.setor == setor_filtro)
    if status_filtro:
        query = query.filter(Hardware.status == status_filtro)

    hardwares = query.all()

    return render_template('hardware.html', hardwares=hardwares)



@app.route('/editar_hardware/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_hardware(id):
    hardware = Hardware.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            
            data_entrada_str = request.form['data_entrada']
            data_entrada = datetime.strptime(data_entrada_str, '%Y-%m-%d').date()

            
            hardware.data_entrada = data_entrada
            hardware.nome = request.form['nome']
            hardware.tipo = request.form['tipo']
            hardware.processador = request.form['processador']
            hardware.memoria = request.form['memoria']
            hardware.armazenamento = request.form['armazenamento']
            hardware.setor = request.form['setor']
            hardware.status = request.form['status']

            db.session.commit()  # Salva as mudanças no banco
            
            flash('Hardware atualizado com sucesso!', 'success')
            return redirect(url_for('gerenciar_hardware'))
        except Exception as e:
            db.session.rollback()  # Desfaz qualquer mudança em caso de erro
            flash(f'Erro ao atualizar hardware: {str(e)}', 'danger')
        
    return render_template('editar_hardware.html', hardware=hardware)




@app.route('/hardware/delete/<int:id>')
@login_required
def deletar_hardware(id):
    hardware = Hardware.query.get_or_404(id)
    db.session.delete(hardware)
    db.session.commit()
    flash("Hardware removido!", "danger")
    return redirect(url_for('gerenciar_hardware'))

@app.route('/hardware/salvar', methods=['POST'])
@login_required
def salvar_hardware():
    return gerenciar_hardware()  



@app.route('/registrar_periferico', methods=['GET', 'POST'])
@login_required
def registrar_periferico():
    # Filtros para a listagem de periféricos
    nome_filtro = request.args.get('nome', '')
    tipo_filtro = request.args.get('tipo', '')
    status_filtro = request.args.get('status', '')

    # Aplicando filtros na consulta de periféricos
    query = Periferico.query
    if nome_filtro:
        query = query.filter(Periferico.nome.ilike(f'%{nome_filtro}%'))
    if tipo_filtro:
        query = query.filter(Periferico.tipo == tipo_filtro)
    if status_filtro:
        query = query.filter(Periferico.status == status_filtro)

    perifericos = query.all()

    # Buscando a lista de hardwares para vinculação
    hardwares = Hardware.query.all()

    # Se for um POST, registra o novo periférico
    if request.method == 'POST':
        nome = request.form.get('nome')
        tipo = request.form.get('tipo')
        status = request.form.get('status')
        data_entrada_str = request.form.get('data_entrada')
        hardware_id = request.form.get('hardware_id')

        if not data_entrada_str:
            flash('Por favor, forneça a data de entrada.', 'error')
            return redirect(url_for('registrar_periferico'))

        data_entrada = datetime.strptime(data_entrada_str, '%Y-%m-%d').date()

        novo_periferico = Periferico(
            nome=nome,
            tipo=tipo,
            status=status,
            data_entrada=data_entrada,
            hardware_id=hardware_id if hardware_id else None
        )
        
        db.session.add(novo_periferico)
        db.session.commit()
        flash('Periférico registrado com sucesso!', 'success')

        return redirect(url_for('registrar_periferico'))

    return render_template('registrar_periferico.html',hardwares=hardwares, perifericos=perifericos)


@app.route('/editar_periferico/<int:id>', methods=['GET', 'POST'])
def editar_periferico(id):
    periferico = Periferico.query.get(id)
    hardwares = Hardware.query.all()  # Buscar todos os hardwares disponíveis

    if request.method == 'POST':
        data_entrada_str = request.form['data_entrada']
        data_entrada = datetime.strptime(data_entrada_str, '%Y-%m-%d').date()

        periferico.data_entrada = data_entrada
        periferico.nome = request.form['nome']
        periferico.tipo = request.form['tipo']
        periferico.status = request.form['status']

        # Atualizar o vínculo do hardware
        hardware_id = request.form.get('hardware_id')  # Pode ser string vazia se "Nenhum" for selecionado
        if hardware_id:  # Se um hardware foi selecionado
            periferico.hardware_id = int(hardware_id)
        else:
            periferico.hardware_id = None  # Desvincular o hardware caso "Nenhum" seja selecionado
        
        db.session.commit()
        return redirect(url_for('registrar_periferico'))

    return render_template('editar_periferico.html', periferico=periferico, hardwares=hardwares)

@app.route('/deletar_periferico/<int:id>', methods=['GET', 'POST'])
@login_required
def deletar_periferico(id):
   
    periferico = Periferico.query.get(id)
    if periferico:
        db.session.delete(periferico)
        db.session.commit()
        flash('Periférico excluído com sucesso!', 'success')
    else:
        flash('Periférico não encontrado.', 'danger')
    return redirect(url_for('registrar_periferico'))  


@app.route('/software', methods=['GET', 'POST'])
@login_required
def gerenciar_software():
    if request.method == 'POST':
        nome = request.form['nome']
        fabricante = request.form['fabricante']
        chave_licenca = request.form['chave_licenca']
        data_expiracao = request.form['data_expiracao']
        novo_software = Software(nome=nome, fabricante=fabricante, chave_licenca=chave_licenca, data_expiracao=data_expiracao)
        db.session.add(novo_software)
        db.session.commit()
        flash("Software cadastrado!", "success")
    softwares = Software.query.all()
    return render_template('software.html', softwares=softwares)

@app.route('/atualizar_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def atualizar_ticket(ticket_id):
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('dashboard'))
    
    ticket = Ticket.query.get(ticket_id)
    if ticket:
        ticket.status = "Resolvido"
        db.session.commit()
        flash("Ticket atualizado para Resolvido!", "success")
    else:
        flash("Ticket não encontrado!", "danger")
    return redirect(url_for('listar_tickets'))


@app.route('/excluir_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def excluir_ticket(ticket_id):
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('dashboard'))
    
    ticket = Ticket.query.get(ticket_id)
    
    if ticket:
        db.session.delete(ticket)
        db.session.commit()
        flash("Ticket excluído com sucesso!", "success")
    else:
        flash("Ticket não encontrado!", "danger")
    
    return redirect(url_for('listar_tickets'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        novo_usuario = User(username=username, password=hashed_password)
        db.session.add(novo_usuario)
        db.session.commit()
        flash('Usuário registrado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha incorretos.', 'danger')
    return render_template('login.html')


@app.route('/admin/usuarios')
@login_required
def gerenciar_usuarios():
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('dashboard'))
    
    usuarios = User.query.all()
    return render_template('admin_usuarios.html', usuarios=usuarios)



@app.route('/admin/tornar_admin/<int:user_id>', methods=['POST'])
@login_required
def tornar_admin(user_id):
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('dashboard'))

    usuario = User.query.get(user_id)
    if usuario:
        usuario.is_admin = True
        db.session.commit()
        flash(f"{usuario.username} agora é um administrador!", "success")
    return redirect(url_for('gerenciar_usuarios'))

@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('dashboard'))
    
    usuario = User.query.get(user_id)
    if request.method == 'POST':
        usuario.username = request.form.get('username')
        nova_senha = request.form.get('senha')
        if nova_senha:
            from werkzeug.security import generate_password_hash
            usuario.password = generate_password_hash(nova_senha)
        db.session.commit()
        flash("Usuário atualizado com sucesso!", "success")
        return redirect(url_for('gerenciar_usuarios'))
    
    return render_template('editar_usuario.html', usuario=usuario)
    
@app.route('/admin/usuarios/excluir/<int:user_id>', methods=['POST'])
@login_required
def excluir_usuario(user_id):
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('dashboard'))
    usuario = User.query.get(user_id)
    if usuario:
        db.session.delete(usuario)
        db.session.commit()
        flash("Usuário excluído com sucesso!", "success")
    return redirect(url_for('gerenciar_usuarios'))


@app.route('/dashboard')
@login_required
def dashboard():
    tickets_usuario = Ticket.query.filter_by(user_id=current_user.id).all()

    # Dicionários para contar os tickets
    tickets_por_data = defaultdict(lambda: {"Aberto": 0, "Resolvido": 0})
    tickets_por_prioridade = defaultdict(int)

    for ticket in tickets_usuario:
        data_formatada = ticket.data_criacao.strftime("%Y-%m-%d")
        
        if ticket.status == "Resolvido":
            tickets_por_data[data_formatada]["Resolvido"] += 1
        else:
            tickets_por_data[data_formatada]["Aberto"] += 1

        tickets_por_prioridade[ticket.prioridade] += 1

    return render_template('dashboard.html', tickets=tickets_usuario)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da conta.', 'info')
    return redirect(url_for('login'))   

if __name__ == '__main__':
    app.run(debug=True)
