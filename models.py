from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

import pytz


db = SQLAlchemy()
datatime_corrigir = pytz.timezone("America/Sao_Paulo")


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    problema = db.Column(db.Text, nullable=False)
    prioridade = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default='Aberto')
    data_criacao = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='tickets')
    
    user = db.relationship('User', backref='tickets', lazy=True) 


class Acessos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_entrada = db.Column(db.Date, nullable=False)
    nome = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(50))
    setor = db.Column(db.String(50))
    emails = db.relationship('EmailAcesso', backref='acesso', lazy=True, cascade="all, delete-orphan")

class EmailAcesso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    senha = db.Column(db.String(150), nullable=False)
    acesso_id = db.Column(db.Integer, db.ForeignKey('acessos.id'), nullable=False)


class Hardware(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(50))  
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Relaciona ao usuário dono
    status = db.Column(db.String(50), default="ativo") 
    processador = db.Column(db.String(200))
    armazenamento = db.Column(db.String(100))
    memoria = db.Column(db.String(100))
    data_entrada = db.Column(db.Date)
    setor = db.Column(db.String(50))


class Software(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    fabricante = db.Column(db.String(100))
    chave_licenca = db.Column(db.String(255))
    data_expiracao = db.Column(db.Date)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'))  

    def __repr__(self):
        return f'<Ticket {self.id}>'
    
class Periferico(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)  
    data_entrada = db.Column(db.Date, nullable=False)
    hardware_id = db.Column(db.Integer, db.ForeignKey('hardware.id'), nullable=True)
    hardware = db.relationship('Hardware', backref='perifericos')  # Relacionamento com Hardware



    def __repr__(self):
        return f'<Periferico {self.nome} - {self.status}>'


