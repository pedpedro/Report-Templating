from docxtpl import DocxTemplate
from tqdm import tqdm
import re
from docx import Document
from flask import Flask, render_template, request, redirect, url_for, send_file
from pathlib import Path
from openpyxl import load_workbook
from collections import namedtuple
import pandas as pd
import datetime
import locale


app = Flask(__name__)

def get_findings_by_category(category, vulnerabilidades):
    return [{'FINDINGS_'+category: [v]} for v in vulnerabilidades if v['category']==category]

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Recebendo o caminho do modelo de relatório enviado pelo formulário
        modelo_relatorio = request.files['modelo_relatorio']

        # Recebendo os dados do formulário
        cliente_nome = request.form['cliente_nome']
        teste_titulo = request.form['teste_titulo']
        teste_ambiente = request.form['teste_ambiente']
        teste_tipo = request.form['teste_tipo']
        data_capa = request.form['data_capa']
        display_web = 'display_web' in request.form
        display_infra = 'display_infra' in request.form
        display_mobile = 'display_mobile' in request.form
        num_pontos_infra = int(request.form['num_pontos_infra']) if request.form['num_pontos_infra'] else 0
        num_pontos_mobile = int(request.form['num_pontos_mobile']) if request.form['num_pontos_mobile'] else 0
        num_pontos_web = int(request.form['num_pontos_web']) if request.form['num_pontos_web'] else 0


        # Salvando o arquivo de modelo de relatório temporariamente
        modelo_relatorio_salvo = "modelo_relatorio.docx"
        modelo_relatorio.save(modelo_relatorio_salvo)

        # Criando o objeto DocxTemplate
        doc = DocxTemplate(modelo_relatorio_salvo)


        # Criando o dicionário de contexto a partir das entradas do usuário
        context = {
            'cliente_nome': cliente_nome,
            'teste_titulo': teste_titulo,
            'teste_ambiente': teste_ambiente,
            'teste_tipo': teste_tipo,
            'data_capa': data_capa,
            'display_web': display_web,
            'display_infra': display_infra,
            'display_mobile': display_mobile,
            'num_pontos_web': int(num_pontos_web),
            'num_pontos_infra': int(num_pontos_infra),
            'num_pontos_mobile': int(num_pontos_mobile),
            'FINDINGS_web': [],
            'FINDINGS_infra': [],
            'FINDINGS_mobile': []
        }


        # Separar em categorias
        vulnerabilidades = [{'title': 'Cross-site scripting', 'severity': 'Alto', 'category': 'web'},
                            {'title': 'SQLi', 'severity': 'Moderado', 'category': 'infra'},    
                            {'title': 'HTTP Code error', 'severity': 'Moderado', 'category': 'web'},    
                            {'title': 'Invasão a domicilio', 'severity': 'Baixo', 'category': 'infra'},    
                            {'title': 'Homocídio culposo', 'severity': 'Baixo', 'category': 'mobile'},
                        ]

        if display_web:
            context['FINDINGS_web'] = get_findings_by_category('web', vulnerabilidades)
        if display_infra:
            context['FINDINGS_infra'] = get_findings_by_category('infra', vulnerabilidades)
        if display_mobile:
            context['FINDINGS_mobile'] = get_findings_by_category('mobile', vulnerabilidades)


        # Renderizando o modelo de relatório com o contexto
        doc.render(context)
        locale.setlocale(locale.LC_ALL, 'pt_pt.UTF-8')
        timestamp = datetime.datetime.now().strftime("%d-%b-%y")

        # Salvando o arquivo de saída
        output_dir = Path(__file__).parent / 'reports'
        output_dir.mkdir(parents=True, exist_ok=True)
        arquivo_saida = output_dir / f"relatorio_{cliente_nome}_{timestamp}.docx"
        doc.save(arquivo_saida)

        return relatorios()
    else:
        return render_template('index.html')

@app.route('/relatorios', methods=['GET'])
def relatorios():
    output_dir = Path(__file__).parent / 'reports'
    relatorios = [f.name for f in output_dir.glob('*.docx')]
    return render_template('relatorios.html', relatorios=relatorios)

@app.route('/reports/<filename>', methods=['GET'])
def download_relatorio(filename):
    output_dir = Path(__file__).parent / 'reports'
    return send_file(output_dir / filename)

@app.route('/excluir_relatorio', methods=['POST'])
def excluir_relatorio():
    filename = request.form['filename']
    output_dir = Path(__file__).parent / 'reports'
    arquivo_exclusao = output_dir / filename
    if arquivo_exclusao.exists():
        arquivo_exclusao.unlink()
    return 'OK'

@app.route('/base_dados')
def base_dados():
    # lê os dados do arquivo Base.xlsx
    df = pd.read_excel('Base de Dados/Base.xlsx')
    dados = []
    for _, row in df.iterrows():
        dado = {
            'nome': row['Nome'],
            'descricao': row['Descrição'],
            'impacto': row['Impacto'],
            'recomendacao': row['Recomendação'],
            'probabilidade': row['Probabilidade'],
            'impacto_novamente': row['Impacto2'],
            'risco': row['Risco']
        }
        dados.append(dado)
    
    # renderiza o template com os dados do arquivo XLSX
    return render_template('base_dados.html', dados=dados)
