import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import nmap
import pandas as pd
import socket
import dash_bootstrap_components as dbc

# Definição de cores personalizadas
colors = {
    'background': '#1e1e1e',  # Cor de fundo escura
    'text': '#FFFFFF',         # Cor do texto branco
    'accent': '#4CAF50',       # Cor de destaque verde
}

# Instanciando a aplicação Dash com Bootstrap
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

# Layout do aplicativo
app.layout = dbc.Container([
    html.H1("Scanner de Host Avançado", className="display-4 text-center mt-5 mb-4 font-weight-bold text-success"),  # Ajustes na tipografia e cor
    dbc.Row([
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Label("Insira a URL do host:", className="font-weight-bold text-light mb-0"),  # Cor do texto ajustada
                    dcc.Input(id="input-url", type="text", placeholder="URL do host...", className="form-control mb-3"),
                    html.Label("Selecione as opções de varredura:", className="font-weight-bold text-light mb-0"),  # Cor do texto ajustada
                    dbc.Checklist(
                        id="nmap-options",
                        options=[
                            {'label': '-F (Fast scan)', 'value': '-F'},
                            {'label': '-O (OS detection)', 'value': '-O'},
                            {'label': '-sV (Service detection)', 'value': '-sV'},
                            {'label': '-p (Port range)', 'value': '-p'},
                            {'label': '-A (Aggressive scan)', 'value': '-A'},  
                            {'label': '-T4 (Aggressive timing template)', 'value': '-T4'},  
                            {'label': '-sA (ACK scan)', 'value': '-sA'},  
                            # Adicione mais opções conforme necessário
                        ],
                        value=[],
                        inline=True,
                        className="mb-3"  # Espaçamento inferior ajustado
                    ),
                    dbc.Row([
                        dbc.Col(
                            html.Button(id="submit-button", n_clicks=0, children="Executar Scanner", className="btn btn-success btn-block"),  # Cor de botão ajustada
                        ),
                        dbc.Col(
                            html.Button(id="clear-button", n_clicks=0, children="Limpar", className="btn btn-secondary btn-block"),
                        )
                    ], className="mb-3")  # Espaçamento inferior ajustado
                ])
            ], className="shadow p-4 bg-dark text-light"),
            width=12
        )
    ], className="mb-4"),
    
    dbc.Row([
        dbc.Col(
            dcc.Loading(id="loading-output", children=[
                html.Div(id='host-info', style={'padding': '20px', 'borderRadius': '10px', 'backgroundColor': 'black', 'boxShadow': '2px 2px 5px #ccc'})
            ], className="shadow p-4 bg-dark text-light"),
            width=12
        )
    ])
])

# Função para obter o endereço IP a partir da URL
def get_ip_from_url(url):
    try:
        ip = socket.getaddrinfo(url, None, socket.AF_INET6)[0][4][0]  # Tentar primeiro IPv6
        return ip
    except Exception as e:
        try:
            ip = socket.getaddrinfo(url, None, socket.AF_INET)[0][4][0]  # Tentar IPv4 em caso de falha
            return ip
        except Exception as e:
            return None

# Callback para executar o scanner quando o botão é clicado
@app.callback(
    Output("host-info", "children"),
    [Input("submit-button", "n_clicks")],
    [State("input-url", "value"),
     State("nmap-options", "value")]
)
def update_output(submit_clicks, url, options):
    if submit_clicks is None or submit_clicks == 0 or not url:
        return ""

    # Obtém o endereço IP da URL
    ip = get_ip_from_url(url)
    if not ip:
        return html.Div("URL inválida. Por favor, insira uma URL válida.", style={'textAlign': 'center', 'color': colors['text']})

    # Executa o scanner de host
    results_df, host_info = scan_host(ip, options)
    if results_df is None:
        return html.Div("Erro ao executar a varredura. Verifique se as opções são válidas.", style={'textAlign': 'center', 'color': colors['text']})

    host_info_content = html.Div([
        html.Div([
            html.Label("Informações do Host", className="font-weight-bold text-success mb-3"),  # Ajuste na cor do texto
            html.Table([
                html.Tr([html.Td("Endereço IP:"), html.Td(host_info['addresses']['ipv4'])]),
                html.Tr([html.Td("Nome do Host:"), html.Td(host_info['hostnames'][0]['name'] if host_info['hostnames'] else 'Desconhecido')]),
                html.Tr([html.Td("Sistema Operacional:"), html.Td(host_info['osmatch'][0]['name'] if 'osmatch' in host_info else 'Desconhecido')]),
                html.Tr([html.Td("Endereço MAC:"), html.Td(host_info['addresses']['mac'] if 'mac' in host_info['addresses'] else 'Desconhecido')]),
                html.Tr([html.Td("Tempo de Resposta:"), html.Td(f"{host_info['rtt']} ms" if 'rtt' in host_info else 'Desconhecido')]),
            ], className="table table-dark table-bordered table-striped text-light"),  # Cor do texto ajustada
        ], className='col-md-6'),
        
        html.Div([
            html.Label("Detalhes das Portas", className="font-weight-bold text-success mb-3"),  # Ajuste na cor do texto
            dash_table.DataTable(
                id='port-table',
                columns=[{"name": i, "id": i} for i in results_df.columns],
                data=results_df.to_dict('records'),
                style_table={'overflowX': 'auto', 'backgroundColor': '#333333'},  # Cor de fundo ajustada
                style_cell={'minWidth': '50px', 'maxWidth': '180px', 'overflow': 'hidden', 'textOverflow': 'ellipsis', 'color': colors['text'], 'backgroundColor': '#444444'},  # Cores de texto e fundo ajustadas
                style_header={'backgroundColor': colors['accent'], 'fontWeight': 'bold'},  # Cor de fundo do cabeçalho ajustada
            ),
        ], className='col-md-6'),
        
    ], className='row')

    return host_info_content

# Função para executar o scanner de host
def scan_host(host, options):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=host, arguments=' '.join(options))
        host_info = nm[host]
        open_ports = host_info['tcp'].items()
        
        # Organize os resultados em um DataFrame para fácil visualização
        results_df = pd.DataFrame(open_ports, columns=['Porta', 'Detalhes'])
        for key in results_df['Detalhes'][0].keys():
            results_df[key] = results_df['Detalhes'].apply(lambda x: x.get(key, 'Desconhecido'))
        results_df = results_df.drop(columns=['Detalhes'])
        
        return results_df, host_info
    except Exception as e:
        print(e)
        return None, None

if __name__ == "__main__":
    app.run_server(debug=True)
