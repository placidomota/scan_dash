import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import nmap
import pandas as pd
import socket
import dash_bootstrap_components as dbc

# Definição de cores personalizadas
colors = {
    'background': '#f9f9f9',
    'text': '#333333',
    'accent': '#1f77b4',
}

# Instanciando a aplicação Dash com Bootstrap
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Layout do aplicativo
app.layout = html.Div(style={'backgroundColor': colors['background'], 'fontFamily': 'Arial, sans-serif'}, children=[
    dbc.Container([
        dbc.Row([
            dbc.Col(
                html.H1("Scanner de Host Avançado", style={'textAlign': 'center', 'color': colors['text'], 'marginBottom': '20px', 'textShadow': '1px 1px #ccc'}),
                width=12
            )
        ]),
        dbc.Row([
            dbc.Col(
                dbc.Card([
                    dbc.CardBody([
                        html.Label("Insira a URL do host:", style={'fontWeight': 'bold', 'color': colors['text']}),
                        dcc.Input(id="input-url", type="text", placeholder="URL do host...", style={'width': '100%', 'marginBottom': '10px', 'padding': '8px', 'borderRadius': '5px', 'border': '1px solid #ccc'}),
                        html.Label("Selecione as opções de varredura:", style={'fontWeight': 'bold', 'color': colors['text']}),
                        dcc.Checklist(
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
                            style={'marginBottom': '20px', 'color': colors['text']}
                        ),
                        dbc.Row([
                            dbc.Col(
                                html.Button(id="submit-button", n_clicks=0, children="Executar Scanner", style={'backgroundColor': colors['accent'], 'color': 'white', 'border': 'none', 'padding': '12px 24px', 'cursor': 'pointer', 'borderRadius': '5px', 'fontWeight': 'bold', 'boxShadow': '2px 2px 5px #ccc'}),
                                width=6
                            ),
                            dbc.Col(
                                html.Button(id="clear-button", n_clicks=0, children="Limpar", style={'backgroundColor': colors['accent'], 'color': 'white', 'border': 'none', 'padding': '12px 24px', 'cursor': 'pointer', 'borderRadius': '5px', 'fontWeight': 'bold', 'boxShadow': '2px 2px 5px #ccc'}),
                                width=6
                            )
                        ])
                    ])
                ], style={'maxWidth': '500px', 'margin': 'auto', 'padding': '20px', 'borderRadius': '10px', 'backgroundColor': 'white', 'boxShadow': '2px 2px 5px #ccc'}),
                width=12
            )
        ]),
        dbc.Row([
            dbc.Col(
                dcc.Loading(id="loading-output", children=[
                    dcc.Tabs(id="tabs", value='tab-host', children=[
                        dcc.Tab(label='Informações do Host', value='tab-host', style={'color': colors['text'], 'backgroundColor': colors['accent'], 'borderTopLeftRadius': '10px', 'borderTopRightRadius': '10px'}),
                        dcc.Tab(label='Detalhes das Portas', value='tab-ports', style={'color': colors['text'], 'backgroundColor': colors['accent'], 'borderTopLeftRadius': '10px', 'borderTopRightRadius': '10px'})
                    ]),
                    html.Div(id='tabs-content', style={'padding': '20px', 'borderRadius': '0 0 10px 10px', 'backgroundColor': 'white', 'boxShadow': '2px 2px 5px #ccc'}),
                ], style={'backgroundColor': colors['background'], 'padding': '20px', 'marginTop': '20px', 'borderRadius': '10px', 'boxShadow': '2px 2px 5px #ccc'}),
                width=12
            )
        ]),
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
    Output("tabs-content", "children"),
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

    host_tab_content = html.Div([
        html.Div([
            
            html.Div([
                html.Label("Endereço IP:", style={'fontWeight': 'bold', 'color': colors['text']}),
                html.Div(host_info['addresses']['ipv4'], style={'marginBottom': '10px', 'color': colors['text']}),
                html.Label("Nome do Host:", style={'fontWeight': 'bold', 'color': colors['text']}),
                html.Div(host_info['hostnames'][0]['name'] if host_info['hostnames'] else 'Desconhecido', style={'marginBottom': '10px', 'color': colors['text']}),
                html.Label("Sistema Operacional:", style={'fontWeight': 'bold', 'color': colors['text']}),
                html.Div(host_info['osmatch'][0]['name'] if 'osmatch' in host_info else 'Desconhecido', style={'marginBottom': '10px', 'color': colors['text']}),
                html.Label("Endereço MAC:", style={'fontWeight': 'bold', 'color': colors['text']}),
                html.Div(host_info['addresses']['mac'] if 'mac' in host_info['addresses'] else 'Desconhecido', style={'marginBottom': '10px', 'color': colors['text']}),
                html.Label("Tempo de Resposta:", style={'fontWeight': 'bold', 'color': colors['text']}),
                html.Div(f"{host_info['rtt']} ms" if 'rtt' in host_info else 'Desconhecido', style={'marginBottom': '10px', 'color': colors['text']}),
            ], style={'float': 'left', 'width': '50%'}),
            html.Div([
              
                dash_table.DataTable(
                    id='port-table',
                    columns=[{"name": i, "id": i} for i in results_df.columns],
                    data=results_df.to_dict('records'),
                    style_table={'overflowX': 'auto'},
                    style_cell={'minWidth': '50px', 'maxWidth': '180px', 'overflow': 'hidden', 'textOverflow': 'ellipsis', 'color': colors['text']},
                    style_header={'backgroundColor': colors['accent'], 'fontWeight': 'bold'},
                ),
            ], style={'float': 'right', 'width': '50%'}),
        ])
    ])

    return host_tab_content

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
