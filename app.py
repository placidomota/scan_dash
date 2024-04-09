import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
import nmap
import pandas as pd
import socket

app = dash.Dash(__name__)

# Layout do aplicativo
app.layout = html.Div([
    html.Div([
        html.H1("Scanner de Host Avançado", style={'textAlign': 'center', 'marginBottom': '20px', 'color': '#333'}),
        html.Div([
            dcc.Input(id="input-url", type="text", placeholder="Insira a URL do host...", style={'width': '100%', 'marginBottom': '10px', 'padding': '10px', 'border': '1px solid #ccc', 'borderRadius': '5px'}),
            dcc.Checklist(
                id="nmap-options",
                options=[
                    {'label': '-F (Fast scan)', 'value': '-F'},
                    #{'label': '-O (OS detection)', 'value': '-O'},
                    {'label': '-sV (Service detection)', 'value': '-sV'},
                    {'label': '-p (Port range)', 'value': '-p'}
                ],
                value=[],
                style={'marginBottom': '10px'}
            ),
            html.Button(id="submit-button", n_clicks=0, children="Executar Scanner", style={'marginRight': '10px', 'backgroundColor': '#4CAF50', 'color': 'white', 'padding': '10px 20px', 'border': 'none', 'borderRadius': '5px', 'cursor': 'pointer'}),
            html.Button(id="clear-button", n_clicks=0, children="Limpar", style={'backgroundColor': '#f44336', 'color': 'white', 'padding': '10px 20px', 'border': 'none', 'borderRadius': '5px', 'cursor': 'pointer'}),
            dcc.Loading(id="loading-output", children=[html.Div(id="output-results", style={'marginTop': '20px'})], type='circle', fullscreen=True)
        ], style={'maxWidth': '500px', 'margin': 'auto', 'backgroundColor': '#f9f9f9', 'padding': '20px', 'borderRadius': '10px', 'boxShadow': '0 4px 8px rgba(0,0,0,0.1)'})
    ], style={'fontFamily': 'Arial, sans-serif'})
])

# Função para obter o endereço IP a partir da URL
def get_ip_from_url(url):
    try:
        ip = socket.gethostbyname(url)
        return ip
    except Exception as e:
        return None

# Callback para executar o scanner quando o botão é clicado
@app.callback(
    Output("output-results", "children"),
    [Input("submit-button", "n_clicks"),
     Input("clear-button", "n_clicks")],
    [State("input-url", "value"),
     State("nmap-options", "value")]
)
def update_output(submit_clicks, clear_clicks, url, options):
    if dash.callback_context.triggered[0]['prop_id'].split('.')[0] == 'submit-button':
        if submit_clicks > 0 and url:
            # Obtém o endereço IP da URL
            ip = get_ip_from_url(url)
            if ip:
                # Executa o scanner de host
                results_df, host_info = scan_host(ip, options)
                if results_df is not None:
                    return html.Div([
                        html.H3("Resultados da Varredura", style={'textAlign': 'center', 'marginBottom': '20px', 'color': '#333'}),
                        html.Div([
                            html.Div([
                                html.Label("Endereço IP:", style={'fontWeight': 'bold'}),
                                html.Div(host_info['addresses']['ipv4'], style={'marginBottom': '10px'}),
                                html.Label("Sistema Operacional:", style={'fontWeight': 'bold'}),
                                html.Div(host_info['osmatch'][0]['name'] if 'osmatch' in host_info else 'Desconhecido', style={'marginBottom': '10px'}),
                                html.Label("Endereço MAC:", style={'fontWeight': 'bold'}),
                                html.Div(host_info['addresses']['mac'] if 'mac' in host_info['addresses'] else 'Desconhecido', style={'marginBottom': '10px'}),
                                html.Label("Tempo de Resposta:", style={'fontWeight': 'bold'}),
                                html.Div(f"{host_info['rtt']} ms" if 'rtt' in host_info else 'Desconhecido', style={'marginBottom': '10px'}),
                            ], style={'flex': '1'}),
                            html.Div([
                                html.Label("Portas Abertas e Serviços:", style={'fontWeight': 'bold'}),
                                html.Table([
                                    html.Thead(html.Tr([html.Th("Porta"), html.Th("Serviço")])),
                                    html.Tbody([
                                        html.Tr([html.Td(port), html.Td(service)]) for port, service in zip(results_df['Porta'], results_df['Serviço'])
                                    ])
                                ])
                            ], style={'flex': '1', 'overflowY': 'auto', 'maxHeight': '400px'})
                        ], style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'flex-start', 'color': '#333'}),
                    ])
                else:
                    return html.Div("Erro ao executar a varredura. Verifique se as opções são válidas.", style={'textAlign': 'center', 'color': 'red'})
            else:
                return html.Div("URL inválida. Por favor, insira uma URL válida.", style={'textAlign': 'center', 'color': 'red'})
    elif dash.callback_context.triggered[0]['prop_id'].split('.')[0] == 'clear-button':
        return ''

# Função para executar o scanner de host
def scan_host(host, options):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=host, arguments=' '.join(options))
        host_info = nm[host]
        open_ports = host_info['tcp'].items()
        
        # Organize os resultados em um DataFrame para fácil visualização
        results_df = pd.DataFrame(open_ports, columns=['Porta', 'Detalhes'])
        results_df['Serviço'] = results_df['Detalhes'].apply(lambda x: x.get('name', 'Desconhecido'))
        
        return results_df, host_info
    except Exception as e:
        print(e)
        return None, None

if __name__ == "__main__":
    app.run_server(debug=True)
