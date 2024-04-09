# Use a imagem base Python
FROM python:3.9-slim

# Atualize os pacotes e instale o Nmap
RUN apt-get update && apt-get install -y nmap

# Defina o diretório de trabalho dentro do contêiner
WORKDIR /app

# Copie os arquivos necessários para o contêiner
COPY app.py .
COPY requirements.txt .

# Instale as dependências da aplicação
RUN pip install -r requirements.txt

# Exponha a porta 8050 para acesso à aplicação
EXPOSE 8050

# Comando para executar a aplicação quando o contêiner for iniciado
CMD ["python", "app.py"]
