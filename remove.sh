# Nome da imagem Docker
NOME_DA_IMAGEM="scanner-de-host"

# Verifica se a imagem com o nome especificado já existe
if [ "$(docker images -q $NOME_DA_IMAGEM 2> /dev/null)" != "" ]; then
    # Remove a última imagem Docker com o nome especificado
    docker rmi $(docker images $NOME_DA_IMAGEM -q | head -n 1)
fi

# Constrói a nova imagem Docker
docker build -t $NOME_DA_IMAGEM . && \

# Executa o contêiner Docker
docker run --privileged -p 8050:8050 $NOME_DA_IMAGEM
