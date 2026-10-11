Backend — API do Sistema de E-commerce

Backend responsável pela API REST do sistema de e-commerce. Desenvolvido com Node.js e Express, fornece os serviços necessários para autenticação de administradores, gestão de produtos, imagens, especificações e comunicação com a base de dados MySQL.

Funcionalidades

Autenticação e sessões

- Registo de administradores.
- Validação de e-mail através de código.
- Autenticação através de e-mail e palavra-passe.
- Hash das palavras-passe com "bcrypt".
- Criação de tokens de sessão.
- Armazenamento da sessão através de cookie "HTTP-only".
- Verificação da sessão nas rotas protegidas.
- Expiração das sessões.
- Proteção das operações administrativas.

Gestão de produtos

A API disponibiliza operações para:

- Criar produtos.
- Listar produtos.
- Pesquisar produtos.
- Consultar um produto específico.
- Editar produtos.
- Eliminar produtos.
- Atualizar stock.
- Atualizar preço e promoção.
- Atualizar categoria.
- Gerir especificações.

Gestão de imagens

O backend utiliza "Multer" para receber os ficheiros enviados pelo frontend.

As imagens são:

- Recebidas através de "multipart/form-data".
- Limitadas a até 5 imagens por produto.
- Armazenadas na base de dados como dados binários.
- Associadas ao respetivo produto através de uma chave estrangeira.
- Disponibilizadas através de uma rota específica da API.

Durante a edição de um produto, a API permite manter imagens existentes, remover imagens selecionadas e adicionar novas imagens.

Pesquisa e paginação

A API suporta:

- Pesquisa de produtos.
- Filtragem.
- Paginação.
- "LIMIT" e "OFFSET" nas consultas SQL.

Isso permite controlar a quantidade de dados retornados em cada requisição.

---

Tecnologias utilizadas

Runtime e framework

- Node.js
- Express.js

Base de dados

- MySQL
- MySQL2

Autenticação e segurança

- bcrypt
- crypto
- cookie-parser
- CORS

Upload e comunicação

- Multer
- Nodemailer

---

Arquitetura

O backend funciona como uma camada intermediária entre o frontend e a base de dados.

                    ┌───────────────────┐
                    │     Frontend      │
                    │ React + Vite      │
                    └─────────┬─────────┘
                              │
                         HTTP / REST
                              │
                              ▼
                    ┌───────────────────┐
                    │      Backend      │
                    │ Node.js + Express │
                    └─────────┬─────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                 SQL / DB          Serviços
                    │              externos
                    ▼                   │
             ┌─────────────┐            │
             │    MySQL    │      ┌─────▼─────┐
             │             │      │   Email   │
             └─────────────┘      └───────────┘

Fluxo de uma requisição

Frontend
   │
   │ HTTP Request
   ▼
Express
   │
   ├── Autenticação
   │
   ├── Validação
   │
   ├── Regra de negócio
   │
   ▼
MySQL
   │
   ▼
Resposta JSON
   │
   ▼
Frontend

O backend recebe a requisição, verifica a autenticação quando necessário, valida os dados, executa a operação correspondente e retorna uma resposta ao frontend.

---

API REST

A API é organizada através de endpoints específicos para cada operação.

Autenticação

POST   /novousuario
POST   /validacao_dados
POST   /entrar

Responsáveis pelo registo, validação e autenticação dos administradores.

Produtos

POST   /adicionar
GET    /produtosadmin
GET    /buscar/:valor
GET    /buscareditar/:id
PUT    /editarprodutos/:id
DELETE /eliminar/:id

Esses endpoints permitem realizar as principais operações CRUD sobre os produtos.

Imagens

GET /imagem/:id

Retorna a imagem armazenada no banco de dados juntamente com o seu respetivo "Content-Type".

---

Base de dados relacional

O backend utiliza MySQL e trabalha com um modelo relacional.

As principais entidades são separadas em tabelas, permitindo estabelecer relações através de chaves primárias e estrangeiras.

Administradores

A tabela "adimin" armazena os dados dos administradores.

adimin
├── id
├── nome
├── email
└── senha

O campo "id" identifica cada administrador.

Sessões

A tabela "sessoes_adimin" é utilizada para controlar as sessões autenticadas.

adimin 1 ───────── N sessoes_adimin

Um administrador pode possuir várias sessões.

Cada sessão possui um token e uma informação de expiração.

Produtos

A tabela "produtos" armazena os dados principais dos produtos.

produtos
├── id
├── nome
├── descricao
├── preco
├── categoria
├── stock
└── promocao

Imagens

As imagens são armazenadas numa tabela separada.

produtos 1 ───────── N imagens

Um produto pode possuir várias imagens.

Cada imagem possui uma referência ao produto através de "product_id".

Especificações

As especificações também possuem uma tabela própria.

produtos 1 ───────── N especificacoes

Isso permite que cada produto tenha várias especificações sem criar várias colunas na tabela "produtos".

Relacionamento geral

                    ┌─────────────────┐
                    │     adimin      │
                    └────────┬────────┘
                             │
                            1:N
                             │
                    ┌────────▼────────┐
                    │ sessoes_adimin  │
                    └─────────────────┘


                    ┌─────────────────┐
                    │    produtos     │
                    └────────┬────────┘
                             │
                   ┌─────────┴─────────┐
                   │                   │
                  1:N                 1:N
                   │                   │
          ┌────────▼────────┐  ┌───────▼────────────┐
          │     imagens     │  │   especificacoes   │
          └─────────────────┘  └────────────────────┘

---

Desenvolvimento

O backend foi desenvolvido seguindo uma arquitetura cliente-servidor, mantendo a responsabilidade da API separada da interface do utilizador.

O Express é responsável pelo processamento das requisições e definição das rotas, enquanto o MySQL é responsável pelo armazenamento persistente dos dados.

As operações de criação, leitura, atualização e eliminação utilizam consultas SQL através do "MySQL2".

A autenticação utiliza tokens de sessão, cookies "HTTP-only" e middleware para restringir o acesso às operações administrativas.

Para operações que envolvem imagens, o "Multer" processa os ficheiros recebidos pelo servidor antes do armazenamento na base de dados.

A comunicação com o frontend é realizada através de respostas JSON, permitindo que a API seja consumida independentemente da interface utilizada.
