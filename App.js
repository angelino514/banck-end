const express = require('express')
const cors = require('cors')
const mysql = require('mysql2')
const multer = require('multer')
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt')
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express()
require("dotenv").config();
const upload = multer({
   storage: multer.memoryStorage()
})



const origensPermitidas = [
   'http://localhost:5173',
   'https://painel-admin-amber-pi.vercel.app',
   'https://angelino-eurico-dev.vercel.app/'
]

app.use(cors({
   origin: origensPermitidas,
   credentials: true
}))


app.use(cookieParser())
app.use(express.json())

const db = mysql.createConnection({
   host: process.env.DB_HOST,
   port: process.env.DB_PORT,
   user: process.env.DB_USER,
   password: process.env.DB_PASSWORD,
   database: process.env.DB_NAME,
   timezone: 'Z'
})


db.connect((err) => {
   if (err) throw err
})


// Configuracao para enviar email
const transporter = nodemailer.createTransport({
   host: 'smtp.gmail.com',
   port: 587,
   secure: false,
   auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.SENHA_APP
   }
})

function criarCookie(res, nome, valor, maxAge) {
   res.cookie(nome, valor, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: maxAge
   })
}

// Iniciar sessao
app.post('/entrar', upload.none(), async (req, res) => {

   const { email, senha } = req.body

   if (typeof email !== 'string' || typeof senha !== 'string') {
      return res.status(400).json({
         mensagem: 'Dados inválidos',
         error: true
      });
   }

   if (email.trim() === '' || senha.trim() === '') {
      return res.status(400).json({
         mensagem: 'Preencha todos os campos',
         error: true
      })
   }

   if (!email.includes('@') || !email.includes('gmail.com')) {
      return res.status(400).json({
         mensagem: 'Email inválido',
         error: true
      })
   }

   db.query('select * from adimin', async (erro, sucesso) => {

      if (erro) {
         return res.status(500).json({
            mensagem: 'falha ao iniciar sessão',
            error: true
         })
      }

      const verificar = sucesso.find(
         p => p.email == email
      )

      if (verificar) {
         if (await compararSenhas(senha, verificar.senha)) {
            const sqlSessao = `
         insert into sessoes_adimin
         (adimin_id, token, expiracao)
         values (?, ?, ?)
      `
            const token = crypto.randomBytes(32).toString("hex")

            const expiracao = new Date(
               Date.now() + 2 * 60 * 60 * 1000
            )

            const dataMysql = expiracao
               .toISOString()
               .slice(0, 19)
               .replace("T", " ")


            db.query(
               sqlSessao,
               [verificar.id, token, dataMysql],
               (erroSQL) => {

                  if (erroSQL) {
                     return res.status(500).json({
                        mensagem: 'Erro ao criar sessão',
                        error: true
                     })
                  }

                  criarCookie(res, 'sessao', token, 2 * 60 * 60 * 1000);
                  return res.json({
                     mensagem: 'Sessão Iniciada com sucesso',
                     error: false
                  })
               }
            )
            return
         }

         return res.json({
            mensagem: 'Senha incorecta',
            error: true
         })
      }
      return res.status(404).json({
         mensagem: 'Usuário não encontrado',
         error: true
      })
   })
})


// Senha 
async function compararSenhas(senhaDigitada, senhaHash) {
   const senhaCorreta = await bcrypt.compare(
      senhaDigitada,
      senhaHash
   )
   return senhaCorreta
}

// Verificar Sessao
async function verificarSessao({ cookie }) {

   const sql = `
    SELECT adimin_id, expiracao
    FROM sessoes_adimin
    WHERE token = ?
    AND expiracao > UTC_TIMESTAMP()
  `

   try {

      const [resultado] = await db.promise().query(sql, [cookie])

      if (resultado.length === 0) {
         return {
            id: null,
            mensagem: 'Sessão expirada ou não encontrada',
            expiracao: null,
            autenticacao: false
         }
      }

      return {
         id: resultado[0].adimin_id,
         mensagem: 'Sessão válida',
         expiracao: resultado[0].expiracao,
         autenticacao: true
      }

   } catch (erro) {

      return {
         id: null,
         mensagem: 'Erro ao consultar sessão',
         expiracao: null,
         autenticacao: false
      }
   }
}

// Permissão
async function permisao(token) {

   const sessao = await verificarSessao({
      cookie: token
   })

   const expiracao = sessao.expiracao
   const admin = sessao.id
   const autenticacao = sessao.autenticacao

   if (new Date() < new Date(expiracao)) {

      return {
         mensagem: "Sessão em andamento",
         admin: admin,
         autenticacao: autenticacao
      }

   } else {

      return {
         mensagem: "Sessão expirada",
         admin: admin,
         autenticacao: false
      }
   }
}


app.get('/admin', async (req, res) => {

   // Permitir 
   const token = req.cookies.sessao

   if (!token) {
      return res.json({
         mensagem: "Usuário não autenticado",
         erro: true
      })
   }

   const resultado = await permisao(token)

   if (resultado.autenticacao === false) {
      return res.json({
         mensagem: resultado.mensagem,
         erro: true
      })
   }


   const sql = `SELECT nome FROM adimin WHERE id = ?`
   const [adimin] = await db.promise().query(sql, [resultado.admin])
   if (adimin.length === 0) {
      return res.status(500).json({
         mensagem: 'Sessão não encontrada',
         erro: true,
      })
   }

   return res.json({
      mensagem: "Sucesso",
      erro: false,
      adimin: adimin[0]
   })

})


// Enviar codigo por email
async function enviarEmail({ email }) {

   // Gerar Codigo para validar dados
   const codigo = Math.floor(100000 + Math.random() * 900000)
   try {
      await transporter.sendMail({
         from: process.env.EMAIL_USER,
         to: email,
         subject: 'Confirmação de e-mail',
         text: 'Código de confirmação',
         html: ` <div>
            <h1> Olá! </h1>
            <p>Meu nome é Angelino Eurico e sou o desenvolvedor deste sistema.

              Para confirmar que este endereço de e-mail está ativo e pertence a você, utilize o código de verificação abaixo:
            </p>
            <strong>Código de verificação: ${codigo}</strong>
            <p>
              Digite este código na página de verificação para concluir o processo.

              Obrigado pela colaboração.

              Atenciosamente,
              Angelino Eurico
              Desenvolvedor
            </p>
          </div>`
      })
      return { erro: false, codigo: codigo }

   } catch (erro) {
      return { erro: true }
   }
}

app.post('/novousuario', upload.none(), async (req, res) => {

   const { nome, sobrenome, email, senha } = req.body
   if (
      typeof nome !== 'string' ||
      typeof sobrenome !== 'string' ||
      typeof email !== 'string' ||
      typeof senha !== 'string'
   ) {
      return res.status(400).json({
         mensagem: 'Tipos de dados inválidos',
         erro: true
      })
   }

   if (
      nome.trim() === '' ||
      sobrenome.trim() === '' ||
      email.trim() === '' ||
      senha.trim() === ''
   ) {
      return res.status(400).json({
         mensagem: 'Todos os dados devem ser preenchidos',
         erro: true
      })
   }

   if (!email.includes('@') || !email.includes('gmail.com')) {
      return res.status(400).json({
         mensagem: 'Email inválido',
         erro: true
      })
   }


   // Verificar se existe um usuario com email digitado 
   const [existeUsuario] = await db.promise().query(`select * from adimin where email = ? `, [email])
   if (existeUsuario.length !== 0) {
      return res.json({ mensagem: 'Este email já está cadastrado', erro: true })
   }

   // Usuario Pendente
   const [resultado] = await db.promise().query(`select email from validacao_dados where email = ? `, [email])
   if (resultado.length !== 0) {

      const informacoes = await enviarEmail({ email: email })

      if (informacoes.erro === false) {
         const token = crypto.randomBytes(32).toString('hex')
         // Actulizar os dados no SQl
         const sql = ` UPDATE validacao_dados SET codigo = ? , expiracao = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 90 SECOND), token = ? WHERE email = ?`
         const [actualizar] = await db.promise().query(sql, [informacoes.codigo, token, email])
         if (actualizar.changedRows > 0) {
            criarCookie(res, 'validacao', token, 30 * 60 * 1000)
            return res.json({ mensagem: 'foi enviado um novo codigo', erro: false })
         }
         return res.status(500).json({
            mensagem: 'Nao foi possivel enviar um novo codigo',
            erro: true
         })
      }
      return res.status(500).json({
         mensagem: 'Erro de conexao com a internet', erro: true
      })
   }

   // Enviar codigo ao email ao novo usaurio
   const novaInformacoes = await enviarEmail({ email: email })
   if (novaInformacoes.erro === false) {

      const senhaHash = await bcrypt.hash(senha, 10)
      const token = crypto.randomBytes(32).toString('hex')
      const sqlAdicionar = `INSERT INTO validacao_dados (nome, sobrenome, email, senha, codigo, expiracao, token) VALUES (?, ?, ?, ?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 90 SECOND), ?)`

      const [adicionar] = await db.promise().query(sqlAdicionar, [nome, sobrenome, email, senhaHash, novaInformacoes.codigo, token])

      if (adicionar.affectedRows > 0) {
         criarCookie(res, 'validacao', token, 30 * 60 * 1000)
         return res.json({
            mensagem: 'Dados registrados. Verifique o seu email.',
            erro: false
         })
      }

      return res.status(500).json({
         mensagem: 'Não foi possível registrar os dados',
         erro: true
      })

   }
   return res.status(500).json({
      mensagem: 'Erro de conexão com a internet', erro: true
   })

})



// Registrar um novo usuário e confirmar por email
app.post('/confirmarcodigo', upload.none(), async (req, res) => {

   const { codigo } = req.body
   const token = req.cookies.validacao

   if (!token || !codigo) {
      return res.json({ mensagem: 'Erro ao verificar codigo', erro: true })
   }

   if (typeof token !== 'string' || typeof codigo !== 'string') {
      return res.json({ mensagem: 'Erro ao verificar codigo', erro: true })
   }

   const sqlVerificar = `
    SELECT *
    FROM validacao_dados
    WHERE token = ?
    AND expiracao > UTC_TIMESTAMP()
`

   const [verificar] = await db.promise().query(sqlVerificar, [token]);
   if (verificar.length === 0) {
      return res.status(500).json({
         mensagem: 'Código expirado',
         erro: true
      })
   }

   if (codigo != verificar[0].codigo) {
      return res.status(500).json({
         mensagem: 'Código errado',
         erro: true
      })
   }

   const slAdimin = `INSERT INTO adimin (nome , email , senha , sobrenome) VALUES (? ,? , ? ,?)`
   const [adicionarAdimin] = await db.promise().query(slAdimin, [verificar[0].nome, verificar[0].email, verificar[0].senha, verificar[0].sobrenome])

   if (adicionarAdimin.affectedRows > 0) {

      const sqlEliminarPendente = `DELETE FROM validacao_dados WHERE codigo = ? AND token = ?`
      const [eliminarPendente] = await db.promise().query(sqlEliminarPendente, [codigo, token])

      return res.json({
         mensagem: 'Registro realizado com sucesso',
         erro: false
      })
   }

   return res.status(500).json({
      mensagem: 'Erro ao cadastrar',
      erro: true
   })
})


// Reenvisr codigo
app.post('/novocodigo', upload.none(), async (req, res) => {

   const token = req.cookies.validacao
   if (!token) {
      return res.status(401).json({
         mensagem: "Não foi possível reenviar o código. A sua validação expirou."
      })
   }


   const sql = `SELECT email FROM validacao_dados WHERE token = ?`
   const [consultar] = await db.promise().query(sql, [token])

   if (consultar.length === 0) {
      return res.status(401).json({
         mensagem: "Não foi possível reenviar o código. A sua validação expirou."
      })
   }

   const verificar = await enviarEmail({ email: consultar[0].email })
   if (verificar.erro === true) {
      return res.status(400).json({
         mensagem: "Não foi possível enviar o email. Tente novamente."
      })
   }

   const sqlActualizar = `UPDATE validacao_dados SET codigo = ? ,expiracao = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 150 SECOND) WHERE token = ?`
   const [actulizar] = await db.promise().query(sqlActualizar, [verificar.codigo, token])
   if (actulizar.affectedRows > 0) {
      return res.status(200).json({
         mensagem: "Foi enviado um novo código para o seu email."

      })
   }

})


app.get('/produtosadmin', async (req, res) => {

   // Permitir 
   const token = req.cookies.sessao

   if (!token) {
      return res.json({
         mensagem: "Usuário não autenticado",
         erro: true
      })
   }

   const resultado = await permisao(token)
   if (resultado.autenticacao === false) {
      return res.json({
         mensagem: resultado.mensagem,
         erro: true,
         autenticacao: resultado.autenticacao
      })
   }

   const sql = `SELECT * FROM produtos`
   const [produtos] = await db.promise().query(sql)
   return res.json(produtos)

})


// Imagens Principal
app.get('/imagens/:id', async (req, res) => {

   const { id } = req.params
   try {
      const sql = `SELECT arquivo, tipo FROM imagens WHERE produto_id = ?`
      const [resultado] = await db.promise().query(sql, [id])
      if (resultado.length === 0) {
         return res.status(404).json({
            erro: 'Imagem não encontrada'
         })
      }
      const imagem = resultado[0]
      res.set('Content-Type', imagem.tipo)
      res.send(imagem.arquivo)
      return
   } catch (erro) {
      res.status(500).json({
         erro: 'Erro ao buscar imagem'
      })
   }
})


// Pesquisa 
app.get("/buscar/:accao/:valor", async (req, res) => {

   const token = req.cookies.sessao
   if (!token) {
      return res.json({
         mensagem: "Usuário não autenticado",
         erro: true
      })
   }

   const resultado = await permisao(token)
   if (resultado.autenticacao === false) {
      return res.status(401).json({
         mensagem: resultado.mensagem,
         erro: true,
         autenticacao: resultado.autenticacao
      })
   }

   try {

      const { valor, accao } = req.params;
      if (!valor) {
         return res.status(400).json({
            mensagem: "Informe um valor para buscar"
         })
      }

      if (valor === 'todas') {
         const [produtos] = await db.promise().query('SELECT * FROM produtos')
         return res.json(produtos)
      }

      if (accao === 'busca') {
         const [produtos] = await db.promise().query(
            "SELECT * FROM produtos WHERE nome LIKE ?",
            [`%${valor}%`]
         );
         return res.json(produtos)
      }
      if (accao === 'categoria') {
         const [produtos] = await db.promise().query(
            "SELECT * FROM produtos WHERE categoria LIKE ?",
            [`%${valor}%`]
         );
         return res.json(produtos)
      }
      return res.status(400).json({
         mensagem: "Ação de busca inválida"
      })

   } catch (erro) {
      res.status(500).json({
         mensagem: "Erro ao buscar produtos"
      })
   }
})


//  Adicionar produtos 
app.post('/adicionar', upload.array('imagens', 5), async (req, res) => {

   // Permitir 
   const token = req.cookies.sessao
   if (!token) {
      return res.json({
         mensagem: 'Sessão não encontrada',
         autenticacao: false
      })
   }

   const resultado = await permisao(token)
   if (resultado.autenticacao === false) {
      return res.json({
         mensagem: resultado.mensagem,
         erro: true,
         autenticacao: resultado.autenticacao
      })
   }

   const { nome, preco, descricao, categoria, stock, especificao, especificao2, status } = req.body

   // Verificar dados obrigatórios
   if (!nome || !preco || !descricao || !categoria || !stock || !especificao || !especificao2) {
      return res.status(400).json({
         erro: 'Todos os dados obrigatórios devem ser enviados'
      })
   }

   // Verificar imagens
   if (!req.files || req.files.length === 0) {
      return res.status(400).json({
         erro: 'É necessário enviar pelo menos uma imagem'
      })
   }

   // Verificar se já existe
   const sqlExiste = `SELECT nome, preco, categoria FROM produtos WHERE nome = ? AND preco = ? AND categoria = ?`
   const [existeProduto] = await db.promise().query(sqlExiste, [nome, preco, categoria])
   if (existeProduto.length !== 0) {
      return res.json({
         mensagem: 'Já existe um produto com as mesmas especificações. Se deseja alterá-lo, vá para a página de editar.',
         erro: true
      })
   }

   const sqlAicionar = `INSERT INTO  produtos (nome, descricao, preco, stock, categoria , promocao) VALUES (?,?,?,?,?,?)`
   const [adicionar] = await db.promise().query(sqlAicionar, [nome, descricao, preco, stock, categoria, status])

   if (adicionar.affectedRows > 0) {

      const id = adicionar.insertId
      // Adiconar Imagens do produto
      const sqlImagens = `INSERT INTO imagens (produto_id, arquivo, tipo) VALUES(?,?,?)`
      for (const imagem of req.files) { await db.promise().query(sqlImagens, [id, imagem.buffer, imagem.mimetype]) }

      const sqlespecificacoes = `INSERT INTO especificacoes (produto_id , valor ) VALUES (?, ?)`
      const itensEspecificao = JSON.parse(especificao)
      for (const iten of itensEspecificao) { await db.promise().query(sqlespecificacoes, [id, iten]) }

      const sqlespecificacoes_otr = `INSERT INTO outras_especificacoes (produto_id , valor ) VALUES (?, ?)`
      const itensEspecificao_otr = JSON.parse(especificao2)
      for (const iten of itensEspecificao_otr) {
         await db.promise().query(sqlespecificacoes_otr, [id, iten])
      }

      return res.json({
         mensagem: 'Produtos enviados com sucesso',
         erro: false
      })
   }
})


app.delete('/eliminar/:id', async (req, res) => {
   const { id } = req.params;
   // Permitir 
   const token = req.cookies.sessao
   if (!token) {
      return res.json({
         mensagem: 'Sessão não encontrada',
         autenticacao: false
      })
   }

   const resultado = await permisao(token)
   if (resultado.autenticacao === false) {
      return res.json({
         mensagem: resultado.mensagem,
         erro: true,
         autenticacao: resultado.autenticacao
      })
   }
   const sql = `DELETE FROM produtos WHERE id = ?`
   const [deletar] = await db.promise().query(sql, [id])
   if (deletar.affectedRows > 0) {
      return res.json({
         erro: false,
         mensagem: 'Produto eliminado com sucesso'
      })
   }
   return res.json({
      erro: true,
      mensagem: 'Falha ao eliminar o produto tente novamente'
   })
})

app.get('/buscareditar/:id', async (req, res) => {

   // Permitir 
   const token = req.cookies.sessao
   if (!token) {
      return res.json({
         mensagem: 'Sessão não encontrada',
         autenticacao: false
      })
   }

   const resultado = await permisao(token)
   if (resultado.autenticacao === false) {
      return res.json({
         mensagem: resultado.mensagem,
         erro: true,
         autenticacao: resultado.autenticacao
      })
   }

   const { id } = req.params
   const sql = `SELECT id , nome , descricao , preco , categoria , stock , promocao  FROM produtos WHERE id = ?`
   const sqlmgs = `SELECT id , produto_id FROM imagens WHERE produto_id = ?`
   const sqlEsp = `SELECT * FROM especificacoes WHERE produto_id = ?`
   const sqlOutEsp = `SELECT * FROM outras_especificacoes WHERE produto_id = ?`

   const [produto] = await db.promise().query(sql, [id])
   const [imagens] = await db.promise().query(sqlmgs, [id])
   const [esp] = await db.promise().query(sqlEsp, [id])
   const [outEsp] = await db.promise().query(sqlOutEsp, [id])

   if (produto.length === 0) {
      return res.json({
         mensagem: 'Produto não encontrado',
         erro: true
      })
   }

   return res.json([{
      id: produto[0].id, nome: produto[0].nome,
      descricao: produto[0].descricao, preco: produto[0].preco,
      categoria: produto[0].categoria, stock: produto[0].stock, promocao: produto[0].promocao,
      esp: esp,
      outEsp: outEsp,
      imagens: imagens
   }])
})


app.get('/imagem/:id', async (req, res) => {

   const { id } = req.params
   try {
      const sql = `
         SELECT arquivo, tipo
         FROM imagens
         WHERE id = ?
      `
      const [resultado] = await db.promise().query(sql, [id])
      if (resultado.length === 0) {
         return res.status(404).json({
            erro: 'Imagem não encontrada'
         })
      }

      const imagem = resultado[0]
      res.set('Content-Type', imagem.tipo)
      res.send(imagem.arquivo)

   } catch (erro) {
      console.error(erro)

      res.status(500).json({
         erro: 'Erro ao buscar imagem'
      })
   }

})

app.put('/editarprodutos/:id', upload.array('imagens', 5), async (req, res) => {

   // Permitir 
   const token = req.cookies.sessao
   if (!token) {
      return res.json({
         mensagem: 'Sessão não encontrada',
         autenticacao: false
      })
   }

   const resultado = await permisao(token)
   if (resultado.autenticacao === false) {
      return res.json({
         mensagem: resultado.mensagem,
         erro: true,
         autenticacao: resultado.autenticacao
      })
   }


   const { id } = req.params
   const { name, description, stock, price, especificacoes, otherespecificacoes, existingImages } = req.body

   const originalespecificacoes = JSON.parse(especificacoes)
   const origainalotherespecificacoes = JSON.parse(otherespecificacoes)
   const originalexistingImages = JSON.parse(existingImages)

   if (!name || !description || originalespecificacoes.length === 0
      || origainalotherespecificacoes.length === 0 || originalexistingImages.length === 0) {
      return res.json({ erro: true, mensagem: 'Valores Inseridos inválidos' })
   }

   const stockNumero = Number(stock);
   const priceNumero = Number(price);

   if (
      !Number.isInteger(stockNumero) ||
      stockNumero <= 0 ||
      !Number.isFinite(priceNumero) ||
      priceNumero <= 0
   ) {
      return res.status(400).json({
         erro: true,
         mensagem: 'Valores inseridos inválidos.'
      });
   }


   const sqlUpdate = ` UPDATE produtos SET nome = ?, descricao = ?, stock = ?, preco = ?  WHERE id = ?`
   const [resultadoUpdate] = await db.promise().query(sqlUpdate, [name, description, stock, price, id]);

   if (resultadoUpdate.affectedRows > 0) {

      // Eliminar o estado antigo das especificacoes
      const sqlDelete = 'DELETE FROM especificacoes WHERE produto_id = ?'
      await db.promise().query(sqlDelete, [id])

      // Actulizar com os novos valores
      originalespecificacoes.forEach(async (item) => {
         const sqlInsert = `INSERT INTO especificacoes (produto_id, valor) VALUES (?, ?)`
         await db.promise().query(sqlInsert, [id, item.valor])
      })

      // Eliminar o estado antigo das outras especificacoes
      const sqlDeleteOher = 'DELETE FROM outras_especificacoes WHERE produto_id = ?'
      await db.promise().query(sqlDeleteOher, [id])

      // Actulizar com os novos valores
      origainalotherespecificacoes.forEach(async (item) => {
         const sqlInsert = `INSERT INTO outras_especificacoes (produto_id, valor) VALUES (?, ?)`
         await db.promise().query(sqlInsert, [id, item.valor])
      })

      const sqlStatus = `SELECT * FROM imagens WHERE produto_id = ?`
      const [oldersStatusImgs] = await db.promise().query(sqlStatus, [id])

      const newImagens = []
      // Adicionar as imagens novas, se existirem
      for (const imagem of req.files) {
         newImagens.push({
            produto_id: id,
            arquivo: imagem.buffer,
            tipo: imagem.mimetype
         })
      }

      const newStutusImgs = oldersStatusImgs.filter(p => originalexistingImages.includes(p.id))
      if (newStutusImgs.length > 0) {
         newStutusImgs.forEach(element => {
            newImagens.push({
               produto_id: element.produto_id,
               arquivo: element.arquivo,
               tipo: element.tipo
            })
         })
      }

      if (newImagens.length > 0) {
         const sqlDelete = 'DELETE FROM imagens WHERE produto_id = ?';
         await db.promise().query(sqlDelete, [id])
         for (const imagem of newImagens) {
            const sqlInsert = `INSERT INTO imagens (produto_id, arquivo, tipo) VALUES (?, ?, ?)`
            await db.promise().query(sqlInsert, [imagem.produto_id, imagem.arquivo, imagem.tipo]);
         }
      }

      return res.json({
         erro: false,
         mensagem: 'Produto atualizado com sucesso!'
      })
   }

   return res.json({
      erro: true,
      mensagem: 'Não foi possível atualizar o produto. Verifica os dados e tenta novamente.'
   })

})

app.post('/mensgemportffolio', upload.none(), async (req, res) => {

   const { name, email, messege } = req.body

   if (!name || !email || !messege) {
      return res.json({
         erro: true,
         mensagem: 'Todos os campos devem ser textos válidos'
      })
   }

   if (! typeof name === 'string' || ! typeof email === 'string' || ! typeof messege === 'string') {
      return res.json({
         erro: true,
         mensagem: 'Todos os campos devem ser textos válidos'
      })
   }

   const regex = {
      name: /^[A-Za-zÀ-ÿ\s'-]+$/,
      email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
      message: /\S/
   }

   if (!regex.name.test(name.trim()) || !regex.email.test(email.trim())
      || !regex.message.test(messege.trim())) {
      return res.json({
         erro: true,
         mensagem: 'Valores  Inválidos'
      })
   }

   try {
      await transporter.sendMail({
         from: process.env.EMAIL_USER,
         to: email,
         subject: name,
         text: messege,
      })

      return res.json({
         erro: false,
      })

   } catch (erro) {
      return res.json({
         erro: true,
         mensagem: 'Mensagem Não Enviada'
      })
   }
})

module.exports = app;