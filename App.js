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
   'https://angelino-eurico-dev.vercel.app',
   'https://ecommerce-react-gamma-ruddy.vercel.app'
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
      sameSite: 'none',
      maxAge: maxAge,
      path: '/'
   })
}

function eliminarCookie(res, nome) {
   res.clearCookie(nome, {
      path: '/'
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

                  criarCookie(res, 'sessao', token, 2 * 60 * 60 * 1000)
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


// Loja Onlie 
// Verificar sessao
async function usuarioSessao(token) {

   try {
      const sql = `
         SELECT usuario_id, expira_em
         FROM sessoes_usuario
         WHERE token = ?
         AND expira_em > NOW()
      `

      const [sessao] = await db.promise().query(sql, [token])

      if (sessao.length === 0) {
         return {
            success: false,
            message: 'Sessão não encontrada.'
         }
      }

      return {
         success: true,
         message: 'Sessão encontrada.',
         usuarioId: sessao[0].usuario_id
      }

   } catch (error) {
      return {
         success: false,
         message: 'Erro ao verificar a sessão.'
      }
   }
}


app.post('/favoritosAdd', upload.none(), async (req, res) => {

   const token = req.cookies.sessaoUsuario
   const { produto_id, browserId } = req.body

   if (!produto_id || !browserId) {
      return res.status(500).json({
         message: 'Erro ao processar dados',
         success: false
      })
   }

   let sql
   let params

   async function existeFav({ condicao, valor }) {
      const sql = `SELECT id FROM favoritos WHERE ${condicao} = ? AND produto_id = ?`
      const [existe] = await db.promise().query(sql, [valor, produto_id])
      return existe.length === 0
   }

   if (!token) {
      if (await existeFav({ condicao: 'browser_id', valor: browserId })) {
         sql = `INSERT INTO favoritos (produto_id, browser_id , usuario_id) VALUES (? ,? , NULL)`
         params = [produto_id, browserId]
      }
   } else {
      const usuario = await usuarioSessao(token)
      if (usuario.success) {
         if (await existeFav({ condicao: 'usuario_id', valor: usuario.usuarioId })) {
            sql = `INSERT INTO favoritos(produto_id, browser_id , usuario_id) VALUES (? ,? ,?)`
            params = [produto_id, browserId, usuario.usuarioId]
         }
      }
   }

   await db.promise().query(sql, params)
   return res.status(200).json({ success: true, message: 'Item Adicionado aos favoritos' })
})

app.delete('/deleteFav', upload.none(), async (req, res) => {

   try {

      const { produto_id, browserId } = req.body
      const token = req.cookies.sessaoUsuario

      if (!produto_id || !browserId) {
         return res.status(400).json({
            success: false,
            message: 'Dados inválidos'
         })
      }

      if (token) {

         const result = await usuarioSessao(token)

         if (!result.success) {
            return res.status(401).json({
               success: false,
               message: 'Sessão inválida'
            })
         }

         await db.promise().query(
            `DELETE FROM favoritos
             WHERE produto_id = ? AND usuario_id = ?`,
            [produto_id, result.usuarioId]
         )

      } else {
         await db.promise().query(
            `DELETE FROM favoritos
             WHERE produto_id = ? AND browser_id = ?`,
            [produto_id, browserId]
         )
      }
      return res.json({
         success: true,
         message: 'Favorito eliminado'
      })
   } catch (err) {
      return res.status(500).json({
         success: false,
         message: 'Erro ao eliminar favorito'
      })
   }
})

app.post('/pegarFav', upload.none(), async (req, res) => {

   const token = req.cookies.sessaoUsuario
   const { browserId } = req.body

   if (!token) {
      await favoritos({ condicao: 'browser_id', valor: browserId })
   } else {
      const usuario = await usuarioSessao(token)
      if (usuario.success) {
         await favoritos({ condicao: 'usuario_id', valor: usuario.usuarioId })
      }
   }

   async function favoritos({ condicao, valor }) {
      const sql = `
      SELECT
         favoritos.id AS favorito_id,
         favoritos.produto_id,
         produtos.*
      FROM favoritos
      INNER JOIN produtos
      ON favoritos.produto_id = produtos.id
      WHERE favoritos.${condicao} = ?`

      const [itens] = await db.promise().query(sql, [valor])
      return res.status(200).json({
         success: true,
         favoritos: itens
      })
   }

})

app.get('/productsStore', async (req, res) => {

   const limit = 20
   const offset = Number(req.query.offset) || 0

   try {

      const sql = `SELECT * FROM produtos
         ORDER BY id LIMIT ? OFFSET ?`
      const [products] = await db.promise().query(
         sql,
         [limit, offset]
      )
      return res.json(products)

   } catch (error) {
      return res.status(500).json({
         erro: 'Erro interno do servidor'
      })
   }

})

app.get('/categoriasStores', upload.none(), async (req, res) => {

   const newProducts = []
   try {
      const sql = `
      SELECT *
      FROM produtos`
      const [products] = await db.promise().query(sql)
      products.forEach((product) => {
         const existe = newProducts.some(
            (item) => item.categoria === product.categoria
         )

         if (!existe) {
            newProducts.push(product)
         }
      })
      return res.json(newProducts)

   } catch (error) {
      return res.status(500).json({
         erro: 'Erro interno do servidor'
      })
   }
})


app.post('/searchStore/:action/:values', upload.none(), async (req, res) => {

   try {

      const { browserId } = req.body
      const { action, values } = req.params

      if (!action || !values || !browserId) {
         return res.status(500).json({
            success: false,
            message: 'Erro ao pesquisar'
         })
      }

      const limit = Number(req.query.limit) || 10
      const offset = Number(req.query.offset) || 0

      let sql
      let params

      if (action === 'Categories') {

         if (values === 'todas') {
            sql = `
            SELECT *
            FROM produtos ORDER BY id
            LIMIT ? OFFSET ?`
            params = [limit, offset]
         }

         else {
            sql = `
            SELECT *
            FROM produtos
            WHERE categoria = ?
            ORDER BY id
            LIMIT ? OFFSET ?
         `

            params = [values, limit, offset]
         }

      } else if (action === 'Search') {

         sql = `
            SELECT *
            FROM produtos
            WHERE nome LIKE ?
               OR descricao LIKE ? OR categoria LIKE ? OR promocao LIKE ?
            ORDER BY id
            LIMIT ? OFFSET ?
         `

         const pesquisa = `%${values}%`
         params = [pesquisa, pesquisa, pesquisa, pesquisa, limit, offset]


         const sqlExsite = `SELECT id FROM historico_pesquisas WHERE browser_id = ? AND pesquisa LIKE ? LIMIT 1`

         const [existeValues] = await db.promise().query(sqlExsite, [browserId, values])

         if (existeValues.length === 0) {
            await db.promise().query(
               `INSERT INTO historico_pesquisas (browser_id, pesquisa)
         VALUES (?, ?)`,
               [browserId, values]
            )
         }

      } else {
         return res.status(400).json({
            success: false,
            message: 'Tipo de pesquisa inválido.'
         })
      }
      const [produtos] = await db.promise().query(sql, params)
      return res.status(200).json({
         success: true,
         produtos: produtos
      })

   } catch (error) {
      return res.status(500).json({
         success: false,
         message: 'Erro ao pesquisar produtos.'
      })
   }
})

app.get('/detailsStore/:id', async (req, res) => {

   const { id } = req.params;
   try {
      // Buscar o produto
      const [products] = await db.promise().query(
         `SELECT id, nome, descricao, preco, categoria, stock, promocao
             FROM produtos
             WHERE id = ?`,
         [id]
      );

      if (products.length === 0) {
         return res.status(404).json({
            erro: 'Produto não encontrado'
         });
      }

      // Percorrer os produtos encontrados
      for (const product of products) {

         // Buscar imagens
         const [images] = await db.promise().query(
            `SELECT id, produto_id, arquivo, tipo
                 FROM imagens
                 WHERE produto_id = ?`,
            [product.id]
         );

         // Buscar especificações
         const [specifications] = await db.promise().query(
            `SELECT *
                 FROM especificacoes
                 WHERE produto_id = ?`,
            [product.id]
         );

         // Buscar outras especificações
         const [otherSpecifications] = await db.promise().query(
            `SELECT *
                 FROM outras_especificacoes
                 WHERE produto_id = ?`,
            [product.id]
         );

         // Adicionar os dados relacionados ao produto
         product.images = images;
         product.specifications = specifications;
         product.otherSpecifications = otherSpecifications;
      }

      return res.json(products);

   } catch (error) {
      return res.status(500).json({
         erro: 'Erro interno do servidor'
      });
   }
})

app.post('/historicoPesquisas', upload.none(), async (req, res) => {

   const { browserId } = req.body
   if (!browserId) {
      return res.status(400).json({
         message: 'Identificador do navegador não fornecido',
         success: false
      })
   }

   const sql = `SELECT id, pesquisa FROM historico_pesquisas
        WHERE browser_id = ? ORDER BY id DESC LIMIT 10`
   const [pesquisas] = await db.promise().query(sql, [browserId])
   return res.json(pesquisas)
})


app.post('/addCart', upload.none(), async (req, res) => {
   const {
      produto_id,
      preco,
      quantidade,
      promocao,
      browser_id,
      espSelecionado,
      outrasEspSelecionado
   } = req.body

   try {

      const token = req.cookies.sessaoUsuario
      const result = token ? await usuarioSessao(token)
         : { success: false }
      function userActivo(e) {
         if (e === true) {
            return {
               sqlVerificar: `SELECT id FROM carrinho WHERE produto_id = ? AND usuario_id = ?`,
               params: [produto_id, result.usuarioId],
               usuarioId: result.usuarioId
            }
         }

         if (e === false) {
            return {
               sqlVerificar: `SELECT id FROM carrinho
                WHERE produto_id = ? AND navegador_id = ? 
                AND usuario_id IS NULL` ,
               params: [produto_id, browser_id],
               usuarioId: null
            }
         }
      }

      const { sqlVerificar, params, usuarioId } = userActivo(result.success)
      const [existe] = await db.promise().query(sqlVerificar, params)
      if (existe.length > 0) {
         return res.status(409).json({
            success: false,
            mensagem: 'Produto já existe no carrinho'
         })
      }

      const sqlCart = `INSERT INTO carrinho (
            produto_id,
            navegador_id,
            preco,
            quantidade,
            promocao,
            usuario_id
         ) VALUES (?, ?, ?, ?, ?, ?)`
      const [cartResult] = await db.promise().query(sqlCart, [
         produto_id,
         browser_id,
         preco,
         quantidade,
         promocao,
         usuarioId
      ])

      const carrinhoId = cartResult.insertId
      if (espSelecionado) {
         await db.promise().query(`
            INSERT INTO especificacoes_selecionadas
            (carrinho_id, valor)
            VALUES (?, ?)
         `, [carrinhoId, espSelecionado])
      }

      if (outrasEspSelecionado) {
         await db.promise().query(`
            INSERT INTO outras_especificacoes_selecionadas
            (carrinho_id, valor)
            VALUES (?, ?)
         `, [carrinhoId, outrasEspSelecionado])
      }

      return res.status(201).json({
         success: true,
         mensagem: 'Produto adicionado ao carrinho'
      })

   } catch (error) {
      return res.status(500).json({
         success: false,
         erro: 'Erro interno do servidor'
      })
   }
})

app.post('/entrarUsaurio', upload.none(), async (req, res) => {

   try {
      const { email, password, browserId } = req.body

      if (!email || !password) {
         return res.status(400).json({
            success: false,
            message: 'Preencha todos os campos.'
         })
      }

      if (
         typeof email !== 'string' ||
         typeof password !== 'string'
      ) {
         return res.status(400).json({
            success: false,
            message: 'Formato de dados inválido.'
         })
      }


      const [users] = await db.promise().query(
         'SELECT * FROM usuarios WHERE email = ?',
         [email.trim()]
      )

      if (users.length === 0) {
         return res.status(401).json({
            success: false,
            message: 'E-mail ou palavra-passe incorretos.'
         })
      }

      const user = users[0]

      if (await compararSenhas(password, user.senha)) {

         const token = crypto.randomBytes(32).toString("hex")
         criarCookie(res, 'sessaoUsuario', token, 6 * 60 * 60 * 1000)
         const usuarioId = user.id
         const expiracao = new Date(
            Date.now() + 6 * 60 * 60 * 1000
         )

         const dataMysql = expiracao
            .toISOString()
            .slice(0, 19)
            .replace("T", " ")

         const sqlSessao = `INSERT INTO sessoes_usuario
          (usuario_id, token, expira_em) VALUES (?, ?, ?)`
         await db.promise().query(sqlSessao, [usuarioId, token, dataMysql])

         const [itensCarrinho] = await db.promise().query('SELECT * FROM carrinho WHERE navegador_id = ? ', [browserId])

         if (itensCarrinho.length > 0) {
            const sqlAutoSave = ` UPDATE carrinho SET usuario_id = ?
             WHERE navegador_id = ? AND usuario_id IS NULL`
            await db.promise().query(sqlAutoSave, [usuarioId, browserId])
         }

         return res.status(200).json({
            success: true,
            message: 'Sessão iniciada com sucesso.'
         })
      } else {
         return res.status(200).json({
            success: false,
            message: 'Palavara passe incorretas'
         })
      }

   } catch (error) {
      return res.status(500).json({
         success: false,
         message: 'Erro interno ao iniciar sessão.'
      })
   }
})

app.post('/getCartItems', upload.none(), async (req, res) => {

   try {
      const { browserId } = req.body
      const token = req.cookies.sessaoUsuario

      let condicao
      let valor

      function verificarToken(token) {
         if (token) return true
         if (!token) return false
      }

      const result = verificarToken(token)
         ? await usuarioSessao(token)
         : { success: false }


      if (!result.success && !browserId) {
         return res.status(400).json({
            success: false,
            message: 'Identificador do navegador inválido'
         })
      }

      function userActivo(e) {
         if (e === true) {
            return {
               condicao: 'usuario_id',
               valor: result.usuarioId
            }
         }

         if (e === false) {
            return {
               condicao: 'navegador_id',
               valor: browserId
            }
         }
      }

      const dados = userActivo(result.success)
      condicao = dados.condicao
      valor = dados.valor

      const sql = `
         SELECT
            c.*,
            p.nome AS nome,

            es.id AS especificacao_id,
            es.valor AS especificacao_valor,

            oes.id AS outra_especificacao_id,
            oes.valor AS outra_especificacao_valor

         FROM carrinho AS c

         INNER JOIN produtos AS p
            ON c.produto_id = p.id

         LEFT JOIN especificacoes_selecionadas AS es
            ON c.id = es.carrinho_id

         LEFT JOIN outras_especificacoes_selecionadas AS oes
            ON c.id = oes.carrinho_id

         WHERE c.${condicao} = ?
      `

      const [products] = await db.promise().query(sql, [valor])
      const productsCart = new Map()
      for (const product of products) {

         if (!productsCart.has(product.id)) {

            productsCart.set(product.id, {
               ...product,
               especificacoes_selecionadas: [],
               outras_especificacoes_selecionadas: []
            })
         }

         const item = productsCart.get(product.id)

         if (product.especificacao_id &&
            !item.especificacoes_selecionadas.some(
               e => e.id === product.especificacao_id
            )) {

            item.especificacoes_selecionadas.push({
               id: product.especificacao_id,
               valor: product.especificacao_valor
            })
         }

         if (product.outra_especificacao_id &&
            !item.outras_especificacoes_selecionadas.some(
               e => e.id === product.outra_especificacao_id
            )) {

            item.outras_especificacoes_selecionadas.push({
               id: product.outra_especificacao_id,
               valor: product.outra_especificacao_valor
            })
         }
      }

      return res.json({
         success: true,
         productsCart: [...productsCart.values()]
      })

   } catch (error) {
      return res.status(500).json({
         success: false,
         message: 'Erro ao carregar carrinho',
         error: error
      })
   }
})

app.post('/register', upload.none(), async (req, res) => {

   const {
      nome,
      sobrenome,
      email,
      telefone,
      senha, browserId
   } = req.body

   // Regex
   const regexNome = /^[A-Z][a-zÀ-ÿ]*$/
   const regexEmail = /^[^\s@]+@[^\s@]+\.[A-Za-z]{2,}$/
   const regexTelefone = /^9\d{8}$/
   const regexSenha = /^.{8,}$/

   // Campos obrigatórios
   if (
      !nome?.trim() ||
      !sobrenome?.trim() ||
      !email?.trim() ||
      !telefone?.trim() ||
      !senha?.trim() ||
      !browserId?.trim()
   ) {
      return res.status(400).json({
         success: false,
         message: 'Preencha todos os campos.'
      })
   }

   // Nome
   if (!regexNome.test(nome)) {
      return res.status(400).json({
         success: false,
         message: 'Nome inválido.'
      })
   }

   // Sobrenome
   if (!regexNome.test(sobrenome)) {
      return res.status(400).json({
         success: false,
         message: 'Sobrenome inválido.'
      })
   }

   // Email
   if (!regexEmail.test(email)) {
      return res.status(400).json({
         success: false,
         message: 'E-mail inválido.'
      })
   }

   // Telefone
   if (!regexTelefone.test(telefone)) {
      return res.status(400).json({
         success: false,
         message: 'Número de telefone inválido.'
      })
   }

   // Senha
   if (!regexSenha.test(senha)) {
      return res.status(400).json({
         success: false,
         message: 'A senha deve ter pelo menos 8 caracteres.'
      })
   }

   try {

      // Verificar se o email já existe
      const sqlExiste = `
         SELECT * FROM usuarios
         WHERE email = ?
      `

      const [existe] = await db.promise().query(sqlExiste, [email])

      if (existe.length > 0) {
         return res.status(400).json({
            success: false,
            message: 'Email já cadastrado.'
         })
      }

      const senhaHash = await bcrypt.hash(senha, 10)

      // Inserir usuário
      const sql = `
         INSERT INTO usuarios
         (nome, sobrenome, email, telefone, senha)
         VALUES (?, ?, ?, ?, ?)
      `

      const [result] = await db.promise().query(sql, [
         nome,
         sobrenome,
         email,
         telefone,
         senhaHash
      ])

      if (result.affectedRows === 1) {

         const usuarioId = result.insertId
         const token = crypto.randomBytes(32).toString("hex")

         const expiracao = new Date(
            Date.now() + 6 * 60 * 60 * 1000
         )

         const dataMysql = expiracao
            .toISOString()
            .slice(0, 19)
            .replace("T", " ")

         const sqlSessao = `INSERT INTO sessoes_usuario
          (usuario_id, token, expira_em) VALUES (?, ?, ?)`
         const [iniciarSessao] = await db.promise().query(sqlSessao, [usuarioId, token, dataMysql])

         const [itensCarrinho] = await db.promise().query('SELECT * FROM carrinho WHERE navegador_id = ? ', [browserId])

         if (itensCarrinho.length > 0) {
            const sqlAutoSave = ` UPDATE carrinho SET usuario_id = ?
             WHERE navegador_id = ? AND usuario_id IS NULL`
            await db.promise().query(sqlAutoSave, [usuarioId, browserId])
         }

         if (iniciarSessao.affectedRows === 1) {
            criarCookie(res, 'sessaoUsuario', token, 6 * 60 * 60 * 1000)
            return res.status(201).json({
               success: true,
               message: 'Conta criada com sucesso.',
            })
         }
      }

      return res.status(201).json({
         success: true,
         message: 'Conta criada com sucesso.',
      })

   } catch (error) {
      return res.status(500).json({
         success: false,
         message: 'Erro ao criar a conta.'
      })
   }
})

app.delete('/deleteUserSession', upload.none(), async (req, res) => {

   try {

      const token = req.cookies.sessaoUsuario

      if (!token) {
         return res.status(401).json({
            success: false,
            message: 'Sessão não encontrada'
         })
      }

      const usuario = await usuarioSessao(token)
      if (!usuario.success) {
         return res.status(401).json({
            success: false,
            message: 'Sessão inválida'
         })
      }

      const sqlDelete = `
         DELETE FROM sessoes_usuario
         WHERE usuario_id = ? AND token = ?
      `

      const [deleteSessao] = await db.promise().query(
         sqlDelete,
         [usuario.usuarioId, token]
      )

      if (deleteSessao.affectedRows === 0) {
         return res.status(404).json({
            success: false,
            message: 'Sessão não encontrada'
         })
      }


      eliminarCookie(res, 'sessaoUsuario')
      return res.status(200).json({
         success: true,
         message: 'Sessão terminada'
      })
   } catch (err) {
      return res.status(500).json({
         success: false,
         message: 'Erro ao processar dados'
      })
   }

})

app.delete('/deleteCartItem', upload.none(), async (req, res) => {

   try {
      const { carrinho_id, browserId } = req.body;
      const token = req.cookies.sessaoUsuario;


      const result = token
         ? await usuarioSessao(token)
         : { success: false };

      function userActivo(e) {
         if (e === true) {
            return {
               condicao: condicaoSQL('usuario'),
               parms: [carrinho_id, result.usuarioId]
            };
         }

         if (e === false) {
            return {
               condicao: condicaoSQL('navegador'),
               parms: [carrinho_id, browserId]
            };
         }
      }

      function condicaoSQL(tipo) {
         if (tipo === 'usuario') {
            return 'DELETE FROM carrinho WHERE id = ? AND usuario_id = ?';
         }

         if (tipo === 'navegador') {
            return 'DELETE FROM carrinho WHERE id = ? AND navegador_id = ?';
         }
      }

      const { condicao, parms } = userActivo(result.success);
      const [deleteIten] = await db.promise().query(condicao, parms);
      if (deleteIten.affectedRows === 0) {
         return res.status(404).json({
            message: 'Produto não encontrado',
            success: false
         });
      }

      return res.status(200).json({
         message: 'Produto eliminado do carrinho',
         success: true
      });

   } catch (err) {
      return res.status(500).json({
         message: 'Erro ao eliminar produto',
         success: false
      });
   }

});


app.get('/verificarSessao', upload.none(), async (req, res) => {

   const token = req.cookies.sessaoUsuario
   if (!token) {
      return res.status(401).json({
         success: false,
         message: 'Sessão não encontrada.'
      })
   }

   const resultado = await usuarioSessao(token)
   if (!resultado.success) {
      return res.status(401).json(resultado)
   }
   const usuarioId = resultado.usuarioId

   const sql = `
      SELECT *
      FROM usuarios
      WHERE id = ?
   `
   const [dadosUsuario] = await db.promise().query(sql, [usuarioId])
   return res.status(200).json({
      success: true,
      usuario: dadosUsuario
   })
})


app.post('/pedidos', upload.none(), async (req, res) => {

   const token = req.cookies.sessaoUsuario
   if (!verificarToken(token)) {
      return res.status(401).json({
         message: "Utilizador não autenticado",
         success: false
      });
   }

   const result = await usuarioSessao(token);
   if (!result.success) {
      return res.status(401).json({
         message: "Sessão inválida",
         success: false
      });
   }

   const { pagamento, envio, produtos, telefone } = req.body
   const listaProdutos = JSON.parse(produtos);

   let precoEnvio = (metodo) => {
      if (metodo == 'economico') {
         return 0
      }
      if (metodo === 'padrao') {
         return 1500
      }
      if (metodo === 'expresso') {
         return 3000
      }
   }

   let pagemenoSelecionado = (metodo) => {
      if (metodo === "express") {
         return "multicaixa_express";
      }

      if (metodo === "referencia") {
         return "multicaixa_reference";
      }
      return null;
   };

   const subtotal = listaProdutos.reduce(
      (total, produto) =>
         total +
         produto.preco * produto.quantidade,
      0
   );

   const total = subtotal + precoEnvio(envio)
   const idAleatorio = crypto.randomUUID()

   const inf = await criarPagamentoBitPay({
      pedidoId: idAleatorio,
      valorTotal: total,
      metodo: pagemenoSelecionado(pagamento),
      telefone: telefone
   })

   async function criarPagamentoBitPay({ pedidoId, valorTotal, metodo, telefone }) {
      const response = await fetch(
         "https://api-sandbox.bitpay.ao/v1/payment_intents",
         {
            method: "POST",
            headers: {
               "Authorization": `Bearer ${process.env.BITPAY_SECRET_KEY}`,
               "Content-Type": "application/json",
               "Idempotency-Key": `pedido-${pedidoId}`
            },
            body: JSON.stringify({
               amount: valorTotal,
               currency: "AOA",
               payment_method: metodo,
               ...(metodo === "multicaixa_express"
                  ? { customer: { mobile: telefone } }
                  : {}),
               merchant_reference: `PED-${pedidoId}`
            })
         }
      );

      const dados = await response.json();
      if (!response.ok) {
         throw new Error(
            dados.error?.message || "Erro ao criar pagamento BitPay"
         );
      }
      return dados;
   }

   return res.json({
      message: 'Welcome',
      success: true
   });

});

function verificarToken(token) {
   if (token) return true
   return false
}

module.exports = app;
