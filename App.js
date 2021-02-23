// Carregando as variáveis de ambiente caso seja ambinete de producao
if(process.env.NODE_ENV !== 'production'){
  require('dotenv').config();
}
console.log('Ambiente identificado: ' + process.env.NODE_ENV);

// Imports
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const app = express();
const models = require('./models');
const urlencodeParser = bodyParser.urlencoded({extended: false});
app.use(urlencodeParser);
app.use(bodyParser.json());
app.use(cors());

const jwt = require('jsonwebtoken');
const validarToken = require('./middleware/validarToken');

// Models sequelize
const user = models.User;
const profile = models.Profile;


// --------------------------- Rotas CRUD para o cadastro de usuários ---------------------------

/*
app.get('/', function(req,res,next){
  console.log('Testando Conexão!');
  res.json({message: 'BackEnd: Tudo certo!'});
});
*/

app.post('/login', async (req , res)=>{
    console.log('/login');
    console.log(req.body);

    try {

      if(req.body.nickName && req.body.password){
        const response = await user.findOne({
          where: {
            nickName: req.body.nickName
          }
        });
        //console.log(response)
        if(response == null){
          res.status(404).send({ok: false, msg: 'Usuário não cadastrado!'});
        }else if(response.dataValues.status === 'Inativo'){
          res.status(401).send({ok: false, msg: 'Usuário Inativado!'});
        }else{
  
          bcrypt.compare(req.body.password, response.dataValues.password, (errBcrypt, results) => {
            if(errBcrypt){
              return res.status(500).send({ok: false, msg: 'Erro no bcrypt:' + errBcrypt});
            }
            console.log(results)
            if(results){
              const result = {
                id: response.dataValues.id,
                name: response.dataValues.name,
                changePassword: response.dataValues.changePassword,
                profileId: response.dataValues.profileId
              }

              const token = jwt.sign({id: response.dataValues.id}, process.env.JWT_KEY, {
                expiresIn: process.env.JWT_EXPIRES_IN
              });
              return res.status(200).send({ok: true, msg: 'Usuário autorizado com sucesso!', token: token, result: result});
            }else{
              return res.status(401).send({ok: false, msg: 'Senha Inválida!'});
            }
  
          });
        }
      }else{
        res.status(406).send({ok: false, 
                  msg: 'Não foi recebido todas as informações para Login!'
        })
      }
      
    } catch (err) {
      console.log('Não foi possível acessar o banco de dados! Erro: '+ err);
      //res.send('Não foi possível acessar o banco de dados! Erro: '+ error);
      res.status(500).send({ok: false, 
                msg: 'Não foi possível acessar o banco de dados! Erro: '+ err
      })
    }
    
});

app.post('/loginChangePass', validarToken, async (req , res)=>{
  console.log('/loginChangePass');
  console.log(req.body);

  try {

    if(req.body.id && req.body.currentPassword){
      const response = await user.findOne({
        where:{
          id: req.body.id
        }
      })

      if(response == null){
        res.status(404).send({ok: false, msg: 'Usuário não cadastrado!'});
      }else if(response.dataValues.status === 'Inativo'){
        res.status(401).send({ok: false, msg: 'Usuário Inativado!'});
      }else if(response.dataValues.changePassword == 1){

        bcrypt.compare(req.body.currentPassword, response.dataValues.password, (errBcrypt, results) => {
          if(errBcrypt){
            return res.status(500).send({ok: false, msg: 'Erro no bcrypt:' + errBcrypt});
          }
          console.log(results)
          if(results){

            bcrypt.hash(req.body.newPassword, saltRounds, (errBcrypt, hash) => {
              if(errBcrypt){
                return res.status(500).send({ok: false, msg: errBcrypt})
              }

              response.password = hash;
              response.changePassword = 0;
              response.save();
              const result = {
                id: response.dataValues.id,
                name: response.dataValues.name,
                profileId: response.dataValues.profileId
              };
              res.status(200).send({ok: true, msg: 'Senha alterada com sucesso!', result: result});
              console.log('Senha alterada com sucesso!');

            });
          }else{
            return res.status(401).send({ok: false, msg: 'Senha Inválida!'});
          }

        });
      }else{
        res.status(403).send({ok: false, msg: 'Usuário não solicitou troca de senha!'});
      }
    }else{
      res.status(406).send({ok: false, 
        msg: 'Não foi recebido todas as informações para troca de senha!'
      });
    }
    
  } catch (err) {
    console.log('Não foi possível acessar o banco de dados! Erro: '+ err);
    //res.send('Não foi possível acessar o banco de dados! Erro: '+ error);
    res.status(500).send({ok: false, 
              msg: 'Não foi possível acessar o banco de dados! Erro: '+ err
    })
  }
});

app.get('/readProfiles', validarToken, async (req, res)=>{
  console.log('/readProfiles');
  try {
    const response = await profile.findAll({
      attributes: ['id', 'name', 'description'],
      raw: true
    });
    console.log(response);
    res.status(200).send({ok: true, msg: 'Autorizado!', result: response});
  } catch (err) {
    console.log('Não foi possível acessar o banco de dados! Erro: '+ err);
    res.status(500).send({ok: false, 
                          msg: 'Não foi possível acessar o banco de dados! Erro: '+ err
    })
  }
  
});

app.get('/readUsers', validarToken, async (req, res)=>{
  console.log('/readUsers');
  try {
    const response = await user.findAll({
      attributes: ['id', 'name', 'nickName', 'cpf', 'fone', 'email', 'status', 'changePassword', 'obs', 'profileId'],
      raw: true,
      include: [{
        model: profile,
        required: true,
        attributes: ['name', 'description']
      }],
      order: [['name', 'ASC']]
    });
    console.log(response);
    res.status(200).send({ok: true, msg: 'Autenticado!', result: response});

  } catch (err) {
    console.log('Não foi possível acessar o banco de dados! Erro: '+ err);
    res.status(500).send({ok: false, 
                          msg: 'Não foi possível acessar o banco de dados! Erro: '+ err
    })
  }
});

app.post('/createUser', validarToken, (req, res)=>{
  console.log('/createUser');
  try {
    if(req.body.nickName && req.body.name && req.body.cpf && req.body.fone && req.body.email && req.body.status && (req.body.changePassword == 0 || req.body.changePassword == 1) && req.body.profileId && req.body.password){
      bcrypt.hash(req.body.password, saltRounds, async (errBcrypt, hash) => {
        if(errBcrypt){
          return res.status(500).send({ok: false, msg: 'Erro no bcrypt:' + errBcrypt})
        }

        const response = await user.create({
          name: req.body.name,
          nickName: req.body.nickName,
          cpf: req.body.cpf,
          fone: req.body.fone,
          email: req.body.email,
          password: hash,
          changePassword: req.body.changePassword,
          status: req.body.status,
          profileId: req.body.profileId,
          obs: req.body.obs,
          existLink: 0,
          createdAt: new Date().toLocaleString()
        });

        console.log(response);
        console.log('Usuário criado com sucesso!');
        res.status(201).send({ok: true, 
                  msg:'Usuário criado com sucesso!'
        });
      });
    }
  } catch (err) {
    console.log('Não foi possível acessar o banco de dados! Erro: '+ err);
      res.status(500).send({ok: false, 
                msg: 'Não foi possível acessar o banco de dados! Erro: '+ err
      });
  }
  
});

app.post('/editUser', validarToken, async (req, res)=>{
  console.log('/editUser');
  try {
    if(req.body.id && req.body.nickName && req.body.name && req.body.cpf && req.body.fone && req.body.email && req.body.obs && req.body.status && (req.body.changePassword == 0 || req.body.changePassword == 1) && req.body.profileId){
      if(req.body.changePassword == 1){

        if(req.body.password.length > 2){
  
          const response = await user.findOne({
            where:{
              id: req.body.id
            }
          })
          if(response == null){
            console.log('Usuário não cadastrado!');
            res.status(404).send({ok: false, msg: 'Usuário não cadastrado!'});
          }else{
            if(req.body.name == response.dataValues.name){
              bcrypt.hash(req.body.password, saltRounds, async (errBcrypt, hash) => {
                if(errBcrypt){
                  return res.status(500).send({ok: false, msg: 'Erro no bcrypt:' + errBcrypt})
                }
    
                response.name = req.body.name,
                response.nickName = req.body.nickName,
                response.cpf = req.body.cpf,
                response.fone = req.body.fone,
                response.email = req.body.email,
                response.password = hash,
                response.changePassword = req.body.changePassword,
                response.status = req.body.status,
                response.profileId = req.body.profileId,
                response.obs = req.body.obs,
                response.updateAt = new Date().toLocaleString()
                response.save();
    
                res.status(200).send({ok: true, msg: 'Usuário editado com sucesso!'});
                console.log('Usuário editado com sucesso!');
              });
            }else{
              res.status(401).send({ok: false, 
                                    msg:'Usuário divergente no banco!'
              });
            }
          }
        }else{
          res.status(406).send({ok: false, 
                    msg:'Senha inicial inválida ou inexistente, mínimo de 3 caracteres!'
          });
        }
      }else if(req.body.changePassword == 0){
        let response = await user.findByPk(req.body.id);

        if(response == null){
          console.log('Usuário não cadastrado!');
          res.status(404).send({ok: false, msg: 'Usuário não cadastrado!'});
        }else{
          if(req.body.name == response.dataValues.name){
            response.name = req.body.name,
            response.nickName = req.body.nickName,
            response.cpf = req.body.cpf,
            response.fone = req.body.fone,
            response.email = req.body.email,
            response.status = req.body.status,
            response.profileId = req.body.profileId,
            response.obs = req.body.obs,
            response.updateAt = new Date().toLocaleString()
            response.save();
            
            console.log('Usuário editado com sucesso!');
            res.status(200).send({ok: true, 
                      msg:'Usuário editado com sucesso!'
            });
          }else{
            res.status(401).send({ok: false, 
              msg:'Usuário divergente no banco!'
            });
          }
        }
      }else{
        res.status(406).send({ok: false, 
                              msg:'Não foi identificado se é necessário trocar a senha!'
        });
      }
    }else{
      res.status(406).send({ok: false, 
                msg: 'Não foi recebido todas as informações para a edição de um usuário!'
      })
    }
    
  } catch (err) {
    console.log('Não foi possível acessar o banco de dados! Erro: '+ err);
    //res.send('Não foi possível acessar o banco de dados! Erro: '+ error);
    res.status(500).send({ok: false, 
              msg: 'Não foi possível acessar o banco de dados! Erro: '+ err
    })
  }

});

app.post('/deleteUser', validarToken, async (req, res)=>{
  console.log('/deleteUser');
  try {
    if(req.body.id){
      const response = await user.findOne({
        where: {
          id: req.body.id
        }
      });
  
      if(response == null){
        res.status(404).send({ok: false,
                              msg: 'Não foi possível encontrar o usuário!'
        });
      }else{
        if(response.dataValues.existLink == 0){
          await user.destroy({
            where: {
              id: response.id
            }
          });
          console.log('Usuário: ' + response.name + ' excluído com sucesso!');
          res.status(200).send({ok: true,
                                msg: 'Usuário: ' + response.name + ' excluído com sucesso!'
          });
        }else{
          res.send({
            ok: false,
            msg: 'Usuário ' + response.dataValues.name + ' possue vínculos com lançamentos de containers, não é possível deletá-lo! Sugestão: Inative ele!'
          });
        }
      }
    }else{
      return res.status(406).send({ok: false, msg: 'Não foi recebido todas as informações para a exclusão do usuário!'})
    }
    
  } catch (err) {
    console.log('Não foi possível acessar o banco de dados! Erro: '+ err);
    //res.send('Não foi possível acessar o banco de dados! Erro: '+ error);
    res.send({ok: false, 
              msg: 'Não foi possível acessar o banco de dados! Erro: '+ err
    })
  }
  

});

//---------------------------          Start Server          --------------------------- 
const server = http.createServer(app);
server.listen(3000);
console.log('Servidor rodando na porta 3000....');