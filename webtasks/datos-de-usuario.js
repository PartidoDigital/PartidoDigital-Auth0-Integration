const express = require('express');
const jwt = require('express-jwt');
const wt = require('webtask-tools');
const bodyParser = require('body-parser');
const app = express();
const ManagementClient = require('auth0').ManagementClient;
const jsonwebtoken = require('jsonwebtoken');

module.exports = wt.fromExpress((req, res) => {
  // se configura el cliente usando un cliente no interactivo
  // llamadas disponibles: http://auth0.github.io/node-auth0/module-management.ManagementClient.html
  const managementClient = new ManagementClient({
    domain: req.webtaskContext.secrets.AUTH0_DOMAIN,
    clientId: req.webtaskContext.secrets.NON_INTERACTIVE_CLIENT_ID,
    clientSecret: req.webtaskContext.secrets.NON_INTERACTIVE_CLIENT_SECRET
  });
  
  // requerido para poder parsear todo tipo de contenido que llega en los requests
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({
    extended: true
  })); 

  app.get("/test", (req, res) => {
    res.status(200).send("OK!");
  });
  
  // todas las rutas requieren la verificación del json web token
  app.use(jwt({
      getToken: function(data) {
        // grab the access token from the query string sent by Auth0 rule instead of default authorization bearer header
        return data.query.token;
      },
      secret: req.webtaskContext.secrets.CLIENT_SECRET,
      audience: req.webtaskContext.secrets.CLIENT_ID,
      issuer: `https://${req.webtaskContext.secrets.AUTH0_DOMAIN}/`
  }).unless({path: '/handle-user-metadata/test'}));
  
  // se procede a chequear que no existe ese usuario en el sistema
  // si llega a existir el primer nombre de usuario, se procede a agregar un número (empezando por 1) y se vuelve a chequear
  // si llega a existir un nombre de usuario con un número, se aumenta el número y se vuelve a chequear
  var checkNickname = function(nickname, i) {
    i = (i !== undefined) ? i+1 : 1;
    var deferred = Promise.defer();
    managementClient.getUsers({ 
      q: `user_metadata.nickname.raw:"${nickname}"` 
    }).then(users => {
      if(users.length) {
        checkNickname(nickname + "" + i, i).then(newNickName => deferred.resolve(newNickname));
      } else {
        deferred.resolve(nickname);
      }
    });
    return deferred.promise;
  };
  
  // el nickname es primeras letras de nombres y el apellido entero
  // ejemplo 1: Juan Perez => jperez
  // ejemplo 2: Juan Ignacio Perez => jiperez
  var getFirstNickname = function(fullName) {
      fullName = fullName.toLowerCase();
      var splitFullname = fullName.split(" ");
      var out = "";
      for(var i = 0; i < splitFullname.length - 1; i++) {
        out += splitFullname[i][0];
      }
      return out + splitFullname[splitFullname.length - 1];
  };
  
  // este endpoint es para poder agregar un campo full_name que representa el nombre completo de la persona
  // se espera información en el cuerpo del request ya que se espera que se utilice un formulario con método POST
  app.post('/add-full-name', (req, res) => {
    checkNickname(getFirstNickname(req.body.full_name)).then(newNickname => {
      managementClient.users.updateUserMetadata(
      { id: req.user.sub }, 
      { full_name: req.body.full_name, nickname: newNickname },
      (err, user) => {
        if (err) return res.status(500).send(JSON.stringify(err));
        
        // se procede a crear un nuevo json web token para que la regla desde Auth0 verifique
        // se agrega un campo fullNameAdded esperado por la regla para validar que se concluyó con éxito
        // la regla que procesa esto es: https://github.com/PartidoDigital/PartidoDigital-Auth0-Integration/blob/master/rules/completar-nombre-completo.js
        jsonwebtoken.sign({
          fullNameAdded: true,
          sub: req.user.sub
        }, req.webtaskContext.secrets.CLIENT_SECRET, {
          expiresInMinutes: 5,
          audience: req.webtaskContext.secrets.CLIENT_ID,
          issuer: `https://${req.webtaskContext.secrets.AUTH0_DOMAIN}/`
        }, 
        (token) => {
          res.redirect(`https://${req.webtaskContext.secrets.AUTH0_DOMAIN}/continue?token=${token}&state=${req.body.state}`);  
        });
      });
    });
  });
  
  return app(req, res);
});