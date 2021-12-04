import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {Keys} from '../config/keys';
import {Persona} from '../models';
import {PersonaRepository} from '../repositories';

const generador = require("password-generator");
const cryptoJS = require("crypto-js");
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
  constructor(@repository(PersonaRepository)
  public persona_repository: PersonaRepository,) { }

  /*
   * Add service methods here
   */
  GeneratePasswordFunction() {
    let password = generador(6, false);
    return password;
  }
  EncryptPasswordFunction(password: string) {
    let password_encrypt = cryptoJS.MD5(password).toString();
    return password_encrypt;
  }

  ShowInfoPerson(user_email: string, password: string) {
    try {
      let persona = this.persona_repository.findOne({
        where: {correo: user_email, clave: password},
      });
      if (persona) {
        return persona;
      }
      return false;
    } catch {
      return false;
    }
  }

  GenerateTokenJWT(persona:Persona){
    let token = jwt.sign({
      data: {
        id:persona.id,
        nombres: persona.nombres,
        correo: persona.correo,
      }
    },
    Keys.JWTkey);
    return token;
  }

  ValidateToken(token:string){
    try{
      let datos = jwt.verify(token, Keys.JWTkey);
      return datos;
    }catch{
      return false;
    }
  }

}
