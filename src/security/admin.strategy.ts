import {AuthenticationStrategy} from '@loopback/authentication';
import {service} from '@loopback/core';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {AutenticacionService} from '../services';

export class AdminStrategy implements AuthenticationStrategy {
  name: string ='admin';
  constructor(@service(AutenticacionService) public serviceAutenticaction: AutenticacionService) {}
  async authenticate(request: Request):Promise<UserProfile|undefined>{
    let token = parseBearerToken(request);
    if(token){
      let data_admin = this.serviceAutenticaction.ValidateToken(token);
      if (data_admin) {
        let admin_info:UserProfile = Object.assign({
          name: data_admin.data.name,
          email: data_admin.data.email
        });
        return admin_info;
      }else{
        throw new HttpErrors[405]("Token inválido");
      }
    }else{
      throw new HttpErrors[405]("No se encontró el token consultado");
    }
  }
}
