import { Request, Response, NextFunction } from "express";
import { verify } from "jsonwebtoken";

interface IPayload {
  sub: string;
}

export function ensureAuthenticated(
  request: Request, 
  response: Response, 
  next: NextFunction
) {
  //receber o token
  const authToken = request.headers.authorization;

  //validar se token está preenchido
  if(!authToken) {
    return response.status(401).end();
  };

  const [, token] = authToken.split(" ");

  try {
    //validar se token é válido
    const { sub } = verify( 
      token,
      "02252ecbabbb62e7bc36131a000d5e17"
    ) as IPayload;
    
    //recuperar informações do usuário
    request.user_id = sub;
    
    return next();
  } catch (error) {
    return response.status(401).end();
  }



  return next();

}