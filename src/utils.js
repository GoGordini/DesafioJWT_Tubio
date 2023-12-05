import { fileURLToPath } from 'url';
import { dirname,join } from 'path';
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';


export const PRIVATE_KEY = 'coder55575' //las constantes se generan con mayúsculas
const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);

export const productPath = join (__dirname,"./files/productos.json");
export const  cartPath = join (__dirname, "./files/carritos.json")

//1. hashear nuestra contraseña
export const createHash = password => //paso como parámetro password a hashear
        bcrypt.hashSync(password, bcrypt.genSaltSync(10)); //primer parámetro es lo que quiero hashear, segundo el número de rondas de hasheo (se recomienda 10)
    //1234
    //ASDASD435@#$#$

//2. validar nuestro password
export const isValidPassword = (plainPassword, hashedPassword) => //plainpassword es lo que valida el usuario, hashedpassword es lo que ya tenemos guardado hasheado.
    bcrypt.compareSync(plainPassword, hashedPassword);

//Implementación de la generación del JWT y la validación
//DFJGKSDNFJGKSDNFGK345656398U5GSDFNGKJSDNFG23485KDFGNJSDG
export const generateToken = (user) => {
    const token = jwt.sign({ user }, PRIVATE_KEY, { expiresIn: '1h' });
    //esta línea genera el token. Primer parámetro lo que quiero embeber, luego la clave para firmar y finalmente la expiración.
    return token;

}

//midleware. Borrado porque lo hace passport jwt:
export const authToken = (req, res, next) => {
    //1. validamos que el token llegue en los headers del request
    const authToken = req.headers.authorization; //el header que necesito se llama authorization

    if(!authToken) return res.status(401).send({ status: 'error', message: 'not authenticated' });

    //Bearer DFJGKSDNFJGKSDNFGK345656398U5GSDFNGKJSDNFG23485KDFGNJSDG
    // {
    //     user: {
    //         name: 'alex',
    //         email: 'ap@gmail.com'
    //     }
    // }
    const token = authToken.split(' ')[1];
    //2. Validar el jwt
    jwt.verify(token, PRIVATE_KEY, (error, credentials) => {
        //verify decodifica la info embebida. Token es lo que quiero verificar, con qué clave. Si todo fue bien, devuelve las credentials con la info embebida del usuario.
        if (error) return res.status(401).send({ status: 'error',  message: 'not authenticated'});
        req.user = credentials.user;
        next();
    })
}
