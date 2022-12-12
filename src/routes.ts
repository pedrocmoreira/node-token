import { Router } from "express";
import { LoginController } from "./controllers/LoginController";
import { UserController } from "./controllers/UserController";

const routes = Router()

routes.post('/user', new UserController().create);
routes.post('/login', new LoginController().create);

export default routes