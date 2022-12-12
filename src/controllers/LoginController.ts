import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { BadRequestError, UnauthorizedError } from "../helpers/api-errors";
import { userRepository } from "../repositories/userRepository";

export class LoginController {
  async create(req: Request, res: Response) {
    const { email, password } = req.body;

    const user = await userRepository.findOneBy({ email });

    if (!user) {
      throw new BadRequestError("E-mail ou senha inválidos");
    }

    const verifyPass = await bcrypt.compare(password, user.password);

    if (!verifyPass) {
      throw new BadRequestError("E-mail ou senha inválidos");
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_PASS ?? "", {
      expiresIn: "1h",
    });

    const { password: _, ...userLogin } = user;

    return res.json({
      user: userLogin,
      token: token,
    });
  }

  async getProfile(req: Request, res: Response) {
    return res.json(req.user);
  }
}
