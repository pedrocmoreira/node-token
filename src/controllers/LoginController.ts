import { Request, Response } from "express";
import bcrypt from 'bcrypt';

import { BadRequestError } from "../helpers/api-errors";
import { userRepository } from "../repositories/userRepository";

export class LoginController {
  async create(req: Request, res: Response) {
    const {email, password} = req.body
  }
}