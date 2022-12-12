import { Request, Response } from "express";
import bcrypt from 'bcrypt';

import { BadRequestError } from "../helpers/api-errors";
import { userRepository } from "../repositories/userRepository";

export class UserController {
  async create(req: Request, res: Response) {
    const { name, email, password } = req.body

    //Verifica se já tem algum usuário cadastrado com o email
    const userExists = await userRepository.findOneBy({ email })

    if (userExists) {
      throw new BadRequestError('Email já existe')
    }

    const hashPassword = await bcrypt.hash(password, 10)
    
    const newUser = userRepository.create({
      name,
      email,
      password: hashPassword
    })

    await userRepository.save(newUser)

    const {password: _, ...user} = newUser

    return res.status(201).json(user)
  }
}