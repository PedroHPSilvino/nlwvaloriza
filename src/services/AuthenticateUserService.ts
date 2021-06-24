import { getCustomRepository } from "typeorm"
import { UsersRepositories } from "../repositories/UsersRepositories"

import { compare } from "bcryptjs"
import { sign } from "jsonwebtoken"

interface IAuthenticateRequest {
    email: string;
    password: string;
}

class AuthenticateUserService {
    async execute({email, password}: IAuthenticateRequest) {
        const usersRepositories = getCustomRepository(UsersRepositories)

        const user = await usersRepositories.findOne({email})

        if (!user) {
            throw new Error("Email or password incorrect")
        }

        const passwordMatch = await compare(password, user.password)

        if (!passwordMatch) {
            throw new Error("Email or password incorrect")
        }

        const token = sign({
            email: user.email,
        }, '5c1dfbfc94cf47d522e0b36e3f96de6a', {
            subject: user.id,
            expiresIn: "1d"
        })

        return token;
    }

}

export { AuthenticateUserService }