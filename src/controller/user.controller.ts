import { Request, Response } from "express";
import { User } from "../entity/user.entity";
import * as argon2 from "argon2";
import myDataSource from "../config/data-source";

export const Create = async (req: Request, res: Response) => {
  try {
    const body = req.body;

    const user = await myDataSource.getRepository(User).save({
      first_name: body.first_name,
      last_name: body.last_name,
      email: body.email,
      password: await argon2.hash(body.password),
    });

    const { password, ...data } = user;

    res.status(201).send(data);
  } catch (error) {
    if (process.env.NODE_ENV === "development") {
        console.log(error.message);
    }
    return res.status(500).send({
      message: "Invalid Request",
    });
  }
};

export const Read = async (req: Request, res: Response) => {
  try {
    const id = req.params.id;
    const user = await myDataSource.getRepository(User).findOne({ where: { id } });
    const { password, ...data } = user;
    res.send(data);
  } catch (error) {
    if (process.env.NODE_ENV === "development") {
        console.log(error.message);
    }
    return res.status(500).send({
      message: "Invalid Request",
    });
  }
};

export const Update = async (req: Request, res: Response) => {
    try {
        await myDataSource.getRepository(User).update(req.params.id, req.body);
        const user = await myDataSource.getRepository(User).findOne({ where: { id: req.params.id } });
        const { password, ...data } = user;
        res.send(data);
        res.status(202).send()
    } catch (error) {
    if (process.env.NODE_ENV === "development") {
        console.log(error.message);
    }
      return res.status(500).send({
        message: "Invalid Request",
      });
    }
};

export const Delete = async (req: Request, res: Response) => {
    try {
        await myDataSource.getRepository(User).delete(req.params.id);

        res.status(204).send(null);
    } catch (error) {
        if (process.env.NODE_ENV === "development") {
            console.log(error.message);
        }
      return res.status(500).send({
        message: "Invalid Request",
      });
    }
};
