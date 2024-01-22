import { Router } from "express";
import { Register } from "./controller/auth.contoller";

const routes = (router: Router) => {
    router.get('/api/login', Register)
}

export default routes;