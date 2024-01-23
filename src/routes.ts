import { Router } from "express";
import { AuthenticatedUser, Login, Logout, Refresh, Register } from "./controller/auth.contoller";
import { Forgot } from "./controller/forgot.controller";

const routes = (router: Router) => {
    router.post('/api/register', Register);
    router.post('/api/login', Login);
    router.get('/api/user', AuthenticatedUser);
    router.post('/api/refresh', Refresh);
    router.post('/api/logout', Logout);
    router.post('/api/forgot', Forgot);
}

export default routes;