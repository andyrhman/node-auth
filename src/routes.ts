import { Router } from "express";
import { AuthenticatedUser, Login, Logout, Refresh, Register } from "./controller/auth.contoller";
import { ForgotPassword, ResetPassword } from "./controller/forgot.controller";
import { Create, Delete, Read, Update } from "./controller/user.controller";

const routes = (router: Router) => {
    router.post('/api/register', Register);
    router.post('/api/login', Login);
    // router.get('/api/user', AuthenticatedUser);
    router.post('/api/refresh', Refresh);
    router.post('/api/logout', Logout);
    router.post('/api/forgot', ForgotPassword);
    router.post('/api/reset', ResetPassword);

    router.post('/api/user', Create);
    router.get('/api/user/:id', Read);
    router.put('/api/user/:id', Update);
    router.delete('/api/user/:id', Delete)
}

export default routes;