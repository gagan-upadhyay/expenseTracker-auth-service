
import app from '../index.js'
import request from 'supertest'

describe('POST /login', ()=>{
    it('Should return 200 and a token for valid credentials', async ()=>{
        const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
            email:'asn@asn.com',
            password:'12345678'
        });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('token');
           
    });

    it('Should return 401 for invalid credentials', async()=>{
        const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
            email:'urmi.bhups@asn.com',
            password:'12344'
        });
        expect(res.statusCode).toBe(401);
        expect(res.body).toHaveProperty('error');
    })
})
