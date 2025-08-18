import {Pool} from 'pg';

const pool = new Pool({
    connectionString:process.env.POSTGRES_URL
});

async function addColumn(){
    try{
        console.log("value of postgres_url", process.env.POSTGRES_URL);
        const result = await pool.query(`ALTER TABLE users ADD profile_picture TEXT`);
        console.log("column added :",result);
    }catch(err){
        console.error(err);
    }finally{
        await pool.end();
    }
}

addColumn();