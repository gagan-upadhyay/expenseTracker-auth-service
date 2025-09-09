import { pgQuery } from '../../dbconnection.js';

export const findUserByEmail = async (email) => {
  const result = await pgQuery(`SELECT * FROM users WHERE EMAIL=$1`, [email]);
  return result.rows[0];
};

export const isUserExist = async(email)=>{
  const result = await pgQuery(`SELECT 1 FROM users WHERE EMAIL=$1 LIMIT 1`, [email]);
  if(!result){
    return {message:'User not found'}
  }
  return 'User exists'
}
isUserExist('gagan.aws.ac@gmail.com')

export const insertEmailOnlyUser = async (email) => {
  await pgQuery(`INSERT INTO users (email) VALUES ($1)`, [email]);
};

export const insertUser = async ({ firstName, lastName, email, hashedPassword, authType, profile_picture }) => {
  const result = await pgQuery(`
    INSERT INTO users(firstname, lastname, email, password, auth_type, profile_picture created_at)
    VALUES($1, $2, $3, $4, $5, $6 CURRENT_TIMESTAMP) RETURNING id`,
    [firstName, lastName, email, hashedPassword, authType, profile_picture]
  );
  return result.rows[0];
};



export const insertOAuthUser = async (payload) => {
  const result = await pgQuery(`
    INSERT INTO users (email, firstName, lastName, auth_type, profile_picture, created_at)
    VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP) RETURNING id`,
    [payload.email, payload.given_name, payload.family_name, "GOOGLE", payload.picture]
  );
  return result.rows[0];
};

export const addAccessTypeColumn = async () => {
  return await pgQuery(`ALTER TABLE users ADD accessType TEXT`);
};

