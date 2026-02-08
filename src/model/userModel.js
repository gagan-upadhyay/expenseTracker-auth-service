import { pgQuery } from '../../config/dbconnection.js';

export const findUserByEmail = async (email) => {
  // console.log('Inside findUserByEmail in userModel');
  const result = await pgQuery(`SELECT id, auth_type, password FROM users WHERE EMAIL=$1`, [email]);
  // console.log('from userModel, value of result:', result.rows);
  if(result.rows.length!==0){
    return result.rows[0];
  }else{
    // console.log('Inside else statement form model');
    return false;
  }
};

// export const isUserExist = async(email)=>{
//   const result = await pgQuery(`SELECT 1 FROM users WHERE EMAIL=$1 LIMIT 1`, [email]);
//   console.log('Value of result:\n', result.rows[0]);
//   if(!result.rows[0]){
//     return {message:'User not found'}
//   }
//   return 'User exists'
// }
export const insertEmailOnlyUser = async (email) => {
  await pgQuery(`INSERT INTO users (email) VALUES ($1)`, [email]);
};

export const insertUser = async ({ firstName, lastName, email, hashedPassword, authType, profile_picture }) => {
  // console.log("Value of allimports from Model:\n", firstName, lastName, email, hashedPassword, authType, profile_picture);
  if(profile_picture){
    const result = await pgQuery(`
      INSERT INTO users(firstname, lastname, email, password, auth_type, profile_picture created_at)
      VALUES($1, $2, $3, $4, $5, $6 CURRENT_TIMESTAMP) RETURNING id`,
      [firstName, lastName, email, hashedPassword, authType, profile_picture]
    );
    console.log("Value of result form model:\n", result);
    return result.rows[0];
  }else{
    const result = await pgQuery(`
      INSERT INTO users(firstname, lastname, email, password, auth_type, created_at)
      VALUES($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) RETURNING id`,
      [firstName, lastName, email, hashedPassword, authType]
    );
    console.log("Value of result form model:\n", result);
    return result.rows[0];
  }
  
};

export const insertOAuthUser = async (payload) => {
  const result = await pgQuery(`
    INSERT INTO users (email, firstName, lastName, auth_type, profile_picture, created_at)
    VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP) RETURNING id`,
    [payload.email, payload.given_name, payload.family_name, "GOOGLE", payload.picture]
  );
  return result.rows[0];
};

// export const addAccessTypeColumn = async () => {
//   return await pgQuery(`ALTER TABLE users ADD accessType TEXT`);
// };


//update query
export const updateField = async(fieldName, value, identifier)=>{
  const result = await pgQuery 
  (`
    UPDATE users
    SET $1 = $2
    WHERE email = $3
    RETURNING *
    `, [fieldName, value, identifier]
  );

  if(result.rows.length!==0) return false;
  return result.rows[0];
    
}

// getUserCreds('urmi.bhups@asn.com');