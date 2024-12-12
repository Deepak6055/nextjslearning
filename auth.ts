import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import Email from 'next-auth/providers/email';
 
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT id, email, password, name FROM users WHERE email = ${email};`;
    return user.rows[0];
  } catch (error) {
    console.error("Database error:", error);
    throw new Error("Database query failed.");
  }
}

 
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);
        
        if (!parsedCredentials.success) {
          console.log("Invalid input:", credentials);
          return null; // Ensure early return on invalid input
        }
        
        const { email, password } = parsedCredentials.data;
        console.log("Parsed credentials:", email, password);
      
        try {
          const user = await getUser(email);
          if (!user) {
            console.log("User not found for email:", email);
            return null;
          }
      
          console.log("User found:", user);
      
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (!passwordsMatch) {
            console.log("Passwords do not match for user:", email);
            return null;
          }
      
          console.log("Authentication successful for user:", email);
          return { id: user.id, email: user.email, name: user.name }; // Adjust returned object to match your User type
        } catch (error) {
          console.error("Error in authorization:", error);
          throw new Error("Authentication failed");
        }
      }
      
    }),
  ],
});