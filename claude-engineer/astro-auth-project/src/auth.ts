import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// This should be a secure, randomly generated string stored in an environment variable
const JWT_SECRET = 'your-secret-key';

export function isAuthenticated(request: Request): boolean {
  const token = request.headers.get('Authorization')?.split(' ')[1];
  if (!token) return false;

  try {
    jwt.verify(token, JWT_SECRET);
    return true;
  } catch (error) {
    return false;
  }
}

export async function login(username: string, password: string): Promise<string | null> {
  // In a real application, you would look up the user in a database
  // and compare the hashed password. This is just a simple example.
  if (username === 'admin' && password === 'password') {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    return token;
  }
  return null;
}

export function hashPassword(password: string): string {
  return bcrypt.hashSync(password, 10);
}

export function verifyPassword(password: string, hash: string): boolean {
  return bcrypt.compareSync(password, hash);
}