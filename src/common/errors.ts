import { HttpStatus } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';

export function getErrorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === 'string') return e;
  try {
    return JSON.stringify(e);
  } catch {
    return 'Unexpected error';
  }
}

export function throwRpc(
  e: unknown,
  status: number = HttpStatus.BAD_REQUEST,
): never {
  throw new RpcException({ status, message: getErrorMessage(e) });
}
