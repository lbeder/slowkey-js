import { createHash, scryptSync } from 'crypto';
import { hash as argon2, argon2id } from 'argon2';
import CliProgress from 'cli-progress';
import { keccak512 } from 'js-sha3';
import { chunk } from 'lodash';
import yargs from 'yargs';
import { Logger } from './utils/logger';

const VERSION = process.env.npm_package_version!;

const MIN_ITERATIONS = 1;
const MAX_ITERATIONS = 4294967295;
const DEFAULT_ITERATIONS = 100;
const MIN_KEY_LENGTH = 10;
const MAX_KEY_LENGTH = 128;
const DEFAULT_KEY_LENGTH = 16;
const SALT_LENGTH = 16;

const MAX_SCRYPT_N = 4294967295;
const DEFAULT_SCRYPT_N = 1 << 20;
const MAX_SCRYPT_R = 4294967295;
const DEFAULT_SCRYPT_R = 8;
const MAX_SCRYPT_P = 4294967295;
const DEFAULT_SCRYPT_P = 1;

const ARGON2_VERSION = 19;
const MIN_ARGON2_M_COST = 8;
const MAX_ARGON2_M_COST = 4294967295;
const DEFAULT_ARGON2_M_COST = 1 << 21;
const MIN_ARGON2_T_COST = 2;
const MAX_ARGON2_T_COST = 4294967295;
const DEFAULT_ARGON2_T_COST = 2;

const doubleHash = (salt: Buffer, password: Buffer, prevRes: Buffer) => {
  let res = prevRes;

  res = createHash('sha512')
    .update(Buffer.concat([res, salt, password]))
    .digest();

  res = Buffer.from(keccak512(Buffer.concat([res, salt, password])), 'hex');

  return res;
};

const verifyParams = (
  iterations: number,
  length: number,
  scryptN: number,
  scryptR: number,
  scryptP: number,
  argon2MCost: number,
  argon2TCost: number
) => {
  if (iterations < MIN_ITERATIONS) {
    throw new Error(`Invalid iterations number. Value ${iterations} is lesser than the minimum ${MIN_ITERATIONS}`);
  }

  if (iterations > MAX_ITERATIONS) {
    throw new Error(`Invalid iterations number. Value ${iterations} is greater than the maximum ${MAX_ITERATIONS}`);
  }

  if (length < MIN_KEY_LENGTH) {
    throw new Error(`Invalid length. Length ${length} is lesser than the minimum length ${MIN_KEY_LENGTH}`);
  }

  if (length > MAX_KEY_LENGTH) {
    throw new Error(`Invalid length. Length ${length} is greater than the maximum length ${MAX_KEY_LENGTH}`);
  }

  if (scryptN > MAX_SCRYPT_N) {
    throw new Error(`Invalid scrypt N. Value ${scryptN} is greater than the maximum ${MAX_SCRYPT_N}`);
  }

  if (scryptR > MAX_SCRYPT_R) {
    throw new Error(`Invalid scrypt r. Value ${scryptR} is greater than the maximum ${MAX_SCRYPT_R}`);
  }

  if (scryptP > MAX_SCRYPT_P) {
    throw new Error(`Invalid scrypt p. Value ${scryptP} is greater than the maximum ${MAX_SCRYPT_P}`);
  }

  if (argon2MCost < MIN_ARGON2_M_COST) {
    throw new Error(`Invalid argon m_cost. Value ${argon2MCost} is lesser than the minimum ${MIN_ARGON2_M_COST}`);
  }

  if (argon2MCost > MAX_ARGON2_M_COST) {
    throw new Error(`Invalid argon m_cost. Value ${argon2MCost} is greater than the maximum ${MAX_ARGON2_M_COST}`);
  }

  if (argon2TCost < MIN_ARGON2_T_COST) {
    throw new Error(`Invalid argon t_cost. Value ${argon2TCost} is lesser than the minimum ${MIN_ARGON2_T_COST}`);
  }

  if (argon2TCost > MAX_ARGON2_T_COST) {
    throw new Error(`Invalid argon t_cost. Value ${argon2TCost} is greater than the maximum ${MAX_ARGON2_T_COST}`);
  }
};

const main = async () => {
  try {
    await yargs(process.argv.slice(2))
      .parserConfiguration({ 'parse-numbers': false })
      .scriptName('slowkey-js')
      .wrap(120)
      .demandCommand()
      .help()
      .version(VERSION)
      .command(
        'derive',
        'Derive a key using using Scrypt, Argon2, SHA2, and SHA3',
        {
          iterations: {
            description: 'Number of iterations',
            type: 'number',
            alias: 'i',
            default: DEFAULT_ITERATIONS
          },
          length: {
            description: 'Length of the derived result',
            type: 'number',
            alias: 'l',
            default: DEFAULT_KEY_LENGTH
          },
          'scrypt-n': {
            description: 'Scrypt CPU/memory cost parameter',
            type: 'number',
            default: DEFAULT_SCRYPT_N
          },
          'scrypt-r': {
            description: 'Scrypt block size parameter, which fine-tunes sequential memory read size and performance',
            type: 'number',
            default: DEFAULT_SCRYPT_R
          },
          'scrypt-p': {
            description: 'Scrypt parallelization parameter',
            type: 'number',
            default: DEFAULT_SCRYPT_P
          },
          'argon2-m-cost': {
            description: 'Argon2 number of 1 KiB memory block',
            type: 'number',
            default: DEFAULT_ARGON2_M_COST
          },
          'argon2-t-cost': {
            description: 'Argon2 number of iterations',
            type: 'number',
            default: DEFAULT_ARGON2_T_COST
          },
          salt: {
            description: 'Random data fed as an additional input to the KDF',
            type: 'string',
            required: true
          },
          password: {
            description: 'Input password to the KDF',
            type: 'string',
            required: true
          }
        },
        async ({ iterations, length, scryptN, scryptR, scryptP, argon2MCost, argon2TCost, salt, password }) => {
          let saltBuf = salt.startsWith('0x') ? Buffer.from(salt.slice(2), 'hex') : Buffer.from(salt);
          if (saltBuf.length < SALT_LENGTH) {
            const paddedBuf = Buffer.alloc(SALT_LENGTH, 0);
            saltBuf.copy(paddedBuf, 0);
            saltBuf = paddedBuf;
          } else if (saltBuf.length > SALT_LENGTH) {
            saltBuf = createHash('sha512').update(saltBuf).digest().subarray(0, SALT_LENGTH);
          }

          const passwordBuf = password.startsWith('0x') ? Buffer.from(password.slice(2), 'hex') : Buffer.from(password);

          verifyParams(iterations, length, scryptN, scryptR, scryptP, argon2MCost, argon2TCost);

          Logger.notice(
            `SlowKey: iterations: ${iterations}, length: ${length}, Scrypt: (n: ${scryptN}, r: ${scryptR}, p: ${scryptP}), Argon2id: (version: ${ARGON2_VERSION}, m_cost: ${argon2MCost}, t_cost: ${argon2TCost})`
          );
          Logger.info();

          const bar = new CliProgress.SingleBar(CliProgress.Presets.shades_classic);
          bar.start(iterations, 0);

          let res = Buffer.alloc(0);

          for (let i = 0; i < iterations; ++i) {
            // Calculate the SHA2 and SHA3 hashes of the result and the inputs
            res = doubleHash(saltBuf, passwordBuf, res);

            // Calculate the Scrypt hash of the result and the inputs
            res = scryptSync(Buffer.concat([res, saltBuf, passwordBuf]), saltBuf, length, {
              N: scryptN,
              r: scryptR,
              p: scryptP,
              maxmem: 128 * scryptN * scryptR * 2
            });

            // Calculate the SHA2 and SHA3 hashes of the result and the inputs again
            res = doubleHash(saltBuf, passwordBuf, res);

            // Calculate the Argon2 hash of the result and the inputs
            res = await argon2(Buffer.concat([res, saltBuf, passwordBuf]), {
              ...{
                version: ARGON2_VERSION,
                type: argon2id,
                memoryCost: argon2MCost,
                timeCost: argon2TCost,
                parallelism: 1
              },
              ...{ salt: saltBuf, hashLength: length, raw: true }
            });

            bar.increment();
          }

          // Calculate the final SHA2 and SHA3 hashes (and trim the result, if required)
          res = doubleHash(saltBuf, passwordBuf, res);
          res = res.subarray(0, length);

          bar.stop();

          Logger.info();
          Logger.info('Key (hex) is:');

          for (const part of chunk(res, 64)) {
            Logger.info(Buffer.from(part).toString('hex'));
          }
        }
      )
      .parse();

    process.exit(0);
  } catch (e) {
    if (e instanceof Error) {
      Logger.fatal(e.stack);
    } else {
      Logger.fatal(e);
    }

    process.exit(1);
  }
};

main();
