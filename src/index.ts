import { createHash, scryptSync } from 'crypto';
import { hash as argon2, argon2id } from 'argon2';
import CliProgress from 'cli-progress';
import { keccak512 } from 'js-sha3';
import { chunk } from 'lodash';
import yargs from 'yargs';
import { Logger } from './utils/logger';

const ARGON2_VERSION = 19;

const VERSION = process.env.npm_package_version!;

const doubleHash = (salt: Buffer, secret: Buffer, prevRes: Buffer) => {
  let res = prevRes;

  res = createHash('sha512')
    .update(Buffer.concat([res, salt, secret]))
    .digest();

  res = Buffer.from(keccak512(Buffer.concat([res, salt, secret])), 'hex');

  return res;
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
            default: 100
          },
          length: {
            description: 'Length of the derived result',
            type: 'number',
            alias: 'l',
            min: 10,
            max: 64,
            default: 16
          },
          'scrypt-log-n': {
            description: 'Scrypt CPU/memory cost parameter',
            type: 'number',
            max: 4294967295,
            default: 20
          },
          'scrypt-r': {
            description: 'Scrypt block size parameter, which fine-tunes sequential memory read size and performance',
            type: 'number',
            max: 4294967295,
            default: 8
          },
          'scrypt-p': {
            description: 'Scrypt parallelization parameter',
            type: 'number',
            max: 4294967295,
            default: 1
          },
          'argon2-m-cost': {
            description: 'Argon2 number of 1 KiB memory block',
            type: 'number',
            min: 8,
            max: 4294967295,
            default: 1 << 21
          },
          'argon2-t-cost': {
            description: 'Argon2 number of iterations',
            type: 'number',
            min: 2,
            max: 4294967295,
            default: 2
          },
          'argon2-p-cost': {
            description: 'Argon2 number of threads',
            type: 'number',
            min: 2,
            max: 16777215,
            default: 4
          },
          salt: {
            description: 'Random data fed as an additional input to the KDF',
            type: 'string',
            min: 8,
            required: true
          },
          secret: {
            description: 'Input secret to the KDF',
            type: 'string',
            required: true
          }
        },
        async ({
          iterations,
          length,
          scryptLogN,
          scryptR,
          scryptP,
          argon2MCost,
          argon2TCost,
          argon2PCost,
          salt,
          secret
        }) => {
          Logger.notice(
            `SlowKey: iterations: ${iterations}, length: ${length}, Scrypt: (log_n: ${scryptLogN}, r: ${scryptR}, p: ${scryptP}), Argon2id: (version: ${ARGON2_VERSION}, m_cost: ${argon2MCost}, t_cost: ${argon2TCost}, p_cost: ${argon2PCost})`
          );
          Logger.info();

          const bar = new CliProgress.SingleBar(CliProgress.Presets.shades_classic);
          bar.start(iterations, 0);

          let res = Buffer.alloc(0);
          const saltBuf = Buffer.from(salt);
          const secretBuf = Buffer.from(secret);

          for (let i = 0; i < iterations; ++i) {
            // Calculate the SHA3 and SHA2 hashes of the result and the inputs
            res = doubleHash(saltBuf, secretBuf, res);

            // Calculate the Scrypt hash of the result and the inputs
            res = scryptSync(Buffer.concat([res, saltBuf, secretBuf]), saltBuf, length, {
              N: 1 << scryptLogN,
              r: scryptR,
              p: scryptP,
              maxmem: 128 * (1 << scryptLogN) * scryptR * 2
            });

            // Calculate the SHA3 and SHA2 hashes of the result and the inputs again
            res = doubleHash(saltBuf, secretBuf, res);

            // Calculate the Argon2 hash of the result and the inputs
            res = await argon2(Buffer.concat([res, saltBuf, secretBuf]), {
              ...{
                version: ARGON2_VERSION,
                type: argon2id,
                memoryCost: argon2MCost,
                timeCost: argon2TCost,
                parallelism: argon2PCost
              },
              ...{ salt: saltBuf, hashLength: length, raw: true }
            });

            bar.increment();
          }

          // Calculate the final SHA3 and SHA2 hashes (and trim the result, if required)
          res = doubleHash(saltBuf, secretBuf, res);
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
