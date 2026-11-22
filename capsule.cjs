const { createDecipheriv, createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function keyFor(job, replies) {
    if (typeof job.id !== 'string' || !/^[a-z0-9-]{1,50}$/.test(job.id) ||
        typeof job.salt !== 'string' || !/^[a-f0-9]{32}$/.test(job.salt) ||
        !Array.isArray(job.rounds) || job.rounds.length !== 3 ||
        replies.length !== 3 || replies.some(s => !/^[a-f0-9]{64}$/i.test(s))) {
        throw Error('expected three ordered 32-byte hex replies and a valid capsule');
    }
    const hash = createHash('sha256');
    hash.update('root-for-glory/hidden-vm/1\0');
    hash.update(job.id + '\0');
    hash.update(Buffer.from(job.salt, 'hex'));
    for (const reply of replies) hash.update(Buffer.from(reply, 'hex'));
    return hash.digest();
}

function open(job, replies) {
    const cipher = createDecipheriv('aes-256-gcm', keyFor(job, replies),
        Buffer.from(job.nonce, 'hex'));
    cipher.setAuthTag(Buffer.from(job.tag, 'hex'));
    return Buffer.concat([cipher.update(Buffer.from(job.sealed, 'hex')), cipher.final()])
        .toString('utf8');
}

if (require.main === module) {
    try {
        const [verb, file, ...args] = process.argv.slice(2);
        if (verb !== 'extract' && verb !== 'open')
            throw Error('usage: node capsule.cjs extract JOB OUT_DIR or open JOB REPLY1 REPLY2 REPLY3');
        const job = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (verb === 'extract' && args.length === 1 &&
            Array.isArray(job.rounds) && job.rounds.length === 3) {
            fs.mkdirSync(args[0], {recursive: true});
            job.rounds.forEach((data, i) => {
                fs.writeFileSync(path.join(args[0], 'round-' + (i+1) + '.bch'),
                    Buffer.from(data, 'base64'), {flag: 'wx'});
            });
        } else if (verb === 'open') {
            console.log(open(job, args));
        } else {
            throw Error('usage: node capsule.cjs extract JOB OUT_DIR');
        }
    } catch (err) {
        console.error(err.message);
        process.exitCode = 1;
    }
}
module.exports = { keyFor, open };
