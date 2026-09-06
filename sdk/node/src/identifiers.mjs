import { DesfireError, ErrorCode } from './errors.mjs';

/** Validate one integer identifier without creating a mutable wrapper object. */
function identifier(value, maximum, name) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
        throw new DesfireError(ErrorCode.InvalidArgument, `${name} is outside its protocol range`);
    }
    return value;
}

/** Construct a checked 24-bit native application identifier. */
export function applicationId(value) { return identifier(value, 0xFF_FFFF, 'ApplicationId'); }

/** Construct a checked native file number. */
export function fileNumber(value) { return identifier(value, 31, 'FileNumber'); }

/** Construct a checked native or ISO AES key selector. */
export function keyNumber(value) { return identifier(value, 63, 'KeyNumber'); }

/** Construct a checked EV3 key-set selector. */
export function keySet(value) { return identifier(value, 15, 'KeySet'); }
