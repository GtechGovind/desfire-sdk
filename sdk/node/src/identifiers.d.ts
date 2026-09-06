declare const applicationIdBrand: unique symbol;
declare const fileNumberBrand: unique symbol;
declare const keyNumberBrand: unique symbol;
declare const keySetBrand: unique symbol;

export type ApplicationId = number & { readonly [applicationIdBrand]: true };
export type FileNumber = number & { readonly [fileNumberBrand]: true };
export type KeyNumber = number & { readonly [keyNumberBrand]: true };
export type KeySet = number & { readonly [keySetBrand]: true };

export function applicationId(value: number): ApplicationId;
export function fileNumber(value: number): FileNumber;
export function keyNumber(value: number): KeyNumber;
export function keySet(value: number): KeySet;
