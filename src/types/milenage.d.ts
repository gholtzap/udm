declare module 'milenage' {
  interface MilenageOptions {
    op_c?: Uint8Array;
    op?: Uint8Array;
    key: Uint8Array;
  }

  interface F1Result {
    mac_a: Uint8Array;
    mac_s?: Uint8Array;
  }

  interface F1StarResult {
    op_c: Uint8Array;
    mac_s: Uint8Array;
  }

  interface F2345Result {
    res: Uint8Array;
    ck: Uint8Array;
    ik: Uint8Array;
    ak: Uint8Array;
  }

  interface F5StarResult {
    op_c: Uint8Array;
    ak_s: Uint8Array;
  }

  class Milenage {
    constructor(options: MilenageOptions);
    op_c(): Uint8Array;
    f1(rand: Uint8Array, sqn: Uint8Array, amf: Uint8Array): F1Result;
    f1star(rand: Uint8Array, sqn: Uint8Array, amf: Uint8Array): F1StarResult;
    f2345(rand: Uint8Array): F2345Result;
    f5star(rand: Uint8Array): F5StarResult;
  }

  export = Milenage;
}
