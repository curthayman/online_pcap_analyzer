declare module 'pcap-parser' {
  import { EventEmitter } from 'events';

  interface PcapPacket {
    header: {
      timestampSeconds: number;
      timestampMicroseconds: number;
      capturedLength: number;
      originalLength: number;
    };
    data: Buffer;
  }

  class Parser extends EventEmitter {
    on(event: 'packet', listener: (packet: PcapPacket) => void): this;
    on(event: 'end', listener: () => void): this;
    on(event: 'error', listener: (err: Error) => void): this;
  }

  function parse(filePath: string): Parser;

  export = { parse };
}
