declare module 'pcap-ng-parser' {
  import { Transform } from 'stream';

  interface PCAPNGPacket {
    interfaceId?: number;
    timestamp?: number;
    data: Buffer;
    capturedLength?: number;
    originalLength?: number;
  }

  interface PCAPNGInterface {
    linkType: number;
    snapLen: number;
  }

  class PCAPNGParser extends Transform {
    on(event: 'data', listener: (packet: PCAPNGPacket) => void): this;
    on(event: 'interface', listener: (iface: PCAPNGInterface) => void): this;
    on(event: 'end', listener: () => void): this;
    on(event: 'finish', listener: () => void): this;
    on(event: 'error', listener: (err: Error) => void): this;
  }

  export = PCAPNGParser;
}
