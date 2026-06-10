"use strict";

const { EventEmitter } = require("events");
const Module = require("module");
const { expect } = require("chai");
const sinon = require("sinon");
const { EuDataActClient } = require("./lib/euDataAct");

describe("adapter startup data source selection", () => {
  let createAdapter;
  let adapterCorePath;
  let originalAdapterCore;

  before(() => {
    adapterCorePath = require.resolve("@iobroker/adapter-core");
    originalAdapterCore = require.cache[adapterCorePath];

    class TestAdapter extends EventEmitter {
      constructor(options) {
        super();
        this.config = options.config || {};
        this.log = {
          debug: sinon.spy(),
          error: sinon.spy(),
          info: sinon.spy(),
          warn: sinon.spy(),
        };
      }
    }

    const adapterCoreMock = new Module(adapterCorePath);
    adapterCoreMock.filename = adapterCorePath;
    adapterCoreMock.loaded = true;
    adapterCoreMock.exports = { Adapter: TestAdapter };
    require.cache[adapterCorePath] = adapterCoreMock;
    delete require.cache[require.resolve("./main")];
    createAdapter = require("./main");
  });

  after(() => {
    delete require.cache[require.resolve("./main")];
    if (originalAdapterCore) {
      require.cache[adapterCorePath] = originalAdapterCore;
    } else {
      delete require.cache[adapterCorePath];
    }
  });

  function createStartupAdapter(type) {
    const adapter = createAdapter({
      config: {
        password: "test-password",
        type,
      },
    });

    adapter.setState = sinon.spy();
    adapter.subscribeStates = sinon.spy();
    adapter.runEuDataAct = sinon.stub().resolves();
    adapter.login = sinon.stub().returns(new Promise(() => {}));
    adapter.getPersonalData = sinon.spy();
    adapter.getVehicles = sinon.spy();
    adapter.getSeatCupraStatus = sinon.spy();

    return adapter;
  }

  it("uses EU Data Act only for My CUPRA", async () => {
    const adapter = createStartupAdapter("seatcupra");

    await adapter.onReady();

    expect(adapter.runEuDataAct).to.have.been.calledOnceWithExactly("CUPRA");
    expect(adapter.login).not.to.have.been.called;
    expect(adapter.getPersonalData).not.to.have.been.called;
    expect(adapter.getVehicles).not.to.have.been.called;
    expect(adapter.getSeatCupraStatus).not.to.have.been.called;
    expect(adapter.subscribeStates).to.have.been.calledOnceWithExactly("*");
    expect(adapter.log.info).to.have.been.calledWithExactly(
      "My CUPRA: legacy OLA detail API is blocked by missing-device-token. " +
        "Using EU Data Act as the only data source.",
    );
  });

  it("keeps the VW ID EU Data Act-only startup behavior", async () => {
    const adapter = createStartupAdapter("id");

    await adapter.onReady();

    expect(adapter.runEuDataAct).to.have.been.calledOnceWithExactly("VOLKSWAGEN_PASSENGER_CARS");
    expect(adapter.login).not.to.have.been.called;
    expect(adapter.subscribeStates).to.have.been.calledOnceWithExactly("*");
  });

  for (const [type, brand] of [
    ["seat", "SEAT"],
    ["audietron", "AUDI"],
  ]) {
    it(`keeps the legacy login startup behavior for ${type}`, async () => {
      const adapter = createStartupAdapter(type);

      await adapter.onReady();

      expect(adapter.runEuDataAct).to.have.been.calledOnceWithExactly(brand);
      expect(adapter.login).to.have.been.calledOnce;
      expect(adapter.subscribeStates).to.have.been.calledOnceWithExactly("*");
    });
  }

  function createEuDataActStatusAdapter(vin, datasets, downloads) {
    const adapter = createAdapter({ config: { password: "test-password", type: "seatcupra" } });
    adapter.euDataActIdentifiers = { [vin]: "request-id" };
    adapter.euDataActLastDataset = {};
    adapter.euDataActNoContentLogged = {};
    adapter.euDataActBackoffUntil = {};
    adapter.euDataActDiagnostics = {};
    adapter.euDataActDescriptions = {};
    adapter.euDataActStates = {};
    adapter.json2iob = { parse: sinon.stub().resolves() };
    adapter.restart = sinon.spy();
    adapter.euDataAct = {
      listDatasets: sinon.stub().resolves(datasets),
      downloadDataset: sinon.stub(),
      login: sinon.spy(),
    };
    for (const download of downloads) {
      adapter.euDataAct.downloadDataset.onCall(download.call).resolves(download.result);
    }
    return adapter;
  }

  it("falls back to an older EU Data Act ZIP after a transient newest-file failure", async () => {
    const vin = "WVWZZZTEST1234567";
    const datasets = [
      { name: "newest.zip", createdOn: "2026-06-10T10:15:00Z" },
      { name: "older.zip", createdOn: "2026-06-10T10:00:00Z" },
    ];
    const adapter = createEuDataActStatusAdapter(vin, datasets, [
      {
        call: 0,
        result: {
          transientDownloadError: true,
          status: 500,
          contentType: "text/html; charset=utf-8",
          byteSize: 1034,
          zipMagic: false,
        },
      },
      {
        call: 1,
        result: {
          status: 200,
          contentType: "application/zip",
          byteSize: 128,
          zipMagic: true,
          fileName: "dataset.json",
          json: { Data: [] },
        },
      },
    ]);

    await adapter.getEuDataActStatus(vin);

    expect(adapter.euDataAct.downloadDataset).to.have.been.calledTwice;
    expect(adapter.euDataAct.downloadDataset.firstCall).to.have.been.calledWithExactly(vin, "request-id", "newest.zip");
    expect(adapter.euDataAct.downloadDataset.secondCall).to.have.been.calledWithExactly(vin, "request-id", "older.zip");
    expect(adapter.euDataAct.login).not.to.have.been.called;
    expect(adapter.restart).not.to.have.been.called;
    expect(adapter.euDataActLastDataset[vin]).to.equal("older.zip");

    const telemetryCall = adapter.json2iob.parse.getCalls().find((call) => call.args[0] === `${vin}.statuseudata`);
    expect(telemetryCall).to.not.equal(undefined);
    expect(telemetryCall.args[1]._dataset_name).to.equal("older.zip");
    expect(adapter.euDataActDiagnostics[vin]).to.include({
      lastFileListCount: 2,
      lastAttemptedFile: "newest.zip",
      lastDownloadStatus: 500,
      lastDownloadContentType: "text/html; charset=utf-8",
      lastDownloadBytes: 1034,
      fallbackFile: "older.zip",
      fallbackDownloadStatus: 200,
      zipMagic: true,
      lastSuccessFile: "older.zip",
      lastError: "",
    });
    expect(adapter.euDataActDiagnostics[vin].lastSuccess).to.be.a("string").and.not.equal("");
  });

  it("preserves existing EU Data Act states when all bounded download attempts fail", async () => {
    const vin = "WVWZZZTEST7654321";
    const datasets = Array.from({ length: 6 }, (_, index) => ({
      name: `dataset-${6 - index}.zip`,
      createdOn: `2026-06-10T0${6 - index}:00:00Z`,
    }));
    const downloads = Array.from({ length: 5 }, (_, call) => ({
      call,
      result: {
        transientDownloadError: true,
        status: 500,
        contentType: "text/html; charset=utf-8",
        byteSize: 900 + call,
        zipMagic: false,
      },
    }));
    const adapter = createEuDataActStatusAdapter(vin, datasets, downloads);
    adapter.euDataActLastDataset[vin] = "last-good.zip";

    await adapter.getEuDataActStatus(vin);

    expect(adapter.euDataAct.downloadDataset).to.have.callCount(5);
    expect(adapter.json2iob.parse.neverCalledWith(`${vin}.statuseudata`)).to.equal(true);
    expect(adapter.json2iob.parse).to.have.been.calledOnce;
    expect(adapter.json2iob.parse.firstCall.args[0]).to.equal(`${vin}.statuseudata.diagnostic`);
    expect(adapter.euDataActLastDataset[vin]).to.equal("last-good.zip");
    expect(adapter.euDataActDiagnostics[vin].lastError).to.equal("transient download error");
    expect(adapter.euDataActDiagnostics[vin].lastSuccessFile).to.equal(undefined);
    expect(adapter.euDataAct.login).not.to.have.been.called;
    expect(adapter.restart).not.to.have.been.called;
  });

});


function createStoredJsonZip(payload) {
  const fileName = Buffer.from("dataset.json");
  const data = Buffer.from(JSON.stringify(payload));
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt32LE(data.length, 18);
  header.writeUInt32LE(data.length, 22);
  header.writeUInt16LE(fileName.length, 26);
  return Buffer.concat([header, fileName, data]);
}

describe("EU Data Act dataset download responses", () => {
  function createClient() {
    const log = {
      debug: sinon.spy(),
      error: sinon.spy(),
      info: sinon.spy(),
      warn: sinon.spy(),
    };
    const client = new EuDataActClient({
      email: "user@example.com",
      password: "secret-password",
      brand: "CUPRA",
      log,
    });
    client._loggedIn = true;
    sinon.spy(client, "login");
    return { client, log };
  }

  it("treats HTTP 500 HTML as a transient per-file error without re-login or sensitive logging", async () => {
    const { client, log } = createClient();
    const html = Buffer.from("<html><body>Adobe AEM Cloud internal error</body></html>");
    sinon.stub(client, "_getBuffer").resolves({
      status: 500,
      url: "https://example.invalid/download",
      headers: {
        "content-type": "text/html; charset=utf-8",
        authorization: "Bearer secret-token",
        cookie: "session=secret-cookie",
      },
      body: html,
    });

    const result = await client.downloadDataset("WVWZZZTEST1234567", "request-id", "newest.zip");

    expect(result).to.deep.equal({
      transientDownloadError: true,
      status: 500,
      contentType: "text/html; charset=utf-8",
      byteSize: html.length,
      zipMagic: false,
    });
    expect(client.login).not.to.have.been.called;
    expect(log.warn).to.have.been.calledOnce;
    const logged = [...log.debug.args, ...log.info.args, ...log.warn.args, ...log.error.args].flat().join(" ");
    expect(logged).to.include("filename=newest.zip");
    expect(logged).to.include("status=500");
    expect(logged).to.include(`bytes=${html.length}`);
    expect(logged).to.not.include("WVWZZZTEST1234567");
    expect(logged).to.not.include(html.toString());
    expect(logged).to.not.include("secret-token");
    expect(logged).to.not.include("secret-cookie");
    expect(logged).to.not.include("secret-password");
  });

  it("accepts a non-empty HTTP 200 ZIP with PK magic", async () => {
    const { client } = createClient();
    const zip = createStoredJsonZip({ Data: [] });
    sinon.stub(client, "_getBuffer").resolves({
      status: 200,
      url: "https://example.invalid/download",
      headers: { "content-type": "application/zip" },
      body: zip,
    });

    const result = await client.downloadDataset("WVWZZZTEST1234567", "request-id", "older.zip");

    expect(result.status).to.equal(200);
    expect(result.zipMagic).to.equal(true);
    expect(result.byteSize).to.equal(zip.length);
    expect(result.fileName).to.equal("dataset.json");
    expect(result.json).to.deep.equal({ Data: [] });
    expect(client.login).not.to.have.been.called;
  });
});
